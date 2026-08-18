"""Guard: the published sample reports stay reproducible and stay current.

``docs/report.html`` and ``docs/exec-report.html`` are the samples linked from
apotrope.sh. They were once hand-made from a real scan with no tracked input, so
when the package version moved they could not be regenerated and sat advertising
v0.1.12 two releases later. ``tools/fixtures/sample_report.json`` is now their
source and ``tools/generate_sample_reports.py`` renders them.

Three failure modes are guarded here:

* **Branding drift** — a committed asset naming a version the package no longer
  is. Covers ``docs/index.html`` too, whose demo terminal and JSON-LD carry the
  same version by hand.
* **Source drift** — the committed assets no longer being what the fixture
  renders, which would put the reproducible path back where it started.
* **Content drift** — the fixture publishing remediation the check modules no
  longer emit. The fixture was recovered from the v0.1.12 report, so it arrived
  carrying that release's commands: a BitLocker block that creates a recovery
  password the operator can never read back, an AutoPlay write with no
  registry-key guard, and a WMI call that discards its ``ReturnValue``. All
  three had been fixed in the source by then and all three were published under
  a v0.2.0 banner.

The fixture holds two kinds of field, and the distinction is what makes it a
sanitized scan rather than a snapshot of an old release:

* **machine-owned** — ``status``, ``details``, ``hostname``, ``score``,
  timestamps. Frozen at the sample machine; the source has nothing to say.
* **code-owned** — ``description``, ``remediation``, ``command``,
  ``cis_reference``. Must equal what the modules emit today.
"""

from __future__ import annotations

import importlib
import pkgutil
import json
import re
import sys
from functools import lru_cache
from pathlib import Path

import pytest

import apotrope
from apotrope import checks as checks_pkg
from apotrope import cis_map
from apotrope.checks import misc
from apotrope.compare import load_baseline
from apotrope.models import Status
from apotrope.scoring import calculate_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

# Imported in-process, not spawned: conftest's autouse guard patches
# subprocess.run process-wide, so shelling out to the generator would raise.
import command_audit

from generate_sample_reports import (
    EXECUTIVE_NAME,
    EXPECTED_COUNTS,
    EXPECTED_HOSTNAME,
    EXPECTED_SCORE,
    FIXTURE,
    TECHNICAL_NAME,
    main,
)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REGENERATE = "python tools/generate_sample_reports.py"


# A resolved literal keeps `{placeholder}` wherever the value is only known at
# scan time. Each placeholder becomes a named group, so a value bound by the
# check name constrains every other field: `BitLocker — {mount}` binding
# mount=G: forces the command to say G: throughout. Repeats inside one field
# become backreferences. Everything else must match exactly — no whitespace is
# collapsed, because a newline in PowerShell ends a comment and separates
# statements.
_PLACEHOLDER = re.compile(r"\\\{([A-Za-z_]\w*)\\\}")
_ANY_PLACEHOLDER = re.compile(r"\{[A-Za-z_]\w*\}")


def _pattern(literal: str, bound: dict[str, str] | None = None) -> re.Pattern[str]:
    """Compile a source literal into a regex with one named group per placeholder."""
    seen: set[str] = set()

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if bound and name in bound:
            return re.escape(bound[name])
        if name in seen:
            return f"(?P={name})"
        seen.add(name)
        return f"(?P<{name}>.+?)"

    return re.compile(_PLACEHOLDER.sub(sub, re.escape(literal)), re.S)


def _match(literal: str | None, rendered: str, bound: dict[str, str] | None = None):
    """Match a rendered value against a source literal, returning any bindings."""
    if literal is None:
        return None
    if literal == rendered:
        return {}
    m = _pattern(literal, bound).fullmatch(rendered)
    return m.groupdict() if m else None


# ── Named validators ────────────────────────────────────────────────────────
#
# A field whose text is assembled at scan time cannot be matched against a
# template. It gets a validator that checks the property that actually matters,
# never a bare wildcard — an approved wildcard is the same hole under a nicer
# name.

def _validate_audit_policy_command(row) -> str | None:
    """The command must enable exactly the subcategories details reports disabled.

    This is the invariant the hardcoded `subcategory:'Logon'` violated: it ran
    cleanly and remediated nothing. Checked semantically because the command
    expands one line per subcategory and has no single static form.
    """
    reported = [n for n in misc._EXPECTED_AUDIT if n in row["details"]]
    targeted = re.findall(r"/subcategory:'([^']+)'", row["command"])

    if sorted(targeted) != sorted(reported):
        return f"targets {sorted(targeted)}, details report {sorted(reported)}"
    if len(targeted) != len(set(targeted)):
        return f"duplicate subcategory lines: {targeted}"
    lines = [ln for ln in row["command"].splitlines() if ln.strip()]
    if len(lines) != len(targeted):
        return f"{len(lines)} lines for {len(targeted)} subcategories"
    return None


def _validate_audit_policy_remediation(row) -> str | None:
    """One of the three shipped wordings, plus the shared Group Policy suffix."""
    wordings = (
        misc._FIX_AUDIT_DISABLED,
        misc._FIX_AUDIT_UNREPORTED,
        misc._FIX_AUDIT_MIXED.split("{")[0],
    )
    if not any(row["remediation"].startswith(w) for w in wordings):
        return "does not begin with any shipped remediation wording"
    if "secpol.msc" not in row["remediation"]:
        return "lost the Group Policy suffix"
    return None


#: (check_name, field) -> validator. Every entry names a function; there is no
#: form of this table that approves a field without checking it.
VALIDATORS = {
    ("Audit Policy", "command"): _validate_audit_policy_command,
    ("Audit Policy", "remediation"): _validate_audit_policy_remediation,
}


@lru_cache(maxsize=1)
def _category_to_module() -> dict[str, str]:
    """Map each check category to the single module that emits it."""
    mapping: dict[str, str] = {}
    for info in pkgutil.iter_modules(checks_pkg.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"apotrope.checks.{info.name}")
        category = getattr(module, "CATEGORY", None)
        if category:
            mapping[category] = f"{info.name}.py"
    return mapping


# Anchors are deliberately narrow. All three files also contain CIS benchmark
# strings ("v5.0.0", "v4.0.0"), so a loose r"v\d+\.\d+\.\d+" sweep captures those
# and fails. Each capture group starts *after* the literal "v" the templates
# render, because apotrope.__version__ is bare ("0.2.0", not "v0.2.0").
VERSION_ANCHORS: list[tuple[str, str, int]] = [
    (TECHNICAL_NAME, r'<span class="ver">v([0-9][^<]*)</span>', 1),
    (EXECUTIVE_NAME, r"Apotrope v([0-9][^ <·]*)", 2),
    ("index.html", r'"softwareVersion":\s*"([^"]+)"', 1),
    ("index.html", r'class="g-dim">v([0-9][^<]*)</span>', 1),
]


@pytest.mark.parametrize(("filename", "pattern", "expected_hits"), VERSION_ANCHORS)
def test_published_assets_name_the_current_version(
    filename: str, pattern: str, expected_hits: int
) -> None:
    """Every tool version printed in docs/ must equal the packaged version."""
    text = (DOCS / filename).read_text(encoding="utf-8")
    found = re.findall(pattern, text)

    # A pattern that stops matching is the same silent failure as a stale
    # version: the guard would pass while covering nothing.
    assert len(found) == expected_hits, (
        f"{filename}: expected {expected_hits} match(es) for {pattern!r}, got {found}. "
        "The template changed — update the anchor rather than deleting the check."
    )
    for value in found:
        assert value == apotrope.__version__, (
            f"{filename} advertises {value!r} but the package is "
            f"{apotrope.__version__!r}. Regenerate with: {REGENERATE}"
        )


def test_committed_reports_match_what_the_fixture_renders(tmp_path: Path) -> None:
    """The committed assets must be exactly what the generator produces today."""
    assert main(["--output-dir", str(tmp_path)]) == 0, "the generator did not succeed"

    for name in (TECHNICAL_NAME, EXECUTIVE_NAME):
        # read_text, not read_bytes. The reporter writes through
        # Path.write_text with newline=None, so a render on Windows is CRLF while
        # the committed asset is LF (.gitattributes: * text=auto eol=lf). A byte
        # comparison would fail on the Windows CI legs only. Universal newlines
        # collapse both sides to "\n" and compare the content that matters.
        rendered = (tmp_path / name).read_text(encoding="utf-8")
        committed = (DOCS / name).read_text(encoding="utf-8")
        assert rendered == committed, (
            f"docs/{name} is not what tools/fixtures/sample_report.json renders. "
            f"If the template or the fixture changed on purpose, regenerate: {REGENERATE}"
        )


def test_fixture_holds_the_sanitized_persona() -> None:
    """The fixture must keep describing the published sample machine."""
    report = load_baseline(str(FIXTURE))

    assert report.hostname == EXPECTED_HOSTNAME
    # Not rendered anywhere in the technical report, so it cannot be recovered by
    # re-parsing it. A silent False flips the executive report's Privileges field
    # to "Standard user" and rewrites its scope paragraph.
    assert report.is_admin is True

    assert len(report.results) == sum(EXPECTED_COUNTS.values())
    for status, expected in EXPECTED_COUNTS.items():
        assert len(report.by_status(status)) == expected, f"{status.value} count changed"

    # The stored score is what renders in the gauge — load_baseline trusts it and
    # never recomputes — so both it and the derived value are pinned.
    assert report.score == EXPECTED_SCORE
    assert calculate_score(report.results) == EXPECTED_SCORE
    assert report.error_count == 0, "the published sample must not show failed checks"


def test_fixture_severity_placeholders_are_confined_to_unrendered_rows() -> None:
    """Only FAIL/WARN severities are real; PASS/INFO carry a uniform placeholder.

    The technical template renders severity for FAIL/WARN only, so the original
    values for the other rows are absent from both published artifacts and were
    not recoverable. A uniform placeholder keeps the per-category sort
    (status, severity) stable, which is what reproduces the committed row order.
    """
    report = load_baseline(str(FIXTURE))

    placeholders = {
        r.severity for r in report.results if r.status in (Status.PASS, Status.INFO)
    }
    assert len(placeholders) == 1, (
        f"PASS/INFO rows must share one placeholder severity, found {placeholders}. "
        "Mixed values reorder rows inside a category and break generation parity."
    )

    # The rendered severities are real data and must stay varied — if these ever
    # collapse to the placeholder too, the fixture has lost the only severities
    # the reports actually show.
    rendered = {
        r.severity for r in report.results if r.status in (Status.FAIL, Status.WARN)
    }
    assert len(rendered) > 1, "FAIL/WARN severities look overwritten, not recovered"


def _fixture_commands() -> list[command_audit.Command]:
    """Fixture rows carrying a command, shaped for the shipped lint."""
    report = load_baseline(str(FIXTURE))
    return [
        command_audit.Command(module=r.check_name, line=0, text=r.command)
        for r in report.results
        if r.command
    ]


def test_fixture_commands_pass_the_shipped_lint() -> None:
    """The sample's commands must clear the same lint the check modules do.

    ``tests/test_remediation_commands.py`` runs this over the source inventory.
    Running it over the fixture as well is what stops the published sample
    advertising a command the source has already fixed — which is exactly how a
    BitLocker block with no recovery-password readback reached apotrope.sh under
    a v0.2.0 banner.
    """
    violations = command_audit.lint_commands(_fixture_commands())
    assert violations == [], (
        "the published sample carries remediation the lint rejects:\n"
        + "\n".join(f"  {v.module}: {v.rule}" for v in violations)
    )


def _templates_for(row) -> list:
    """Templates whose check name and status match this row, with bindings."""
    out = []
    for t in command_audit.collect_result_templates():
        if t.module != _category_to_module()[row["category"]]:
            continue
        if t.status is not None and t.status != row["status"]:
            continue
        bound = _match(t.check_name, row["check_name"])
        if bound is None:
            continue
        out.append((t, bound))
    return out


def _verify_row(row) -> str | None:
    """None if every code-owned field is accounted for; otherwise why not."""
    candidates = _templates_for(row)
    if not candidates:
        return "no check-module template matches this name and status"

    problems = []
    for template, bound in candidates:
        failed = None
        for field in command_audit.RESULT_TEXT_FIELDS:
            validator = VALIDATORS.get((row["check_name"], field))
            if validator is not None:
                failed = validator(row)
                if failed:
                    failed = f"{field}: {failed}"
                    break
                continue
            if field in template.unresolved:
                failed = f"{field}: not statically resolvable and no validator"
                break
            # Empty must match empty. Skipping empties is what let a blanked
            # field pass, and it is also what makes a PASS branch meaningful.
            literal = template.__getattribute__(field) or ""
            if _match(literal, row[field], bound) is None:
                failed = f"{field}: does not match {template.module}:{template.line}"
                break
        if failed is None:
            return None
        problems.append(failed)
    return problems[0]


def test_every_published_row_is_verified_against_its_check_module() -> None:
    """Every code-owned field of all 53 rows must be accounted for.

    Not "allowlist what we cannot check" — an unverified field is the wildcard
    weakness this guard exists to remove, so the requirement is zero.
    """
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    failures = {
        r["check_name"]: why
        for r in report["results"]
        if (why := _verify_row(r)) is not None
    }
    assert not failures, (
        f"{len(failures)} of {len(report['results'])} published rows are not "
        f"verified against their check module:\n"
        + "\n".join(f"  {k}: {v}" for k, v in sorted(failures.items()))
        + f"\nRefresh from source, then regenerate: {REGENERATE}"
    )


def test_fixture_cis_references_match_the_benchmark_map() -> None:
    """``cis_reference`` is code-owned too — it comes from cis_map, not the scan."""
    report = load_baseline(str(FIXTURE))
    wrong = [
        (r.check_name, r.cis_reference, cis_map.lookup(r.check_name))
        for r in report.results
        if r.cis_reference != cis_map.lookup(r.check_name)
    ]
    assert not wrong, f"fixture CIS references disagree with cis_map: {wrong}"

# ── Mutation coverage ───────────────────────────────────────────────────────
#
# A guard with no evidence it can fail is the failure mode this whole file
# exists to prevent: the version before this one passed four of these five
# unchanged. Each mutation below is applied to an in-memory copy of a published
# row and must be rejected.


def _row(name: str) -> dict:
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return next(r for r in report["results"] if r["check_name"] == name)


def _swap_within_module(row: dict) -> dict:
    # AutoPlay and Audit Policy both live in misc.py, so a module-scoped guard
    # accepts each other's commands.
    row["command"] = _row("Audit Policy")["command"]
    return row


def _blank_a_field(row: dict) -> dict:
    row["remediation"] = ""
    return row


def _wrong_runtime_value(row: dict) -> dict:
    # A BitLocker G: row carrying a command that targets C:.
    row["command"] = row["command"].replace("'G:'", "'C:'")
    return row


def _fabricated_threshold(row: dict) -> dict:
    row["description"] = row["description"].replace("15 minutes", "999 minutes")
    return row


def _invented_text(row: dict) -> dict:
    row["remediation"] = "Totally invented remediation text."
    return row


def _audit_targets_the_wrong_subcategory(row: dict) -> dict:
    # The exact defect PR #123 fixed: details report one subcategory, the
    # command enables another. This is its standing regression guard.
    row["command"] = row["command"].replace("Sensitive Privilege Use", "Logon")
    return row


def _audit_drops_a_line(row: dict) -> dict:
    row["command"] = ""
    return row


def _audit_duplicates_a_line(row: dict) -> dict:
    row["command"] = row["command"] + "\n" + row["command"]
    return row


def _pass_row_takes_a_warn_branch(row: dict) -> dict:
    # Direct-conditional form (accounts.py): a PASS row carrying the branch that
    # only a FAIL produces. Independent per-field resolution accepts this.
    row["remediation"] = "Disable the built-in Guest account."
    return row


def _assigned_status_row_takes_another_branch(row: dict) -> dict:
    # Assigned-status form (smb.py): status comes from an if/elif/else chain.
    row["remediation"] = _row("SMB Signing Required")["remediation"] or "x"
    return row


def _risky_service_row_gains_text(row: dict) -> dict:
    row["remediation"] = "Totally invented remediation text."
    return row


MUTATIONS = [
    pytest.param("AutoPlay Disabled", _swap_within_module, id="swap-command-within-module"),
    pytest.param("BitLocker — G:", _blank_a_field, id="blank-a-field"),
    pytest.param("BitLocker — G:", _wrong_runtime_value, id="placeholder-bound-to-wrong-value"),
    pytest.param("Screen Lock Timeout", _fabricated_threshold, id="fabricated-threshold"),
    pytest.param("BitLocker — G:", _invented_text, id="invented-text"),
    pytest.param("Audit Policy", _audit_targets_the_wrong_subcategory, id="audit-wrong-subcategory"),
    pytest.param("Audit Policy", _audit_drops_a_line, id="audit-missing-line"),
    pytest.param("Audit Policy", _audit_duplicates_a_line, id="audit-duplicate-line"),
    pytest.param("Guest Account", _pass_row_takes_a_warn_branch, id="branch-correlation-direct"),
    pytest.param("SMB Encryption", _assigned_status_row_takes_another_branch,
                 id="branch-correlation-assigned"),
    pytest.param("Risky Services", _risky_service_row_gains_text, id="risky-service-row"),
]


@pytest.mark.parametrize(("check_name", "mutate"), MUTATIONS)
def test_guard_rejects(check_name: str, mutate) -> None:
    row = _row(check_name)
    assert _verify_row(row) is None, f"{check_name} does not verify before mutation"
    assert _verify_row(mutate(row)) is not None, "the guard accepted a mutated row"
