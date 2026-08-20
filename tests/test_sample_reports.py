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

#: The exact checks the published sample shows. Pinned so one vanishing is a
#: failure rather than a quietly shorter report.
EXPECTED_CHECK_NAMES = (
    'Audit Policy',
    'AutoPlay Disabled',
    'BitLocker — C:',
    'BitLocker — G:',
    'Built-in Administrator Account',
    'Defender Real-Time Protection',
    'Defender Signature Age',
    'Defender Tamper Protection',
    'Domain Membership',
    'Firewall — Domain Default Inbound Action',
    'Firewall — Domain Profile Enabled',
    'Firewall — Private Default Inbound Action',
    'Firewall — Private Profile Enabled',
    'Firewall — Public Default Inbound Action',
    'Firewall — Public Profile Enabled',
    'Guest Account',
    'IPv6 Status',
    'LLMNR Disabled',
    'Last Windows Update',
    'Listening Ports — Summary',
    'Local Administrators',
    'NetBIOS over TCP/IP',
    'OS End-of-Support Status',
    'OS Version',
    'Password Policy — Account Lockout',
    'Password Policy — Complexity',
    'Password Policy — Minimum Length',
    'Pending Windows Updates',
    'PowerShell Constrained Language Mode',
    'PowerShell Execution Policy',
    'PowerShell Module Logging',
    'PowerShell Script Block Logging',
    'PowerShell v2',
    'RDP Enabled',
    'Registered AV Products',
    'Risky Services',
    'SMB Encryption',
    'SMB Signing Required',
    'SMBv1 Disabled',
    'Scheduled Tasks',
    'Screen Lock Timeout',
    'Secure Boot',
    'Speculative Execution Mitigations',
    'Startup Programs',
    'System Uptime',
    'TPM Status',
    'UAC Admin Consent Behavior',
    'UAC Enabled',
    'UAC Secure Desktop',
    'UAC Standard User Behavior',
    'Unquoted Service Paths',
    'WinRM Status',
    'Windows Update Service',
)


# A resolved literal keeps `{placeholder}` wherever the value is only known at
# scan time. Each placeholder becomes a named group, so a value bound by the
# check name constrains every other field: `BitLocker — {mount}` binding
# mount=G: forces the command to say G: throughout. Repeats inside one field
# become backreferences. Everything else must match exactly — no whitespace is
# collapsed, because a newline in PowerShell ends a comment and separates
# statements.
_PLACEHOLDER = re.compile(r"\\\{([A-Za-z_]\w*)\\\}")
_ANY_PLACEHOLDER = re.compile(r"\{([A-Za-z_]\w*)\}")


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

class _AuditDetailsError(ValueError):
    """Details that misc.py could not have produced for a WARN outcome."""


def _audit_subcategories(details: str) -> tuple[list[str], list[str]]:
    """Split the reported subcategories into (confirmed disabled, unreported).

    `misc.py` renders them into one list and marks the second kind
    `"<name> (not reported)"`. A substring scan cannot tell them apart, and
    conflating them inverts the consent rule the source deliberately follows:
    an unreported subcategory was never observed disabled, so enabling it is a
    change the operator did not ask for. Treated as disabled, a legitimate
    missing-only row with no command is rejected while a command that switches
    on the unreported one is accepted.

    Searching for those names anywhere in free-form prose is fail-open twice
    over: text `misc.py` cannot emit still parses, and prose naming nothing at
    all yields two empty lists, which then reads as a legitimate "everything was
    unreported" outcome. The rendered shape is fixed, so it is matched whole and
    every entry in it has to be one of the known names.
    """
    prefix = "Not all expected audit subcategories are confirmed logging: "
    suffix = ". Security-relevant events may not be recorded."
    if not (details.startswith(prefix) and details.endswith(suffix)):
        raise _AuditDetailsError(f"not the shape misc.py renders: {details!r}")

    entries = [e.strip() for e in details[len(prefix):-len(suffix)].split(", ") if e.strip()]
    if not entries:
        raise _AuditDetailsError("names no subcategory at all")
    if len(entries) != len(set(entries)):
        raise _AuditDetailsError(f"repeats an entry: {entries}")

    disabled, unreported = [], []
    for entry in entries:
        name = entry[: -len(" (not reported)")] if entry.endswith(" (not reported)") else entry
        if name not in misc._EXPECTED_AUDIT:
            raise _AuditDetailsError(f"unknown subcategory {name!r}")
        (unreported if entry.endswith(" (not reported)") else disabled).append(name)
    return disabled, unreported


def _validate_audit_policy_command(row) -> str | None:
    """Every line must be the shipped template, and together they must cover
    exactly the subcategories details reports disabled.

    Two separate things, and checking only the second is not enough: reading
    the quoted subcategories while ignoring the rest of the line accepts
    `auditpol ... /success:disable /failure:disable`, which names the right
    subcategory and turns its auditing off. The executable and the switches
    have to be pinned too, so the template is matched whole with only the
    subcategory substituted.
    """
    try:
        disabled, _ = _audit_subcategories(row["details"])
    except _AuditDetailsError as exc:
        return str(exc)
    lines = [ln for ln in row["command"].splitlines() if ln.strip()]

    targeted = []
    for line in lines:
        for name in misc._EXPECTED_AUDIT:
            if line == misc._CMD_AUDITPOL_ENABLE.format(subcategory=name):
                targeted.append(name)
                break
        else:
            return f"line is not the shipped auditpol template: {line!r}"

    if sorted(targeted) != sorted(disabled):
        return f"enables {sorted(targeted)}, details report disabled {sorted(disabled)}"
    if len(targeted) != len(set(targeted)):
        return f"duplicate subcategory lines: {targeted}"
    return None


def _validate_audit_policy_remediation(row) -> str | None:
    """Rebuild the exact remediation for this outcome and require equality.

    Accepting a permitted prefix plus a `secpol.msc` substring is fail-open:
    a fabricated policy path, arbitrary appended instructions, and the wrong
    outcome's wording all satisfy it. Which of the three wordings applies is
    fully determined by what details report, so there is nothing to be lenient
    about.
    """
    try:
        disabled, unreported = _audit_subcategories(row["details"])
    except _AuditDetailsError as exc:
        return str(exc)

    if disabled and unreported:
        fix = misc._FIX_AUDIT_MIXED.format(unreported=", ".join(unreported))
    elif disabled:
        fix = misc._FIX_AUDIT_DISABLED
    else:
        fix = misc._FIX_AUDIT_UNREPORTED

    expected = (
        f"{fix} This can also be configured via Group Policy "
        "(secpol.msc → Advanced Audit Policy Configuration)."
    )
    if row["remediation"] != expected:
        return f"does not equal the wording this outcome produces: {expected!r}"
    return None


#: (check_name, field) -> validator. Every entry names a function; there is no
#: form of this table that approves a field without checking it.
#: (check_name, status, field) -> validator. Status is part of the key on
#: purpose: the Audit Policy WARN outcome builds its command and remediation
#: at scan time and needs one, but the PASS and INFO outcomes are ordinary
#: static text. Running the validators for every status accepted a WARN row
#: relabelled PASS while still carrying its WARN command, and rejected the
#: PASS and INFO results misc.py really emits.
VALIDATORS = {
    ("Audit Policy", "WARN", "command"): _validate_audit_policy_command,
    ("Audit Policy", "WARN", "remediation"): _validate_audit_policy_remediation,
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


def test_every_severity_is_one_its_check_can_emit() -> None:
    """Severity is real data now, not a placeholder.

    The fixture was recovered from HTML that renders severity only for
    FAIL/WARN, so 47 rows arrived carrying a uniform INFO stand-in. Severity
    drives the score, so leaving them unverified let a source change stale the
    published report and its number. They now hold what their outcome emits —
    and putting the real values back left both rendered reports byte-identical,
    which is what the committed row order was always sorted by.
    """
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    placeholders = [
        r["check_name"] for r in report["results"]
        if r["status"] in ("PASS", "INFO") and r["severity"] == "INFO"
    ]
    # INFO severity is legitimate for some checks; a wholesale block of them is
    # the old stand-in coming back.
    assert len(placeholders) < 10, (
        f"{len(placeholders)} PASS/INFO rows carry INFO severity — the recovered "
        f"placeholder is back: {placeholders}"
    )


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
    """Templates describing the outcome that produced this row.

    Name and status alone do not identify an outcome: AutoPlay has three WARN
    call sites with different remediation, so matching on those two lets any of
    them validate another's fields. `details` is what says which branch ran —
    it is machine-owned and never asserted to be current, only used to pick the
    outcome. When it does narrow the candidates, the narrowed set wins; when it
    cannot, every candidate stays and the caller requires agreement.
    """
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

    # Keep what the details match learned. `{count}` appearing in both details
    # and remediation is one value, not two: discarding the binding lets details
    # say 3 pending updates while the remediation says 999, each satisfying its
    # own independent wildcard.
    discriminated = []
    for template, bound in out:
        if template.details is None:
            continue
        learned = _match(template.details, row["details"], bound)
        if learned is not None:
            discriminated.append((template, {**bound, **learned}))
    return discriminated or out


def _verify_row(row) -> str | None:
    """None if every code-owned field is accounted for; otherwise why not."""
    candidates = _templates_for(row)
    if not candidates:
        return "no check-module template matches this name and status"

    # Ambiguity is not a licence to take whichever candidate fits. If details
    # could not narrow to one outcome and the survivors disagree about a
    # code-owned field, then a row carrying any of their values validates —
    # which is how the partial-AutoPlay row accepted a different WARN
    # outcome's remediation.
    if len(candidates) > 1:
        for field in command_audit.RESULT_TEXT_FIELDS:
            if VALIDATORS.get((row["check_name"], row["status"], field)):
                continue
            if len({getattr(t, field) for t, _ in candidates}) > 1:
                lines = sorted(f"{t.module}:{t.line}" for t, _ in candidates)
                return (
                    f"{field}: {len(candidates)} outcomes ({', '.join(lines)}) share this "
                    "name and status and disagree; details did not identify which one ran"
                )

    problems = []
    for template, bound in candidates:
        failed = None
        # Severity drives the score, so a source change here staled the
        # published report and its number while every other check stayed green.
        # Compared across the matched outcomes rather than against one, because
        # a check may pick its severity from runtime state this cannot see —
        # encryption.py takes HIGH for the OS drive and MEDIUM for any other.
        emitted = {t.severity for t, _ in candidates if t.severity is not None}
        if emitted and row["severity"] not in emitted:
            problems.append(
                f"severity: row says {row['severity']} but "
                f"{template.module}:{template.line} emits {sorted(emitted)}"
            )
            continue
        for field in command_audit.RESULT_TEXT_FIELDS:
            validator = VALIDATORS.get((row["check_name"], row["status"], field))
            if validator is not None:
                failed = validator(row)
                if failed:
                    failed = f"{field}: {failed}"
                    break
                continue
            if field in template.unresolved:
                failed = f"{field}: not statically resolvable and no validator"
                break
            # A placeholder nothing can bind is not a runtime value, it is a
            # sub-expression the resolver gave up on — `{sid}` from a variable,
            # `{render}` from a method call. Matched as `.+?` it accepts any
            # text at all, which is the wildcard hole under a friendlier name.
            # Fail closed unless the check name or details pin it.
            literal = getattr(template, field) or ""
            loose = sorted(
                (set(_ANY_PLACEHOLDER.findall(literal)) - set(bound))
                | (set(_ANY_PLACEHOLDER.findall(literal)) & template.opaque)
            )
            if loose:
                failed = (
                    f"{field}: {', '.join(loose)} bound by neither the check name "
                    f"nor details, so it would match anything "
                    f"({template.module}:{template.line})"
                )
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


def _fail_row_takes_the_pass_pair(row: dict) -> dict:
    # accounts.py binds status in an if-chain, then keys remediation and command
    # off `status is Status.PASS`. Treating that settled condition as a free
    # branch emits a FAIL outcome with the PASS blank pair, which the runtime
    # cannot produce — and blanking both fields together validated against it.
    row["remediation"] = ""
    row["command"] = ""
    return row


def _outcome_swapped_within_one_status(row: dict) -> dict:
    # AutoPlay has three WARN call sites with different remediation. Name and
    # status alone do not say which one ran, so without `details` as the
    # discriminator any of them validated another's fields.
    other = next(
        t.remediation for t in command_audit.collect_result_templates()
        if t.check_name == "AutoPlay Disabled" and t.status == "WARN"
        and t.remediation and t.remediation != row["remediation"]
    )
    row["remediation"] = other
    return row


def _audit_command_disables_instead_of_enabling(row: dict) -> dict:
    # Names the right subcategory and silences its auditing. Reading only the
    # quoted names accepted this; the whole line has to match the template.
    row["command"] = row["command"].replace(
        "/success:enable /failure:enable", "/success:disable /failure:disable"
    )
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
    pytest.param("Password Policy — Minimum Length", _fail_row_takes_the_pass_pair,
                 id="impossible-branch-combination"),
    pytest.param("AutoPlay Disabled", _outcome_swapped_within_one_status,
                 id="outcome-swapped-within-one-status"),
    pytest.param("Audit Policy", _audit_command_disables_instead_of_enabling,
                 id="audit-command-disables"),
]


@pytest.mark.parametrize(("check_name", "mutate"), MUTATIONS)
def test_guard_rejects(check_name: str, mutate) -> None:
    row = _row(check_name)
    assert _verify_row(row) is None, f"{check_name} does not verify before mutation"
    assert _verify_row(mutate(row)) is not None, "the guard accepted a mutated row"


# ── Audit Policy: unreported is not disabled ────────────────────────────────

_AUDIT_SUFFIX = (
    " This can also be configured via Group Policy "
    "(secpol.msc → Advanced Audit Policy Configuration)."
)


def _audit_row(details: str, command: str, fix: str) -> dict:
    row = _row("Audit Policy")
    row["details"] = details
    row["command"] = command
    row["remediation"] = fix + _AUDIT_SUFFIX
    return row


_MISSING_ONLY_DETAILS = (
    "Not all expected audit subcategories are confirmed logging: "
    "Logon (not reported). Security-relevant events may not be recorded."
)


def test_missing_only_outcome_with_no_command_is_accepted() -> None:
    """A subcategory auditpol never reported was not observed disabled.

    The source deliberately emits no command for it — enabling auditing the
    operator never asked for is a change they did not consent to. A guard that
    reads the reported names without distinguishing "(not reported)" rejects
    this source-correct row.
    """
    row = _audit_row(_MISSING_ONLY_DETAILS, "", misc._FIX_AUDIT_UNREPORTED)
    assert _verify_row(row) is None


def test_command_enabling_an_unreported_subcategory_is_rejected() -> None:
    row = _audit_row(
        _MISSING_ONLY_DETAILS,
        misc._CMD_AUDITPOL_ENABLE.format(subcategory="Logon"),
        misc._FIX_AUDIT_UNREPORTED,
    )
    assert _verify_row(row) is not None


@pytest.mark.parametrize(
    ("label", "remediation"),
    [
        ("fabricated policy path",
         misc._FIX_AUDIT_DISABLED + " TOTALLY WRONG POLICY AREA secpol.msc"),
        ("appended instructions", None),   # filled in below
        ("wrong outcome wording", misc._FIX_AUDIT_UNREPORTED + _AUDIT_SUFFIX),
    ],
)
def test_audit_remediation_must_equal_the_wording_for_its_outcome(
    label: str, remediation: str | None
) -> None:
    """Prefix plus a `secpol.msc` substring is fail-open."""
    row = _row("Audit Policy")
    row["remediation"] = (
        row["remediation"] + " Also, email the auditor."
        if remediation is None else remediation
    )
    assert _verify_row(row) is not None, label


# ── Bindings and wildcards ──────────────────────────────────────────────────

def test_a_value_learned_from_details_constrains_the_other_fields() -> None:
    """`{count}` in details and in remediation is one value, not two.

    Discarding what the details match learned lets details say 3 and the
    remediation say 999, each satisfying its own independent wildcard.
    """
    template = "Found {count} item(s)."
    bound = _match(template, "Found 3 item(s).")
    assert bound == {"count": "3"}
    # The same binding must then pin the other field.
    assert _match("Fix all {count} of them.", "Fix all 3 of them.", bound) is not None
    assert _match("Fix all {count} of them.", "Fix all 999 of them.", bound) is None


def test_a_placeholder_nothing_binds_is_not_treated_as_a_runtime_value() -> None:
    """`{sid}`, `{render}` and friends are the resolver giving up.

    Matched as an unbound group they accept any text at all. A row whose
    template carries one must fail closed rather than validate.
    """
    row = _row("Built-in Administrator Account")
    # accounts.py emits `Disable-LocalUser -SID '{sid}'` on its enabled branch;
    # nothing in the check name or details binds {sid}.
    row["status"] = "WARN"
    row["severity"] = "LOW"   # what accounts.py emits on the enabled branch
    row["details"] = "Built-in Administrator account is enabled (renamed to 'x')."
    row["remediation"] = (
        "Consider disabling the built-in Administrator account if it is not in active use."
    )
    row["command"] = "Disable-LocalUser -SID 'ANYTHING-AT-ALL'"
    why = _verify_row(row)
    assert why is not None and "bound by neither" in why, why


def test_the_sample_contains_exactly_the_expected_checks() -> None:
    """Status totals do not prove the right checks are present.

    Swapping one row for a duplicate of another leaves 53 rows, the same
    per-status counts, and every row individually verifiable — the sample would
    simply stop showing a check while every guard stayed green.
    """
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    names = [r["check_name"] for r in report["results"]]

    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"the sample repeats a check: {duplicates}"
    assert len(names) == sum(EXPECTED_COUNTS.values())

    # Pinned so a check disappearing from the sample is a failure, not a
    # silently shorter report.
    assert sorted(names) == sorted(EXPECTED_CHECK_NAMES), {
        "missing": sorted(set(EXPECTED_CHECK_NAMES) - set(names)),
        "unexpected": sorted(set(names) - set(EXPECTED_CHECK_NAMES)),
    }
