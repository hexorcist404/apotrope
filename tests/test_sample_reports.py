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
  password without ever displaying or saving it — retrievable while Windows
  still boots, but not at the recovery screen, which is where it is needed — a
  bare ``Set-ItemProperty`` AutoPlay write that fails outright when its policy
  key does not exist, and a WMI call that discards its ``ReturnValue``. All
  three had been fixed in the source by then and all three were published under
  a v0.2.0 banner.

What the fixture owns splits by *origin*, not neatly by field, and that split
is what makes it a sanitized scan rather than a snapshot of an old release:

* **machine-owned** — ``status``, ``hostname``, ``score``, timestamps, and the
  observations carried inside ``details`` (which subcategories were disabled,
  which drive is unencrypted). Frozen at the sample machine.
* **code-owned** — ``description``, ``remediation``, ``command``,
  ``cis_reference``, and the prose that wraps those observations in
  ``details``. These *should* say what the modules say today.

``details`` therefore straddles both: the finding is the machine's, the
sentence around it is the source's.

What this module actually enforces is narrower than that second bullet, and
the gap is deliberate — closing it is what turned an earlier attempt at this
guard into a rewrite of the whole check layer:

* every fixture command passes the shipped remediation lint;
* every non-Audit command must appear in the command inventory — a
  **whitespace-normalized** comparison against a **statically extracted**
  inventory, so it proves the command is one the modules still carry, not that
  the two are byte-identical;
* the Audit Policy row is pinned on its own — the command from the module's
  template, the details as an exact pin on this persona's finding;
* ``cis_reference`` is checked against ``cis_map``.

Nothing here verifies ``description``, ``remediation`` or the general
``details`` prose against source. Some of it is still v0.1.12-era: Guest
Account omits the ``('Guest', RID-501)`` the module now names, and Pending
Windows Updates says "were found; the system is up to date" where the module
says "No pending Windows Updates found." Those are known and left alone — the
published *commands* are correct, which is what this change is for.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

import apotrope
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


def _squash(text: str) -> str:
    """Collapse whitespace runs so reflowed source literals still compare equal."""
    return re.sub(r"\s+", " ", text).strip()

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


def test_fixture_commands_are_still_shipped_by_the_check_modules() -> None:
    """Every sample command must be one the modules emit today, verbatim.

    Catches drift no lint rule models — a reworded comment, a dropped guard —
    by requiring membership in the real inventory rather than mere plausibility.
    Runtime values are substituted back out: ``BitLocker — G:`` renders the
    ``{mount}`` command with its own mount point.

    Audit Policy is excluded here and checked by
    ``test_the_audit_policy_command_enables_the_reported_subcategories``
    instead. Its command is one enable line per subcategory this scan found
    disabled, so membership would have to fold the subcategory name back into
    the template — and that fold accepts *any* name, including the hardcoded
    'Logon' this sample once carried. The dedicated check pins the exact
    subcategory instead, which the fold cannot do.
    """
    shipped = {_squash(c.text) for c in command_audit.collect_commands()}

    stale: list[str] = []
    for cmd in _fixture_commands():
        if cmd.module == "Audit Policy":
            continue
        candidates = {_squash(cmd.text)}
        # Per-row mount, taken from the check name (e.g. "BitLocker — G:").
        mount = cmd.module.rsplit("—", 1)[-1].strip()
        if re.fullmatch(r"[A-Z]:", mount):
            candidates.add(_squash(cmd.text.replace(mount, "{mount}")))
        if not candidates & shipped:
            stale.append(cmd.module)

    assert not stale, (
        f"these sample commands are no longer what the check modules emit: {stale}. "
        "Refresh them from source, then regenerate: " + REGENERATE
    )


#: The subcategories the sample machine reports as confirmed disabled. Pinned,
#: because the Audit Policy command is built from them: a fixture naming a
#: different subcategory — or the hardcoded 'Logon' the sample carried before
#: the check emitted one line per finding — must fail rather than be
#: normalized into agreement.
_SAMPLE_AUDIT_SUBCATEGORIES = ("Sensitive Privilege Use",)


def test_the_audit_policy_command_enables_the_reported_subcategories() -> None:
    """The sample's audit command must enable exactly what its details report.

    The two halves are pinned by different means. The command is built from
    ``misc._CMD_AUDITPOL_ENABLE``, so it stays tied to the source template.
    The details prose is not source-linked: it is an exact pin on this
    persona's finding, rejecting a subcategory that goes missing, one that is
    added, and one that is swapped for another. Equality rather than
    membership is what buys the last two — a membership test accepts a details
    line naming extra subcategories, and accepted the hardcoded 'Logon'
    command this sample used to carry.

    It is not a source-drift alarm for the details wording. Catching a reword
    that happens only in the source would mean executing the real check or
    exposing its sentence as a constant, and neither is in scope here.
    """
    row = next(
        r for r in load_baseline(str(FIXTURE)).results if r.check_name == "Audit Policy"
    )
    expected_command = "\n".join(
        misc._CMD_AUDITPOL_ENABLE.format(subcategory=name)
        for name in _SAMPLE_AUDIT_SUBCATEGORIES
    )
    assert row.command == expected_command, (
        "the sample's Audit Policy command does not enable exactly the "
        f"subcategories it reports as disabled. Refresh it, then regenerate: {REGENERATE}"
    )
    # Mirrors how _check_audit_policy builds the line. Equality, not
    # membership, so a missing, extra or substituted subcategory all fail.
    expected_details = (
        "Not all expected audit subcategories are confirmed logging: "
        f"{', '.join(_SAMPLE_AUDIT_SUBCATEGORIES)}. "
        "Security-relevant events may not be recorded."
    )
    assert row.details == expected_details, (
        "the sample's Audit Policy details no longer report exactly the "
        f"subcategories its command enables. Refresh it, then regenerate: {REGENERATE}"
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
