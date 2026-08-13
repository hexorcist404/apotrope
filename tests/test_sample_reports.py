"""Guard: the published sample reports stay reproducible and stay current.

``docs/report.html`` and ``docs/exec-report.html`` are the samples linked from
apotrope.sh. They were once hand-made from a real scan with no tracked input, so
when the package version moved they could not be regenerated and sat advertising
v0.1.12 two releases later. ``tools/fixtures/sample_report.json`` is now their
source and ``tools/generate_sample_reports.py`` renders them.

Two failure modes are guarded here:

* **Branding drift** — a committed asset naming a version the package no longer
  is. Covers ``docs/index.html`` too, whose demo terminal and JSON-LD carry the
  same version by hand.
* **Source drift** — the committed assets no longer being what the fixture
  renders, which would put the reproducible path back where it started.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

import apotrope
from apotrope.compare import load_baseline
from apotrope.models import Status
from apotrope.scoring import calculate_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

# Imported in-process, not spawned: conftest's autouse guard patches
# subprocess.run process-wide, so shelling out to the generator would raise.
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
