"""Regenerate the published sample reports from their tracked fixture.

``docs/report.html`` and ``docs/exec-report.html`` are the sample reports linked
from apotrope.sh. They were originally produced by scanning a real machine and
sanitizing the result by hand, which left them with no reproducible input: when
the package version moved they could not be refreshed, and they sat advertising
v0.1.12 two releases later.

``tools/fixtures/sample_report.json`` is now that input — a sanitized
``AuditReport`` in exactly the shape ``Reporter.generate_json_report`` writes and
``compare.load_baseline`` reads. This script renders both reports from it, so a
release only has to run one command to bring the public samples current.

The fixture's PASS/INFO rows carry a uniform placeholder severity: the technical
template renders severity only for FAIL/WARN, so the original values for the
other 47 rows are not present in either published artifact. Nothing renders or
scores them, and a uniform value keeps the stable per-category sort a no-op.

Usage:  python tools/generate_sample_reports.py [--output-dir PATH]
Exit code 0 == both reports were written.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from apotrope.compare import load_baseline
from apotrope.models import AuditReport, Status
from apotrope.reporter import Reporter
from apotrope.scoring import calculate_score

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools" / "fixtures" / "sample_report.json"
DEFAULT_OUTPUT_DIR = ROOT / "docs"

TECHNICAL_NAME = "report.html"
EXECUTIVE_NAME = "exec-report.html"

# The sanitized persona the published samples present. Asserted on every run so
# a fixture edit cannot quietly republish a different machine.
EXPECTED_HOSTNAME = "WORKSTATION-07"
EXPECTED_SCORE = 75
EXPECTED_COUNTS = {Status.PASS: 34, Status.FAIL: 3, Status.WARN: 3, Status.INFO: 13}


def _validate(report: AuditReport) -> list[str]:
    """Return a list of persona violations; empty means the fixture is intact."""
    problems: list[str] = []

    if report.hostname != EXPECTED_HOSTNAME:
        problems.append(f"hostname is {report.hostname!r}, expected {EXPECTED_HOSTNAME!r}")
    if not report.is_admin:
        problems.append(
            "is_admin is False — the executive report would render 'Standard user' "
            "and rewrite its scope paragraph"
        )

    total = sum(EXPECTED_COUNTS.values())
    if len(report.results) != total:
        problems.append(f"{len(report.results)} results, expected {total}")
    for status, expected in EXPECTED_COUNTS.items():
        actual = len(report.by_status(status))
        if actual != expected:
            problems.append(f"{actual} {status.value} results, expected {expected}")

    # The stored score is what renders in the gauge; load_baseline trusts it and
    # never recomputes. Check both, so neither can drift from the other.
    if report.score != EXPECTED_SCORE:
        problems.append(f"stored score is {report.score}, expected {EXPECTED_SCORE}")
    calculated = calculate_score(report.results)
    if calculated != EXPECTED_SCORE:
        problems.append(f"calculated score is {calculated}, expected {EXPECTED_SCORE}")

    return problems


def main(argv: list[str] | None = None) -> int:
    """Render both sample reports into the output directory. Returns an exit code."""
    parser = argparse.ArgumentParser(
        description="Regenerate the published sample reports from their tracked fixture.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"destination directory for the two reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args(argv)

    # load_baseline is annotated `path: str`, not `str | Path`.
    try:
        report = load_baseline(str(FIXTURE))
    except (OSError, ValueError) as exc:
        print(f"could not load {FIXTURE}: {exc}", file=sys.stderr)
        return 1

    problems = _validate(report)
    if problems:
        print(f"{FIXTURE} does not match the sanitized sample persona:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    reporter = Reporter()

    # Executive report first so the technical report's header link has a target.
    # Both reporters return False on failure rather than raising, so a report
    # that was never written must not be reported as success.
    if not reporter.generate_executive_report(report, str(output_dir / EXECUTIVE_NAME)):
        print(f"could not write {output_dir / EXECUTIVE_NAME}", file=sys.stderr)
        return 1
    if not reporter.generate_html_report(
        report, str(output_dir / TECHNICAL_NAME), exec_href=EXECUTIVE_NAME
    ):
        print(f"could not write {output_dir / TECHNICAL_NAME}", file=sys.stderr)
        return 1

    print(f"wrote {output_dir / TECHNICAL_NAME}")
    print(f"wrote {output_dir / EXECUTIVE_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
