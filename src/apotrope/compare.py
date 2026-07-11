"""Comparative scanning — diff two AuditReports to track remediation progress.

Usage from CLI:
    apotrope --baseline baseline.json   # save current scan as baseline
    apotrope --compare  baseline.json   # compare current scan against baseline

The diff identifies:
  - New findings: FAIL/WARN in current scan that weren't in the baseline
  - Resolved findings: FAIL/WARN in baseline that are now PASS/INFO in current
  - Worsened findings: check was PASS/INFO in baseline, now FAIL/WARN
  - Score delta: points gained or lost since the baseline
"""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from apotrope.models import AuditReport, CheckResult, Severity, Status

log = logging.getLogger(__name__)

# Statuses considered "bad" — an active finding the user should act on.
_BAD = {Status.FAIL, Status.WARN}
# ERROR means the check could not be evaluated: indeterminate, never "good".
# Bucketed separately so a check that stops evaluating is never mistaken for a
# remediated one — the same honesty principle as ``missing_findings``.
_INDETERMINATE = {Status.ERROR}


@dataclasses.dataclass
class ScanDiff:
    """Differences between a baseline and a current AuditReport.

    Attributes:
        baseline_score:    Security score from the baseline scan.
        current_score:     Security score from the current scan.
        score_delta:       current_score − baseline_score (positive = improved).
        new_findings:      Checks that are FAIL/WARN now but were not in baseline.
        resolved_findings: Checks that were FAIL/WARN in baseline but are now PASS/INFO
                           (present in BOTH scans — genuinely remediated).
        missing_findings:  Checks that were FAIL/WARN in baseline but ABSENT from the
                           current scan. This is coverage lost (a narrower --category,
                           a disabled/admin-gated check, an import failure, or a rename)
                           — NOT proof of remediation. Tracked separately so a reduced
                           scan is never mistaken for fixed risk.
        errored_findings:  Checks that were FAIL/WARN in baseline but ERRORed in the
                           current scan (present, but could not be evaluated). Like
                           missing_findings this is indeterminate — never counted as
                           resolved, because an unevaluable check is not a fixed one.
        worsened_findings: Checks that were PASS/INFO in baseline but are now FAIL/WARN.
        unchanged_bad:     Checks that were FAIL/WARN in both scans.
        unchanged_count:   Total number of checks with the same status in both scans.
    """

    baseline_score: int
    current_score: int
    score_delta: int
    new_findings: list[CheckResult]
    resolved_findings: list[CheckResult]
    worsened_findings: list[CheckResult]
    unchanged_bad: list[CheckResult]
    unchanged_count: int
    missing_findings: list[CheckResult] = dataclasses.field(default_factory=list)
    errored_findings: list[CheckResult] = dataclasses.field(default_factory=list)


def compare_reports(baseline: AuditReport, current: AuditReport) -> ScanDiff:
    """Diff *current* against *baseline* and return a :class:`ScanDiff`.

    Checks are matched by ``(category, check_name)``.  Checks present in only
    one report are treated as new (current-only) or resolved (baseline-only).

    Args:
        baseline: The reference AuditReport loaded from a saved JSON file.
        current:  The freshly-run AuditReport.

    Returns:
        A ScanDiff with categorised findings and score delta.
    """
    # Index both reports by key
    base_map = {(r.category, r.check_name): r for r in baseline.results}
    curr_map = {(r.category, r.check_name): r for r in current.results}

    all_keys = set(base_map) | set(curr_map)

    new_findings: list[CheckResult] = []
    resolved_findings: list[CheckResult] = []
    missing_findings: list[CheckResult] = []
    errored_findings: list[CheckResult] = []
    worsened_findings: list[CheckResult] = []
    unchanged_bad: list[CheckResult] = []
    unchanged_count = 0

    for key in sorted(all_keys):
        b = base_map.get(key)
        c = curr_map.get(key)

        if b is None and c is not None:
            # Only in current scan
            if c.status in _BAD:
                new_findings.append(c)
            else:
                unchanged_count += 1
        elif c is None and b is not None:
            # Only in baseline: this check did not run in the current scan.
            # A bad check vanishing is NOT remediation — it can be a narrower
            # --category set, a disabled/admin-gated check, an import failure,
            # or a rename. Bucket it as coverage lost, never as resolved.
            if b.status in _BAD:
                missing_findings.append(b)
            else:
                unchanged_count += 1
        else:
            assert b is not None and c is not None
            b_bad = b.status in _BAD
            c_bad = c.status in _BAD
            c_indeterminate = c.status in _INDETERMINATE

            if b_bad and c_indeterminate:
                # Was a finding, now unevaluable: cannot confirm remediation.
                # Must be intercepted before the resolved branch, since ERROR
                # is not in _BAD and would otherwise read as "no longer bad".
                errored_findings.append(c)
            elif b_bad and not c_bad:
                resolved_findings.append(c)
            elif not b_bad and c_bad:
                worsened_findings.append(c)
            elif b_bad and c_bad:
                unchanged_bad.append(c)
            else:
                unchanged_count += 1

    score_delta = current.score - baseline.score

    return ScanDiff(
        baseline_score=baseline.score,
        current_score=current.score,
        score_delta=score_delta,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        missing_findings=missing_findings,
        errored_findings=errored_findings,
        worsened_findings=worsened_findings,
        unchanged_bad=unchanged_bad,
        unchanged_count=unchanged_count,
    )


def save_baseline(report: AuditReport, path: str) -> None:
    """Serialise *report* to JSON at *path* for use as a future baseline.

    Args:
        report: A completed AuditReport from scanner.run().
        path:   Destination file path.
    """
    from apotrope.reporter import Reporter
    Reporter().generate_json_report(report, path)
    log.info("Baseline saved to %s", path)


def load_baseline(path: str) -> AuditReport:
    """Deserialise an AuditReport baseline from a JSON file.

    Args:
        path: Path to a JSON file previously saved by :func:`save_baseline`
              or ``apotrope --json``.

    Returns:
        An AuditReport reconstructed from the JSON.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the JSON cannot be parsed as an AuditReport.
    """
    raw = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in baseline file {path!r}: {exc}") from exc

    try:
        results = [
            CheckResult(
                category=r["category"],
                check_name=r["check_name"],
                status=Status(r["status"]),
                severity=Severity(r["severity"]),
                description=r.get("description", ""),
                details=r.get("details", ""),
                remediation=r.get("remediation", ""),
                command=r.get("command", ""),
                check_duration=float(r.get("check_duration", 0.0)),
                cis_reference=r.get("cis_reference", ""),
            )
            for r in data.get("results", [])
        ]
        ts = datetime.fromisoformat(data["scan_timestamp"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)   # assume naive timestamps are UTC
        else:
            ts = ts.astimezone(timezone.utc)        # convert offset timestamps, don't relabel
        return AuditReport(
            hostname=data["hostname"],
            os_version=data.get("os_version", ""),
            scan_timestamp=ts,
            scan_duration=float(data.get("scan_duration", 0.0)),
            results=results,
            score=int(data.get("score", 0)),
            is_admin=bool(data.get("is_admin", False)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Malformed baseline JSON in {path!r}: {exc}") from exc
