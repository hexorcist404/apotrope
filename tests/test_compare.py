"""Tests for apotrope.compare — scan diffing and baseline serialisation."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from apotrope.compare import compare_reports, load_baseline, save_baseline
from apotrope.models import AuditReport, CheckResult, Severity, Status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _make_result(
    check_name: str,
    status: Status,
    category: str = "Test",
    severity: Severity = Severity.HIGH,
) -> CheckResult:
    return CheckResult(
        category=category,
        check_name=check_name,
        status=status,
        severity=severity,
        description="d",
        details="d",
    )


def _make_report(results: list[CheckResult], score: int = 80) -> AuditReport:
    return AuditReport(
        hostname="PC",
        os_version="Win11",
        scan_timestamp=_ts(),
        scan_duration=1.0,
        results=results,
        score=score,
    )


# ---------------------------------------------------------------------------
# compare_reports
# ---------------------------------------------------------------------------

class TestCompareReports:
    def test_resolved_finding(self):
        baseline = _make_report([_make_result("Firewall", Status.FAIL)])
        current  = _make_report([_make_result("Firewall", Status.PASS)])
        diff = compare_reports(baseline, current)
        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0].check_name == "Firewall"

    def test_new_finding(self):
        """A FAIL check in current that is absent from baseline → new finding."""
        baseline = _make_report([])
        current  = _make_report([_make_result("NewCheck", Status.FAIL)])
        diff = compare_reports(baseline, current)
        assert len(diff.new_findings) == 1

    def test_worsened_finding(self):
        baseline = _make_report([_make_result("SMB", Status.PASS)])
        current  = _make_report([_make_result("SMB", Status.WARN)])
        diff = compare_reports(baseline, current)
        assert len(diff.worsened_findings) == 1

    def test_unchanged_bad(self):
        baseline = _make_report([_make_result("RDP", Status.FAIL)])
        current  = _make_report([_make_result("RDP", Status.FAIL)])
        diff = compare_reports(baseline, current)
        assert len(diff.unchanged_bad) == 1
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 0

    def test_score_delta_positive(self):
        diff = compare_reports(
            _make_report([], score=60),
            _make_report([], score=80),
        )
        assert diff.score_delta == 20

    def test_score_delta_negative(self):
        diff = compare_reports(
            _make_report([], score=90),
            _make_report([], score=70),
        )
        assert diff.score_delta == -20

    def test_new_check_not_in_baseline(self):
        """A check in current but not in baseline that is FAIL → new finding."""
        baseline = _make_report([])
        current  = _make_report([_make_result("NewCheck", Status.FAIL)])
        diff = compare_reports(baseline, current)
        assert len(diff.new_findings) == 1

    def test_check_removed_from_current_is_missing_not_resolved(self):
        """A failing check absent from current is coverage lost, NOT resolved.

        Absence can be a narrower --category set, a disabled/admin-gated check,
        an import failure, or a rename — none of which is remediation.
        """
        baseline = _make_report([_make_result("OldCheck", Status.FAIL)])
        current  = _make_report([])
        diff = compare_reports(baseline, current)
        assert len(diff.missing_findings) == 1
        assert diff.missing_findings[0].check_name == "OldCheck"
        assert diff.resolved_findings == []

    def test_genuinely_remediated_check_is_resolved(self):
        """A check present in BOTH scans that left FAIL/WARN is truly resolved."""
        baseline = _make_report([_make_result("Firewall", Status.FAIL)])
        current  = _make_report([_make_result("Firewall", Status.PASS)])
        diff = compare_reports(baseline, current)
        assert len(diff.resolved_findings) == 1
        assert diff.missing_findings == []

    def test_pass_to_pass_unchanged(self):
        baseline = _make_report([_make_result("X", Status.PASS)])
        current  = _make_report([_make_result("X", Status.PASS)])
        diff = compare_reports(baseline, current)
        assert diff.unchanged_count == 1
        assert diff.new_findings == []
        assert diff.resolved_findings == []

    def test_baseline_and_current_scores_captured(self):
        diff = compare_reports(
            _make_report([], score=55),
            _make_report([], score=85),
        )
        assert diff.baseline_score == 55
        assert diff.current_score == 85


# ---------------------------------------------------------------------------
# Errored checks: an ERROR in the current scan means "could not evaluate",
# which is indeterminate — never proof of remediation.
# ---------------------------------------------------------------------------

class TestErroredChecks:
    def test_fail_to_error_is_errored_not_resolved(self):
        """A FAIL check that ERRORs in the current scan cannot be confirmed
        remediated. It must be reported as errored, never resolved."""
        baseline = _make_report([_make_result("Complexity", Status.FAIL)])
        current  = _make_report([_make_result("Complexity", Status.ERROR)])
        diff = compare_reports(baseline, current)
        assert diff.resolved_findings == []
        assert len(diff.errored_findings) == 1
        assert diff.errored_findings[0].check_name == "Complexity"

    def test_warn_to_error_is_errored_not_resolved(self):
        baseline = _make_report([_make_result("Signature Age", Status.WARN)])
        current  = _make_report([_make_result("Signature Age", Status.ERROR)])
        diff = compare_reports(baseline, current)
        assert diff.resolved_findings == []
        assert len(diff.errored_findings) == 1

    def test_error_to_pass_is_not_falsely_resolved(self):
        """A check that was ERROR in baseline and PASSes now was never a known
        finding — there is nothing to credit as resolved."""
        baseline = _make_report([_make_result("X", Status.ERROR)])
        current  = _make_report([_make_result("X", Status.PASS)])
        diff = compare_reports(baseline, current)
        assert diff.resolved_findings == []
        assert diff.errored_findings == []
        assert diff.unchanged_count == 1

    def test_error_in_both_scans_is_not_a_finding(self):
        """ERROR → ERROR is unchanged indeterminacy, not a resolved/new finding."""
        baseline = _make_report([_make_result("Y", Status.ERROR)])
        current  = _make_report([_make_result("Y", Status.ERROR)])
        diff = compare_reports(baseline, current)
        assert diff.resolved_findings == []
        assert diff.errored_findings == []
        assert diff.new_findings == []


# ---------------------------------------------------------------------------
# save_baseline / load_baseline
# ---------------------------------------------------------------------------

class TestBaselineSerialization:
    def _roundtrip(self, results: list[CheckResult], score: int = 80) -> AuditReport:
        report = _make_report(results, score)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_baseline(report, path)
            return load_baseline(path)
        finally:
            os.unlink(path)

    def test_hostname_preserved(self):
        loaded = self._roundtrip([])
        assert loaded.hostname == "PC"

    def test_score_preserved(self):
        loaded = self._roundtrip([], score=73)
        assert loaded.score == 73

    def test_results_count_preserved(self):
        results = [
            _make_result("A", Status.PASS),
            _make_result("B", Status.FAIL),
        ]
        loaded = self._roundtrip(results)
        assert len(loaded.results) == 2

    def test_result_fields_preserved(self):
        r = _make_result("Firewall", Status.FAIL, severity=Severity.CRITICAL)
        loaded = self._roundtrip([r])
        lr = loaded.results[0]
        assert lr.check_name == "Firewall"
        assert lr.status == Status.FAIL
        assert lr.severity == Severity.CRITICAL

    def test_cis_reference_preserved(self):
        r = _make_result("Firewall", Status.FAIL)
        r.cis_reference = "CIS 9.1.1"
        loaded = self._roundtrip([r])
        assert loaded.results[0].cis_reference == "CIS 9.1.1"

    def test_load_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_baseline("/nonexistent/path/baseline.json")

    def test_load_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not json {{")
            path = f.name
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                load_baseline(path)
        finally:
            os.unlink(path)

    def test_load_malformed_report_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump({"hostname": "X"}, f)  # missing required fields
            path = f.name
        try:
            with pytest.raises(ValueError, match="Malformed"):
                load_baseline(path)
        finally:
            os.unlink(path)


class TestBaselineTimestampParsing:
    """load_baseline must convert offset timestamps to UTC, not relabel them (finding #7)."""

    def _load_with_timestamp(self, ts_string: str) -> AuditReport:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump({"hostname": "PC", "scan_timestamp": ts_string}, f)
            path = f.name
        try:
            return load_baseline(path)
        finally:
            os.unlink(path)

    def test_naive_timestamp_assumed_utc(self):
        loaded = self._load_with_timestamp("2026-06-25T10:00:00")
        assert loaded.scan_timestamp == datetime(2026, 6, 25, 10, 0, tzinfo=timezone.utc)

    def test_utc_timestamp_unchanged(self):
        loaded = self._load_with_timestamp("2026-06-25T10:00:00+00:00")
        assert loaded.scan_timestamp == datetime(2026, 6, 25, 10, 0, tzinfo=timezone.utc)

    def test_offset_timestamp_converted_not_relabeled(self):
        # 10:00 at -04:00 is 14:00 UTC; the instant must be converted, not relabeled to 10:00Z.
        loaded = self._load_with_timestamp("2026-06-25T10:00:00-04:00")
        assert loaded.scan_timestamp == datetime(2026, 6, 25, 14, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# One-sided good results count as unchanged
# ---------------------------------------------------------------------------

class TestOneSidedGoodResults:
    def test_current_only_pass_counts_as_unchanged(self):
        baseline = _make_report([])
        current = _make_report([_make_result("New Pass", Status.PASS)])
        diff = compare_reports(baseline, current)
        assert diff.new_findings == []
        assert diff.unchanged_count == 1

    def test_baseline_only_pass_counts_as_unchanged(self):
        baseline = _make_report([_make_result("Old Pass", Status.PASS)])
        current = _make_report([])
        diff = compare_reports(baseline, current)
        assert diff.resolved_findings == []
        assert diff.unchanged_count == 1
