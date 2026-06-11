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

    def test_check_removed_from_current(self):
        """A failing check in baseline but absent in current → resolved."""
        baseline = _make_report([_make_result("OldCheck", Status.FAIL)])
        current  = _make_report([])
        diff = compare_reports(baseline, current)
        assert len(diff.resolved_findings) == 1

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
