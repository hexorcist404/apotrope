"""Tests for apotrope.models — CheckResult/AuditReport helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from apotrope.models import AuditReport, CheckResult, Severity, Status


def _result(category: str, name: str = "Check") -> CheckResult:
    return CheckResult(
        category=category, check_name=name, status=Status.PASS,
        severity=Severity.LOW, description="d", details="ok",
    )


def _report(results: list[CheckResult]) -> AuditReport:
    return AuditReport(
        hostname="PC",
        os_version="Win11",
        scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_duration=1.0,
        results=results,
    )


class TestByCategory:
    def test_returns_matching_results(self):
        report = _report([_result("Firewall", "A"), _result("Accounts", "B")])
        matches = report.by_category("Firewall")
        assert [r.check_name for r in matches] == ["A"]

    def test_match_is_case_insensitive(self):
        report = _report([_result("Firewall")])
        assert len(report.by_category("FIREWALL")) == 1
        assert len(report.by_category("firewall")) == 1

    def test_unknown_category_returns_empty(self):
        report = _report([_result("Firewall")])
        assert report.by_category("Nope") == []


def _status_result(status: Status) -> CheckResult:
    return CheckResult(
        category="Test", check_name="x", status=status,
        severity=Severity.LOW, description="d", details="ok",
    )


class TestEvaluatedCount:
    def test_counts_pass_fail_warn_only(self):
        report = _report([
            _status_result(Status.PASS),
            _status_result(Status.FAIL),
            _status_result(Status.WARN),
            _status_result(Status.INFO),
            _status_result(Status.ERROR),
        ])
        # INFO and ERROR are not evaluated controls.
        assert report.evaluated_count == 3

    def test_all_error_report_evaluates_nothing(self):
        report = _report([_status_result(Status.ERROR), _status_result(Status.ERROR)])
        assert report.evaluated_count == 0

    def test_empty_report_evaluates_nothing(self):
        assert _report([]).evaluated_count == 0
