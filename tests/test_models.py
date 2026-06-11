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
