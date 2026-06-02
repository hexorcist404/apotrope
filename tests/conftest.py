"""Shared pytest fixtures for Apotrope tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apotrope.models import AuditReport, CheckResult, Severity, Status


@pytest.fixture()
def pass_result() -> CheckResult:
    """A sample PASS CheckResult."""
    return CheckResult(
        category="Firewall",
        check_name="Windows Firewall — Domain Profile",
        status=Status.PASS,
        severity=Severity.HIGH,
        description="Firewall domain profile is enabled.",
        details="Enabled: True",
        remediation="",
    )


@pytest.fixture()
def fail_result() -> CheckResult:
    """A sample FAIL CheckResult with critical severity."""
    return CheckResult(
        category="Antivirus",
        check_name="Windows Defender Status",
        status=Status.FAIL,
        severity=Severity.CRITICAL,
        description="Windows Defender real-time protection is disabled.",
        details="RealTimeProtectionEnabled: False",
        remediation="Enable Defender via Settings > Windows Security > Virus & threat protection.",
    )


@pytest.fixture()
def warn_result() -> CheckResult:
    """A sample WARN CheckResult."""
    return CheckResult(
        category="RDP",
        check_name="RDP Enabled",
        status=Status.WARN,
        severity=Severity.HIGH,
        description="Remote Desktop is enabled.",
        details="fDenyTSConnections: 0",
        remediation="Disable RDP if not required, or restrict access via firewall.",
    )


@pytest.fixture()
def sample_report(pass_result, fail_result, warn_result) -> AuditReport:
    """An AuditReport with one PASS, one FAIL, and one WARN result."""
    return AuditReport(
        hostname="TEST-PC",
        os_version="10.0.22621",
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration=1.5,
        results=[pass_result, fail_result, warn_result],
        score=70,
    )
