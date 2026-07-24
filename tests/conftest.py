"""Shared pytest fixtures for Apotrope tests."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from apotrope.models import AuditReport, CheckResult, Severity, Status


@pytest.fixture(autouse=True)
def _reset_powershell_cache():
    """Clear the cached PowerShell resolution between tests.

    ``utils._ps_executable()`` memoises both outcomes. Without this, whichever
    test resolves first would decide the value every later test sees — an
    order-dependent failure that looks like flakiness.
    """
    from apotrope import utils
    utils._reset_ps_cache()
    yield
    utils._reset_ps_cache()


@pytest.fixture(autouse=True)
def _forbid_unmocked_subprocess(request):
    """Fail loudly if any test reaches the real ``powershell.exe``.

    Tests must mock the ``utils`` helpers (``run_powershell`` etc.) so the suite
    is hermetic and OS-independent. A forgotten patch previously reached real
    PowerShell on Windows (and degraded to ``[]`` on Linux, hiding the problem);
    this guard turns that into an immediate error. A test that genuinely needs
    the boundary can opt out with ``@pytest.mark.allow_subprocess``.
    """
    if request.node.get_closest_marker("allow_subprocess"):
        yield
        return

    import apotrope.utils as u

    def _boom(*args, **kwargs):
        raise RuntimeError(
            "unmocked subprocess.run reached the real boundary — patch "
            "run_powershell / run_powershell_json / get_wmi_object instead"
        )

    # Explicit sentinel so a test can prove WHICH callable is installed.
    # unittest.mock's ``_mock_name`` is useless here — _boom is a plain
    # function, not a Mock, so it has no such attribute either and asserting on
    # it passes whether or not the guard is active. An identity check against
    # ``subprocess.run`` proves nothing either: apotrope.utils imports the very
    # same module object the test sees.
    _boom._apotrope_guard = True

    with patch.object(u.subprocess, "run", _boom):
        yield


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
