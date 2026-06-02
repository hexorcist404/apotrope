"""Check: Running services — risky service detection and unquoted path vulnerability."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Services"

# Fetch name + display name for all running services.
_PS_RUNNING = (
    "Get-Service -ErrorAction SilentlyContinue "
    "| Where-Object { $_.Status -eq 'Running' } "
    "| Select-Object Name, DisplayName, @{N='Status';E={$_.Status.ToString()}} "
    "| ConvertTo-Json -Compress"
)

# Unquoted service paths: not quoted, not a Windows system path, contain a space
# before the executable extension — classic privilege-escalation vector.
_PS_UNQUOTED = (
    "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue "
    "| Where-Object { "
    "    $_.PathName -and "
    "    $_.PathName.Trim() -notmatch '^\"' -and "
    "    $_.PathName.Trim() -notmatch '^[A-Za-z]:\\\\Windows\\\\' -and "
    "    $_.PathName.Trim() -match '^[A-Za-z]:\\\\.+ .+\\.(exe|dll)' "
    "} "
    "| Select-Object Name, DisplayName, PathName "
    "| ConvertTo-Json -Compress"
)

# Known-risky service names → (status, severity, details, remediation)
_RISKY: dict[str, tuple[Status, Severity, str, str]] = {
    "RemoteRegistry": (
        Status.WARN,
        Severity.HIGH,
        "Remote Registry service is running — allows remote modification of the registry.",
        "Stop and disable Remote Registry: "
        "Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled",
    ),
    "TlntSvr": (
        Status.FAIL,
        Severity.CRITICAL,
        "Telnet Server is running — all traffic (including credentials) is sent in cleartext.",
        "Disable Telnet Server immediately: "
        "Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled",
    ),
    "Telnet": (
        Status.FAIL,
        Severity.CRITICAL,
        "Telnet service is running — cleartext credential exposure.",
        "Disable Telnet: Stop-Service Telnet; Set-Service Telnet -StartupType Disabled",
    ),
    "SNMP": (
        Status.WARN,
        Severity.MEDIUM,
        "SNMP service is running. SNMPv1/v2 uses weak community-string authentication.",
        "Disable SNMP if not required: "
        "Stop-Service SNMP; Set-Service SNMP -StartupType Disabled. "
        "If required, restrict access and use SNMPv3.",
    ),
}


def run() -> list[CheckResult]:
    """Return service security checks.

    Returns:
        list[CheckResult]: Results for risky running services and unquoted service paths.
    """
    results: list[CheckResult] = []
    results.extend(_check_risky_services())
    results.extend(_check_unquoted_paths())
    return results


def _check_risky_services() -> list[CheckResult]:
    """Flag known-dangerous services that are currently running."""
    try:
        data = run_powershell_json(_PS_RUNNING)
    except ApotropeError as exc:
        return [_error("Risky Services", str(exc))]

    services = data if isinstance(data, list) else ([data] if data else [])
    running_names = {str(s.get("Name", "")).lower(): str(s.get("Name", "")) for s in services}

    results: list[CheckResult] = []
    for svc_name, (status, severity, details, remediation) in _RISKY.items():
        if svc_name.lower() in running_names:
            display = running_names[svc_name.lower()]
            results.append(CheckResult(
                category=CATEGORY,
                check_name=f"Risky Service — {display}",
                status=status,
                severity=severity,
                description=f"Checks whether the {display} service is running.",
                details=details,
                remediation=remediation,
            ))

    if not results:
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Risky Services",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="Checks for known-risky services (Remote Registry, Telnet, SNMP).",
            details="No known-risky services are running.",
            remediation="",
        ))

    return results


def _check_unquoted_paths() -> list[CheckResult]:
    """Detect services with unquoted executable paths containing spaces."""
    try:
        data = run_powershell_json(_PS_UNQUOTED)
    except ApotropeError as exc:
        if "empty output" in str(exc):
            data = []
        else:
            return [_error("Unquoted Service Paths", str(exc))]

    items = data if isinstance(data, list) else ([data] if data else [])

    if not items:
        return [CheckResult(
            category=CATEGORY,
            check_name="Unquoted Service Paths",
            status=Status.PASS,
            severity=Severity.HIGH,
            description=(
                "Checks for services whose executable path contains spaces but is not quoted "
                "(privilege-escalation vector)."
            ),
            details="No services with unquoted paths containing spaces found.",
            remediation="",
        )]

    names = [str(i.get("Name") or "Unknown") for i in items]
    paths = [str(i.get("PathName") or "") for i in items]
    detail_lines = "; ".join(f"{n}: {p}" for n, p in zip(names, paths))

    return [CheckResult(
        category=CATEGORY,
        check_name="Unquoted Service Paths",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description=(
            "Checks for services whose executable path contains spaces but is not quoted "
            "(privilege-escalation vector)."
        ),
        details=(
            f"{len(items)} service(s) with unquoted paths: {detail_lines}. "
            "An attacker with write access to a parent directory could place a malicious "
            "executable that Windows resolves before the intended binary."
        ),
        remediation=(
            "Quote the PathName of each affected service in the registry: "
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath. "
            "Wrap the executable path in double quotes, preserving any arguments."
        ),
    )]


def _error(check_name: str, details: str) -> CheckResult:
    return CheckResult(
        category=CATEGORY,
        check_name=check_name,
        status=Status.ERROR,
        severity=Severity.INFO,
        description="An error occurred while running this check.",
        details=details,
        remediation="Run with --log-level DEBUG for more detail.",
    )
