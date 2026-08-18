"""Check: Running services — risky service detection and unquoted path vulnerability."""

from __future__ import annotations

import logging
from typing import NamedTuple

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


class RiskyService(NamedTuple):
    """The finding a known-risky service produces when it is found running."""

    status: Status
    severity: Severity
    details: str
    remediation: str
    command: str


# The keyword arguments below are load-bearing, not house style.
# tools/command_audit.py collects every `command=` keyword on any call, so
# naming the fields is what puts these four commands into the lint inventory and
# in front of tools/verify_commands.py's PowerShell parser. As a positional
# tuple they were invisible to both: services.py contributed exactly one command
# to a 44-command inventory, and it was the unquoted-ImagePath block.
_RISKY: dict[str, RiskyService] = {
    "RemoteRegistry": RiskyService(
        status=Status.WARN,
        severity=Severity.HIGH,
        details="Remote Registry service is running — allows remote modification of the registry.",
        remediation="Stop and disable the Remote Registry service.",
        command="Stop-Service -Name 'RemoteRegistry' -Force\n"
                "Set-Service -Name 'RemoteRegistry' -StartupType Disabled",
    ),
    "TlntSvr": RiskyService(
        status=Status.FAIL,
        severity=Severity.CRITICAL,
        details="Telnet Server is running — all traffic (including credentials) is sent in cleartext.",
        remediation="Stop and disable the Telnet Server service immediately.",
        command="Stop-Service -Name 'TlntSvr' -Force\n"
                "Set-Service -Name 'TlntSvr' -StartupType Disabled",
    ),
    "Telnet": RiskyService(
        status=Status.FAIL,
        severity=Severity.CRITICAL,
        details="Telnet service is running — cleartext credential exposure.",
        remediation="Stop and disable the Telnet service immediately.",
        command="Stop-Service -Name 'Telnet' -Force\n"
                "Set-Service -Name 'Telnet' -StartupType Disabled",
    ),
    "SNMP": RiskyService(
        status=Status.WARN,
        severity=Severity.MEDIUM,
        details="SNMP service is running. SNMPv1/v2 uses weak community-string authentication.",
        remediation="Disable SNMP if it is not required; if it is, restrict access and use SNMPv3.",
        command="Stop-Service -Name 'SNMP' -Force\n"
                "Set-Service -Name 'SNMP' -StartupType Disabled",
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
    for svc_name, risky in _RISKY.items():
        if svc_name.lower() in running_names:
            display = running_names[svc_name.lower()]
            results.append(CheckResult(
                category=CATEGORY,
                check_name=f"Risky Service — {display}",
                status=risky.status,
                severity=risky.severity,
                description=f"Checks whether the {display} service is running.",
                details=risky.details,
                remediation=risky.remediation,
                command=risky.command,
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
    detail_lines = "; ".join(f"{n}: {p}" for n, p in zip(names, paths, strict=True))

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
            "Wrap the executable path of each affected service in double quotes "
            "(preserving any arguments) so Windows resolves the intended binary."
        ),
        command=(
            "# Set $svc to the affected service. This PRINTS the proposed value and\n"
            "# writes nothing: an unquoted ImagePath is ambiguous by definition, so\n"
            "# which token is the real executable cannot be decided from the string\n"
            "# alone. Check the suggestion against the service's actual binary, then\n"
            "# uncomment the write. These are routinely boot-start services; a wrong\n"
            "# value here is a machine that does not boot.\n"
            "$svc = 'ExampleService'\n"
            "$key = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$svc\"\n"
            "# DoNotExpandEnvironmentNames, not Get-ItemProperty: the latter EXPANDS a\n"
            "# REG_EXPAND_SZ on read, so %SystemRoot%\\... comes back as C:\\WINDOWS\\...\n"
            "# and writing it back bakes the resolved path in permanently.\n"
            "$img = (Get-Item -LiteralPath $key).GetValue("
            "'ImagePath', $null, 'DoNotExpandEnvironmentNames')\n"
            "Write-Host \"current: $img\"\n"
            "if ($img.TrimStart() -notmatch '^\"' -and "
            "$img -match '^(?<exe>.*?\\.exe)(?<args>.*)$') {\n"
            "    $fixed = '\"' + $matches['exe'].Trim() + '\"' + $matches['args']\n"
            "    Write-Host \"proposed: $fixed\"\n"
            "    # Back the original up before changing it, then apply:\n"
            "    # New-ItemProperty -Path $key -Name ImagePath_ApotropeBackup "
            "-PropertyType ExpandString -Value $img -Force | Out-Null\n"
            "    # New-ItemProperty -Path $key -Name ImagePath "
            "-PropertyType ExpandString -Value $fixed -Force | Out-Null\n"
            "}"
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
