"""Check: Remote Desktop Protocol — enabled status, NLA, and port configuration."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Remote Access"

_RDP_DEFAULT_PORT = 3389

# Fetch all RDP-relevant registry values in one PS call.
_PS_RDP = (
    "$ts  = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'; "
    "$rdp = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'; "
    "@{ "
    "fDenyTSConnections  = (Get-ItemProperty $ts  -ErrorAction SilentlyContinue).fDenyTSConnections; "
    "UserAuthentication  = (Get-ItemProperty $rdp -ErrorAction SilentlyContinue).UserAuthentication; "
    "PortNumber          = (Get-ItemProperty $rdp -ErrorAction SilentlyContinue).PortNumber "
    "} | ConvertTo-Json -Compress"
)


def run() -> list[CheckResult]:
    """Return Remote Desktop Protocol security checks.

    Returns:
        list[CheckResult]: Results for RDP enablement, NLA, and port.
        NLA and port checks are only included when RDP is enabled.
    """
    try:
        data = run_powershell_json(_PS_RDP)
    except ApotropeError as exc:
        return [CheckResult(
            category=CATEGORY,
            check_name="RDP Configuration",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Checks Remote Desktop Protocol configuration.",
            details=str(exc),
            remediation="Run with --log-level DEBUG for more detail.",
        )]

    if isinstance(data, list):
        data = data[0] if data else {}

    rdp_check, rdp_enabled = _check_rdp_enabled(data)
    results = list(rdp_check)

    if rdp_enabled:
        results.extend(_check_rdp_nla(data))
        results.extend(_check_rdp_port(data))

    return results


def _check_rdp_enabled(data: dict) -> tuple[list[CheckResult], bool]:
    """Return (results, rdp_is_enabled) for the RDP enabled/disabled state.

    fDenyTSConnections = 0 → RDP enabled
    fDenyTSConnections = 1 (or absent) → RDP disabled
    """
    raw = data.get("fDenyTSConnections")

    if raw is None:
        # Key absent typically means RDP is disabled (default on desktop SKUs)
        return ([CheckResult(
            category=CATEGORY,
            check_name="RDP Enabled",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Checks whether Remote Desktop is enabled.",
            details="RDP is disabled (fDenyTSConnections key not found — default disabled state).",
            remediation="",
        )], False)

    rdp_enabled = int(raw) == 0   # 0 = connections allowed

    if rdp_enabled:
        result = CheckResult(
            category=CATEGORY,
            check_name="RDP Enabled",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether Remote Desktop is enabled.",
            details=(
                "Remote Desktop is enabled (fDenyTSConnections = 0). "
                "Ensure access is restricted by firewall and NLA is required."
            ),
            remediation=(
                "If RDP is not required, disable it: "
                "Set-ItemProperty -Path "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name fDenyTSConnections -Value 1. "
                "If RDP is required, restrict access via Windows Firewall."
            ),
        )
    else:
        result = CheckResult(
            category=CATEGORY,
            check_name="RDP Enabled",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Checks whether Remote Desktop is enabled.",
            details="Remote Desktop is disabled (fDenyTSConnections = 1).",
            remediation="",
        )

    return ([result], rdp_enabled)


def _check_rdp_nla(data: dict) -> list[CheckResult]:
    """Check whether Network Level Authentication is required for RDP."""
    raw = data.get("UserAuthentication")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="RDP Network Level Authentication",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether NLA is required for RDP connections.",
            details="Could not determine NLA setting (UserAuthentication key not found).",
            remediation=(
                "Enable NLA: "
                "Set-ItemProperty -Path "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name UserAuthentication -Value 1"
            ),
        )]

    nla_required = int(raw) == 1
    return [CheckResult(
        category=CATEGORY,
        check_name="RDP Network Level Authentication",
        status=Status.PASS if nla_required else Status.FAIL,
        severity=Severity.HIGH,
        description="Checks whether NLA is required for RDP connections.",
        details=(
            "Network Level Authentication (NLA) is required for RDP."
            if nla_required else
            "Network Level Authentication (NLA) is NOT required. "
            "Unauthenticated users can reach the Windows login screen, "
            "enabling credential brute-force attacks."
        ),
        remediation=(
            "" if nla_required else
            "Enable NLA: "
            "Set-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "-Name UserAuthentication -Value 1. "
            "Or: System Properties → Remote → "
            "'Allow connections only from computers running Remote Desktop with NLA'"
        ),
    )]


def _check_rdp_port(data: dict) -> list[CheckResult]:
    """Report the RDP listening port (informational)."""
    raw = data.get("PortNumber")
    port = int(raw) if raw is not None else _RDP_DEFAULT_PORT
    non_standard = port != _RDP_DEFAULT_PORT

    return [CheckResult(
        category=CATEGORY,
        check_name="RDP Port",
        status=Status.INFO,
        severity=Severity.INFO,
        description=f"Reports the RDP listening port (default: {_RDP_DEFAULT_PORT}).",
        details=(
            f"RDP is listening on port {port}."
            + (" (non-standard port)" if non_standard else " (default port 3389)")
        ),
        remediation="",
    )]
