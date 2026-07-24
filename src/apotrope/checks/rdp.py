"""Check: Remote Desktop Protocol — enabled status, NLA, and port configuration."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Remote Access"

_RDP_DEFAULT_PORT = 3389

# Fetch all RDP-relevant registry values in one PS call. The Group Policy keys
# under ...\Policies\... override the Terminal Server values, so they are read too.
_PS_RDP = (
    "$ts  = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'; "
    "$rdp = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'; "
    "$pol = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'; "
    "@{ "
    "fDenyTSConnections       = (Get-ItemProperty $ts  -ErrorAction SilentlyContinue).fDenyTSConnections; "
    "UserAuthentication       = (Get-ItemProperty $rdp -ErrorAction SilentlyContinue).UserAuthentication; "
    "PortNumber               = (Get-ItemProperty $rdp -ErrorAction SilentlyContinue).PortNumber; "
    "PolicyDenyTSConnections  = (Get-ItemProperty $pol -ErrorAction SilentlyContinue).fDenyTSConnections; "
    "PolicyUserAuthentication = (Get-ItemProperty $pol -ErrorAction SilentlyContinue).UserAuthentication "
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
    # Group Policy overrides the Terminal Server value, so it wins when present.
    policy_raw = data.get("PolicyDenyTSConnections")
    system_raw = data.get("fDenyTSConnections")
    effective = policy_raw if policy_raw is not None else system_raw

    if effective is None:
        # Neither value was readable. Do NOT assume RDP is disabled — a fail-open
        # PASS here would hide an exposed RDP service on a machine we couldn't read.
        return ([CheckResult(
            category=CATEGORY,
            check_name="RDP Enabled",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether Remote Desktop is enabled.",
            details=(
                "Could not determine RDP state (neither the Terminal Server value nor "
                "the policy override was readable). Not assuming RDP is disabled."
            ),
            remediation="Verify the RDP state and disable it if it is not required.",
            command=(
                "# Disable Remote Desktop if it is not required:\n"
                "Set-ItemProperty -Path "
                "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name 'fDenyTSConnections' -Value 1"
            ),
        )], False)

    rdp_enabled = int(effective) == 0   # 0 = connections allowed

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
                "If RDP isn't needed, disable it. If it is required, keep NLA required "
                "and restrict access by firewall scope or a VPN / RD gateway."
            ),
            command=(
                "# Disable Remote Desktop (skip this if RDP is intentionally in use)\n"
                "Set-ItemProperty -Path "
                "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name 'fDenyTSConnections' -Value 1\n"
                "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'"
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
    # Policy value overrides the per-listener value when present.
    raw = data.get("PolicyUserAuthentication")
    if raw is None:
        raw = data.get("UserAuthentication")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="RDP Network Level Authentication",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether NLA is required for RDP connections.",
            details="Could not determine NLA setting (UserAuthentication key not found).",
            remediation="Require Network Level Authentication for RDP.",
            command=(
                "Set-ItemProperty -Path "
                "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name 'UserAuthentication' -Value 1"
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
            "Require Network Level Authentication for RDP."
        ),
        command=(
            "" if nla_required else
            "Set-ItemProperty -Path "
            "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "-Name 'UserAuthentication' -Value 1"
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
