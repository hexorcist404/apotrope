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


# Remediation commands, hoisted to module level so the policy-aware
# `A if policy_managed else B` conditionals below keep the IfExp at the *root*
# of the command= value. tools/command_audit.py expands both arms of a root
# IfExp but collapses a concatenation or f-string wrapper to the literal token
# "{expr}", which would drop these commands from the lint inventory and then
# fail tools/verify_commands.py on the Windows job.
#
# The firewall selector is the locale-neutral group ID, not -DisplayGroup:
# DisplayGroup is the resolved MUI string ("Remotedesktop" on de-DE), so it
# matches nothing on non-English Windows and the cmdlet no-ops with a
# non-terminating error.
_CMD_DISABLE_RDP = (
    "# Disable Remote Desktop (skip this if RDP is intentionally in use)\n"
    "Set-ItemProperty -Path "
    "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
    "-Name 'fDenyTSConnections' -Value 1\n"
    "Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'"
)

_CMD_REQUIRE_NLA = (
    "Set-ItemProperty -Path "
    "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
    "-Name 'UserAuthentication' -Value 1"
)

# When Group Policy owns the value, a local registry write is not merely
# ineffective — the policy is re-applied on every refresh (~90 min by default),
# and during the rewrite window the local value briefly governs, which is the
# documented cause of periodic RDP session drops (KB2083411). So the
# policy-managed branches emit no command at all and point at the GPO instead.
_GPO_ROOT = (
    "Computer Configuration > Administrative Templates > Windows Components > "
    "Remote Desktop Services > Remote Desktop Session Host"
)
_REMEDIATION_RDP_ENABLED_BY_POLICY = (
    "Remote Desktop is enabled by Group Policy; editing the local registry value "
    "has no effect while the policy is set (and is reverted on every refresh). "
    "Change it in the winning GPO: " + _GPO_ROOT + " > Connections > "
    "'Allow users to connect remotely by using Remote Desktop Services' -> Disabled. "
    "Run 'gpresult /h rsop.html' to identify the winning GPO."
)
_REMEDIATION_NLA_BY_POLICY = (
    "Network Level Authentication is controlled by Group Policy; editing the local "
    "registry value has no effect while the policy is set. Change it in the winning "
    "GPO: " + _GPO_ROOT + " > Security > 'Require user authentication for remote "
    "connections by using Network Level Authentication' -> Enabled. "
    "Run 'gpresult /h rsop.html' to identify the winning GPO."
)


def _effective_value(
    data: dict, policy_name: str, local_name: str
) -> tuple[object | None, bool]:
    """Return ``(winning_value, policy_managed)`` for a policy-backed setting.

    The Group Policy value under ``...\\Policies\\...`` overrides the local
    Terminal Server value, so it wins when present. The second element records
    *which source won*, because that decides whether a local ``Set-ItemProperty``
    remediation would actually take effect — the caller must not have to
    re-derive it after the winner has been collapsed into one variable.
    """
    policy_raw = data.get(policy_name)
    if policy_raw is not None:
        return policy_raw, True
    return data.get(local_name), False


def _check_rdp_enabled(data: dict) -> tuple[list[CheckResult], bool]:
    """Return (results, rdp_is_enabled) for the RDP enabled/disabled state.

    fDenyTSConnections = 0 → RDP enabled
    fDenyTSConnections = 1 (or absent) → RDP disabled
    """
    effective, policy_managed = _effective_value(
        data, "PolicyDenyTSConnections", "fDenyTSConnections"
    )

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
                "Remote Desktop is enabled by Group Policy (fDenyTSConnections = 0)."
                if policy_managed else
                "Remote Desktop is enabled (fDenyTSConnections = 0). "
                "Ensure access is restricted by firewall and NLA is required."
            ),
            remediation=(
                _REMEDIATION_RDP_ENABLED_BY_POLICY
                if policy_managed else
                "If RDP isn't needed, disable it. If it is required, keep NLA required "
                "and restrict access by firewall scope or a VPN / RD gateway."
            ),
            # Empty when policy-managed: handing the operator a paste that cannot
            # work is worse than handing them none. Empty command= is already a
            # first-class state here (see the NLA PASS branch below).
            command=("" if policy_managed else _CMD_DISABLE_RDP),
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
    raw, policy_managed = _effective_value(
        data, "PolicyUserAuthentication", "UserAuthentication"
    )

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="RDP Network Level Authentication",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether NLA is required for RDP connections.",
            details="Could not determine NLA setting (UserAuthentication key not found).",
            remediation="Require Network Level Authentication for RDP.",
            # Unconditional: this branch is reached only when *neither* source was
            # readable, so policy_managed is False by construction.
            command=_CMD_REQUIRE_NLA,
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
            _REMEDIATION_NLA_BY_POLICY if policy_managed else
            "Require Network Level Authentication for RDP."
        ),
        # No local command when the policy owns the value — it would be reverted
        # at the next refresh. See _REMEDIATION_NLA_BY_POLICY.
        command=(
            "" if (nla_required or policy_managed) else _CMD_REQUIRE_NLA
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
