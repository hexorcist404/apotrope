"""Check: Windows Firewall — per-profile enabled status and default inbound action."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Firewall"

_PS_PROFILES = (
    "Get-NetFirewallProfile "
    "| Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction "
    "| ConvertTo-Json -Compress"
)

# PS 5.1 serialises the Action enum as integers; PS 7+ as strings.
# NetSecurity.Action: NotConfigured=0, Allow=2, Block=4
_ACTION_INT_MAP: dict[int, str] = {0: "NotConfigured", 2: "Allow", 4: "Block"}


def _parse_action(val: object) -> str:
    """Normalise a PS firewall action value to a plain string.

    Args:
        val: Integer (PS 5.1) or string (PS 7+) representation of the action.

    Returns:
        One of ``"Block"``, ``"Allow"``, ``"NotConfigured"``, or ``"Unknown(<val>)"``.
    """
    if val is None:
        return "NotConfigured"
    if isinstance(val, str):
        return val
    try:
        return _ACTION_INT_MAP.get(int(val), f"Unknown({val})")  # type: ignore[arg-type,call-overload]
    except (TypeError, ValueError):
        return f"Unknown({val})"


def run() -> list[CheckResult]:
    """Return Windows Firewall profile checks.

    Produces two results per profile: one for the enabled/disabled state and
    one for the default inbound action.

    Returns:
        list[CheckResult]: Six results for a standard three-profile system.
    """
    try:
        data = run_powershell_json(_PS_PROFILES)
    except ApotropeError as exc:
        return [CheckResult(
            category=CATEGORY,
            check_name="Windows Firewall",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Checks Windows Firewall profile status.",
            details=str(exc),
            remediation="Ensure Get-NetFirewallProfile is available. Run with --log-level DEBUG.",
        )]

    profiles = data if isinstance(data, list) else [data]
    results: list[CheckResult] = []

    for profile in profiles:
        name = str(profile.get("Name", "Unknown"))
        enabled = bool(profile.get("Enabled", False))
        inbound = _parse_action(profile.get("DefaultInboundAction"))
        outbound = _parse_action(profile.get("DefaultOutboundAction"))

        # --- Check 1: profile enabled ---
        results.append(CheckResult(
            category=CATEGORY,
            check_name=f"Firewall — {name} Profile Enabled",
            status=Status.PASS if enabled else Status.FAIL,
            severity=Severity.HIGH,
            description=f"Checks whether the Windows Firewall {name} profile is enabled.",
            details=f"Profile: {name} | Enabled: {enabled}",
            remediation=(
                "" if enabled else
                f"Enable the {name} firewall profile: "
                f"Set-NetFirewallProfile -Profile {name} -Enabled True"
            ),
        ))

        # --- Check 2: default inbound action ---
        # "NotConfigured" inherits from Group Policy; the Windows built-in default
        # is Block, so it is NOT treated as a finding.  Only explicit "Allow" warns.
        inbound_lower = inbound.lower()
        inbound_explicit_allow = inbound_lower == "allow"
        inbound_status = Status.WARN if inbound_explicit_allow else Status.PASS
        results.append(CheckResult(
            category=CATEGORY,
            check_name=f"Firewall — {name} Default Inbound Action",
            status=inbound_status,
            severity=Severity.MEDIUM,
            description=(
                f"Checks that the {name} profile does not explicitly allow all "
                "unsolicited inbound connections by default."
            ),
            details=(
                f"Profile: {name} | "
                f"DefaultInboundAction: {inbound} | "
                f"DefaultOutboundAction: {outbound}"
            ),
            remediation=(
                "" if not inbound_explicit_allow else
                f"Set default inbound to Block for the {name} profile: "
                f"Set-NetFirewallProfile -Profile {name} -DefaultInboundAction Block"
            ),
        ))

    return results
