"""Check: User Account Control (UAC) configuration."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Access Control"

_REG_KEY = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

# Read all UAC-relevant values in a single PS call
_PS_UAC = (
    "$k = Get-ItemProperty -LiteralPath "
    f"'{_REG_KEY}' "
    "-ErrorAction SilentlyContinue; "
    "@{ "
    "EnableLUA                    = $k.EnableLUA; "
    "ConsentPromptBehaviorAdmin   = $k.ConsentPromptBehaviorAdmin; "
    "ConsentPromptBehaviorUser    = $k.ConsentPromptBehaviorUser; "
    "PromptOnSecureDesktop        = $k.PromptOnSecureDesktop; "
    "EnableVirtualization         = $k.EnableVirtualization "
    "} | ConvertTo-Json -Compress"
)

# ConsentPromptBehaviorAdmin values
_ADMIN_BEHAVIOR: dict[int, str] = {
    0: "Elevate without prompting (silently allows elevation)",
    1: "Prompt for credentials on secure desktop",
    2: "Prompt for consent on secure desktop",
    3: "Prompt for credentials (not on secure desktop)",
    4: "Prompt for consent (not on secure desktop)",
    5: "Prompt for consent for non-Windows binaries (Windows default)",
}

# ConsentPromptBehaviorUser values
_USER_BEHAVIOR: dict[int, str] = {
    0: "Automatically deny elevation requests",
    1: "Prompt for credentials on secure desktop",
    3: "Prompt for credentials (default)",
}


def run() -> list[CheckResult]:
    """Return UAC configuration checks.

    Returns:
        list[CheckResult]: Results for UAC enablement, admin consent behavior,
        secure desktop enforcement, and user elevation behaviour.
    """
    try:
        data = run_powershell_json(_PS_UAC)
    except ApotropeError as exc:
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Configuration",
            status=Status.ERROR,
            severity=Severity.CRITICAL,
            description="Checks User Account Control (UAC) configuration.",
            details=str(exc),
            remediation="Run with --log-level DEBUG for more detail.",
        )]

    if isinstance(data, list):
        data = data[0] if data else {}

    results: list[CheckResult] = []
    results.extend(_check_uac_enabled(data))
    results.extend(_check_admin_behavior(data))
    results.extend(_check_secure_desktop(data))
    results.extend(_check_user_behavior(data))
    return results


def _check_uac_enabled(data: dict) -> list[CheckResult]:
    """Check whether UAC (EnableLUA) is enabled."""
    raw = data.get("EnableLUA")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Enabled",
            status=Status.WARN,
            severity=Severity.CRITICAL,
            description="Checks whether User Account Control (UAC) is enabled.",
            details="Could not read UAC EnableLUA registry value.",
            remediation="Verify UAC status manually, then re-enable User Account Control if it is off.",
            command=(
                f"Get-ItemProperty '{_REG_KEY}' | Select EnableLUA\n"
                f"Set-ItemProperty -Path '{_REG_KEY}' -Name EnableLUA -Value 1"
            ),
        )]

    enabled = int(raw) == 1
    return [CheckResult(
        category=CATEGORY,
        check_name="UAC Enabled",
        status=Status.PASS if enabled else Status.FAIL,
        severity=Severity.CRITICAL,
        description="Checks whether User Account Control (UAC) is enabled.",
        details=f"UAC (EnableLUA) is {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if enabled else
            "Re-enable User Account Control, then reboot for it to take effect."
        ),
        command=(
            "" if enabled else
            f"Set-ItemProperty -Path '{_REG_KEY}' -Name 'EnableLUA' -Value 1\n"
            # Reboot required for the change to take effect — kept as a manual
            # step so pasting the block cannot restart the machine unattended.
            "# Reboot required for UAC to take effect:\n# Restart-Computer"
        ),
    )]


def _check_admin_behavior(data: dict) -> list[CheckResult]:
    """Check the UAC consent prompt behavior for administrators."""
    raw = data.get("ConsentPromptBehaviorAdmin")

    if raw is None:
        # If the key is absent, Windows uses the built-in default (5)
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Admin Consent Behavior",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks the UAC consent prompt behavior for administrator accounts.",
            details="ConsentPromptBehaviorAdmin not set; Windows default (5) applies.",
            remediation="",
        )]

    level = int(raw)
    description_text = _ADMIN_BEHAVIOR.get(level, f"Unknown value ({level})")

    # Level 0 = silent elevation — highest risk
    if level == 0:
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Admin Consent Behavior",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks the UAC consent prompt behavior for administrator accounts.",
            details=(
                f"ConsentPromptBehaviorAdmin = {level}: {description_text}. "
                "Administrators are elevated silently without any confirmation prompt."
            ),
            remediation=(
                "Require administrators to confirm elevation by prompting for consent "
                "on the secure desktop instead of elevating silently."
            ),
            command=(
                f"Set-ItemProperty -Path '{_REG_KEY}' "
                "-Name ConsentPromptBehaviorAdmin -Value 2"
            ),
        )]

    if level not in _ADMIN_BEHAVIOR:
        # Only known, explicitly-safe values (1–5, all of which prompt) PASS.
        # An unrecognized value is not proof of a secure config — report INFO
        # rather than silently passing whatever is set.
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Admin Consent Behavior",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks the UAC consent prompt behavior for administrator accounts.",
            details=(
                f"ConsentPromptBehaviorAdmin = {level}: unrecognized value. "
                "Verify this is an intended UAC configuration."
            ),
            remediation="",
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="UAC Admin Consent Behavior",
        status=Status.PASS,
        severity=Severity.HIGH,
        description="Checks the UAC consent prompt behavior for administrator accounts.",
        details=f"ConsentPromptBehaviorAdmin = {level}: {description_text}.",
        remediation="",
    )]


def _check_secure_desktop(data: dict) -> list[CheckResult]:
    """Check whether UAC prompts are shown on the secure desktop."""
    raw = data.get("PromptOnSecureDesktop")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Secure Desktop",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether UAC prompts appear on the isolated secure desktop.",
            details="PromptOnSecureDesktop not set; Windows default (enabled) applies.",
            remediation="",
        )]

    on_secure = int(raw) == 1
    return [CheckResult(
        category=CATEGORY,
        check_name="UAC Secure Desktop",
        status=Status.PASS if on_secure else Status.WARN,
        severity=Severity.MEDIUM,
        description="Checks whether UAC prompts appear on the isolated secure desktop.",
        details=(
            "UAC prompts are displayed on the secure desktop (isolated from user input)."
            if on_secure else
            "UAC prompts are NOT on the secure desktop. "
            "Malware running as the user may be able to interact with or spoof the UAC dialog."
        ),
        remediation=(
            "" if on_secure else
            "Show UAC prompts on the isolated secure desktop."
        ),
        command=(
            "" if on_secure else
            f"Set-ItemProperty -Path '{_REG_KEY}' -Name 'PromptOnSecureDesktop' -Value 1"
        ),
    )]


def _check_user_behavior(data: dict) -> list[CheckResult]:
    """Check the UAC consent prompt behavior for standard users."""
    raw = data.get("ConsentPromptBehaviorUser")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="UAC Standard User Behavior",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Checks the UAC consent prompt behavior for standard user accounts.",
            details="ConsentPromptBehaviorUser not set; Windows default (3) applies.",
            remediation="",
        )]

    level = int(raw)
    description_text = _USER_BEHAVIOR.get(level, f"Unknown value ({level})")
    return [CheckResult(
        category=CATEGORY,
        check_name="UAC Standard User Behavior",
        status=Status.INFO,
        severity=Severity.LOW,
        description="Checks the UAC consent prompt behavior for standard user accounts.",
        details=f"ConsentPromptBehaviorUser = {level}: {description_text}.",
        remediation="",
    )]
