"""Check: Miscellaneous hardening — AutoPlay, WinRM, Spectre mitigations, audit policy, screen lock."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Hardening"

# ---------------------------------------------------------------------------
# PowerShell snippets
# ---------------------------------------------------------------------------

_AUTOPLAY_KEY = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
_PS_AUTOPLAY = (
    f"$v = (Get-ItemProperty -LiteralPath '{_AUTOPLAY_KEY}' "
    "-ErrorAction SilentlyContinue).NoDriveTypeAutoRun; "
    "if ($null -eq $v) { 'NOTSET' } else { [string]$v }"
)
# Create the policy key first: Set-ItemProperty -Force does NOT create a missing
# key, and the NOTSET finding fires precisely when that key is absent.
# `Set-ItemProperty -Force` cannot create a missing key, so the NOTSET branch
# genuinely needs a New-Item — but on the *registry* provider `New-Item -Force`
# REPLACES an existing key, deleting every value and subkey under it. This key is
# shared with unrelated Explorer policies (NoRecentDocsHistory, NoActiveDesktop,
# ForceActiveDesktopOn, ...), and the two other branches that emit this command
# are only reachable when a value was read back, i.e. when the key already
# exists. Unguarded, the paste would destroy those neighbouring policies.
#
# Kept as one module-level string so tools/command_audit.py still resolves it
# statically; a wrapper it cannot resolve collapses the command to "{expr}" and
# drops it from the lint inventory.
_CMD_AUTOPLAY_DISABLE = (
    f"if (-not (Test-Path '{_AUTOPLAY_KEY}')) "
    f"{{ New-Item -Path '{_AUTOPLAY_KEY}' -Force | Out-Null }}\n"
    f"Set-ItemProperty -Path '{_AUTOPLAY_KEY}' -Name NoDriveTypeAutoRun -Value 255 "
    "-Type DWord -Force"
)

# The five security-relevant audit subcategories Apotrope requires (order fixed
# for deterministic "missing" reporting).
_EXPECTED_AUDIT = (
    "Logon", "Account Lockout", "Logoff",
    "Credential Validation", "Sensitive Privilege Use",
)

# Machine-wide inactivity lock policy (applies even without a per-user screensaver).
_MACHINE_INACTIVITY_KEY = (
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
)

_PS_WINRM = "(Get-Service -Name WinRM -ErrorAction SilentlyContinue).Status"

_SPECTRE_KEY = (
    "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
)
_PS_SPECTRE = (
    f"$k = Get-ItemProperty -LiteralPath '{_SPECTRE_KEY}' -ErrorAction SilentlyContinue; "
    "@{ Override=$k.FeatureSettingsOverride; Mask=$k.FeatureSettingsOverrideMask } "
    "| ConvertTo-Json -Compress"
)

# auditpol CSV: filter to key subcategories we care about
_PS_AUDIT = (
    "try { "
    "auditpol /get /category:* /r "
    "| ConvertFrom-Csv "
    "| Where-Object { "
    "    $_.'Subcategory' -in @('Logon','Account Lockout','Logoff','Credential Validation','Sensitive Privilege Use') "
    "} "
    "| Select-Object Subcategory,'Inclusion Setting' "
    "| ConvertTo-Json -Compress "
    "} catch { '[]' }"
)

_SCREEN_KEY = "HKCU:\\Control Panel\\Desktop"
_PS_SCREEN = (
    f"$d = Get-ItemProperty -LiteralPath '{_SCREEN_KEY}' -ErrorAction SilentlyContinue; "
    f"$m = Get-ItemProperty -LiteralPath '{_MACHINE_INACTIVITY_KEY}' -ErrorAction SilentlyContinue; "
    "@{ "
    "Active=$d.ScreenSaveActive; "
    "Secure=$d.ScreenSaverIsSecure; "
    "Timeout=$d.ScreenSaveTimeOut; "
    "MachineInactivity=$m.InactivityTimeoutSecs "
    "} | ConvertTo-Json -Compress"
)

# Screen-lock threshold: warn if > 15 minutes (900 seconds)
_LOCK_WARN_SECS = 900


def run() -> list[CheckResult]:
    """Return miscellaneous hardening checks.

    Returns:
        list[CheckResult]: Results for AutoPlay, WinRM, Spectre mitigations,
        audit policy, and screen-lock timeout.
    """
    results: list[CheckResult] = []
    results.extend(_check_autoplay())
    results.extend(_check_winrm())
    results.extend(_check_spectre())
    results.extend(_check_audit_policy())
    results.extend(_check_screen_lock())
    return results


def _check_autoplay() -> list[CheckResult]:
    """Check whether AutoPlay/AutoRun is disabled for all drive types."""
    try:
        output = run_powershell(_PS_AUTOPLAY).strip()
    except ApotropeError as exc:
        return [_error("AutoPlay Disabled", str(exc))]

    # NoDriveTypeAutoRun = 255 (0xFF) disables AutoPlay for all drive types.
    # Common value 91 (0x5B) disables most but not network drives.
    if output == "NOTSET":
        return [CheckResult(
            category=CATEGORY,
            check_name="AutoPlay Disabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether AutoPlay is disabled for all drive types.",
            details=(
                "NoDriveTypeAutoRun policy is not set — AutoPlay is enabled by default. "
                "AutoPlay can be abused to auto-execute malicious content from USB drives."
            ),
            remediation=(
                "Disable AutoPlay for all drive types so removable media cannot "
                "auto-execute content. This can also be set via Group Policy: Computer "
                "Configuration → Administrative Templates → Windows Components → AutoPlay "
                "Policies → Turn off AutoPlay → Enabled."
            ),
            command=_CMD_AUTOPLAY_DISABLE,
        )]

    try:
        val = int(output)
    except ValueError:
        val = -1

    # 0xFF = 255 disables all drive types; any non-zero typically disables most
    fully_disabled = val == 255
    partially_disabled = 0 < val < 255

    if fully_disabled:
        return [CheckResult(
            category=CATEGORY,
            check_name="AutoPlay Disabled",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="Checks whether AutoPlay is disabled for all drive types.",
            details=f"AutoPlay is fully disabled (NoDriveTypeAutoRun = {val}).",
            remediation="",
        )]

    if partially_disabled:
        return [CheckResult(
            category=CATEGORY,
            check_name="AutoPlay Disabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether AutoPlay is disabled for all drive types.",
            details=(
                f"AutoPlay is partially disabled (NoDriveTypeAutoRun = {val}). "
                "Some drive types may still trigger AutoPlay."
            ),
            remediation=(
                "Disable AutoPlay for all drive types so the remaining drive types "
                "can no longer auto-execute content."
            ),
            command=_CMD_AUTOPLAY_DISABLE,
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="AutoPlay Disabled",
        status=Status.WARN,
        severity=Severity.MEDIUM,
        description="Checks whether AutoPlay is disabled for all drive types.",
        details=f"AutoPlay may be enabled (NoDriveTypeAutoRun = {val}).",
        remediation="Disable AutoPlay for all drive types so removable media cannot auto-execute content.",
        command=_CMD_AUTOPLAY_DISABLE,
    )]


def _check_winrm() -> list[CheckResult]:
    """Check whether Windows Remote Management (WinRM) service is running."""
    try:
        output = run_powershell(_PS_WINRM).strip()
    except ApotropeError as exc:
        return [_error("WinRM Status", str(exc))]

    if not output:
        return [CheckResult(
            category=CATEGORY,
            check_name="WinRM Status",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether the Windows Remote Management (WinRM) service is running.",
            details="WinRM service not found.",
            remediation="",
        )]

    running = output.lower() == "running"

    return [CheckResult(
        category=CATEGORY,
        check_name="WinRM Status",
        status=Status.WARN if running else Status.PASS,
        severity=Severity.MEDIUM,
        description="Checks whether the Windows Remote Management (WinRM) service is running.",
        details=(
            "WinRM is running — PowerShell remoting is enabled. "
            "Ensure access is restricted by firewall rules and requires authentication."
            if running else
            "WinRM service is not running."
        ),
        remediation=(
            "" if not running else
            "If remote management is not required, stop and disable WinRM. If it is "
            "required, restrict access and disable Basic authentication."
        ),
        command=(
            "" if not running else
            "# If remote management is not required, stop and disable WinRM:\n"
            "Stop-Service WinRM\n"
            "Set-Service WinRM -StartupType Disabled\n"
            "# If WinRM is required, disable Basic authentication instead:\n"
            "Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $false"
        ),
    )]


def _check_spectre() -> list[CheckResult]:
    """Check for explicit disabling of speculative-execution mitigations."""
    try:
        data = run_powershell_json(_PS_SPECTRE)
    except ApotropeError as exc:
        return [_error("Speculative Execution Mitigations", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    override = data.get("Override")
    mask = data.get("Mask")

    if override is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="Speculative Execution Mitigations",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether Spectre/Meltdown mitigations have been explicitly disabled.",
            details=(
                "No FeatureSettingsOverride registry key found — "
                "Windows default mitigations apply (recommended)."
            ),
            remediation="",
        )]

    # FeatureSettingsOverride bit 0 disables Spectre V2, bit 1 disables Meltdown (KPTI).
    # Both set (value & 3 == 3) with mask = 3 means mitigations are explicitly disabled.
    try:
        override_int = int(override)
        mask_int = int(mask) if mask is not None else 0
    except (TypeError, ValueError):
        override_int, mask_int = -1, -1

    mitigations_disabled = (override_int & 3) == 3 and mask_int == 3

    if mitigations_disabled:
        return [CheckResult(
            category=CATEGORY,
            check_name="Speculative Execution Mitigations",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether Spectre/Meltdown mitigations have been explicitly disabled.",
            details=(
                f"Speculative execution mitigations appear disabled "
                f"(FeatureSettingsOverride={override_int}, Mask={mask_int}). "
                "This improves CPU performance but removes Spectre/Meltdown protections."
            ),
            remediation=(
                "Re-enable Spectre/Meltdown mitigations by removing the override "
                "registry keys that disable them."
            ),
            command=(
                f"Remove-ItemProperty -Path '{_SPECTRE_KEY}' "
                "-Name FeatureSettingsOverride,FeatureSettingsOverrideMask -ErrorAction SilentlyContinue"
            ),
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="Speculative Execution Mitigations",
        status=Status.INFO,
        severity=Severity.MEDIUM,
        description="Checks whether Spectre/Meltdown mitigations have been explicitly disabled.",
        details=(
            f"Speculative execution mitigation override present "
            f"(FeatureSettingsOverride={override_int}, Mask={mask_int}). "
            "Mitigations do not appear to be fully disabled."
        ),
        remediation="",
    )]


def _check_audit_policy() -> list[CheckResult]:
    """Check that key audit policy subcategories are logging Success and/or Failure."""
    try:
        data = run_powershell_json(_PS_AUDIT)
    except ApotropeError as exc:
        return [_error("Audit Policy", str(exc))]

    entries = data if isinstance(data, list) else ([data] if data else [])

    if not entries:
        # auditpol needs elevation (and its subcategory names are localized), so an
        # empty result on a default non-admin run does not mean auditing is off.
        # Report INFO (score-neutral), not a WARN that penalises a healthy machine.
        return [CheckResult(
            category=CATEGORY,
            check_name="Audit Policy",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Checks that key audit policy subcategories log Success/Failure events.",
            details=(
                "Could not retrieve audit policy (auditpol typically requires "
                "Administrator, or subcategory names are localized). Key events may "
                "not be assessed."
            ),
            remediation="Run Apotrope as Administrator to check audit policy.",
        )]

    # Build subcategory → inclusion setting map
    audit_map: dict[str, str] = {}
    for entry in entries:
        name = str(entry.get("Subcategory") or "").strip()
        setting = str(entry.get("Inclusion Setting") or "No Auditing").strip()
        if name:
            audit_map[name] = setting

    no_audit = [name for name in _EXPECTED_AUDIT if audit_map.get(name) == "No Auditing"]
    missing = [name for name in _EXPECTED_AUDIT if name not in audit_map]

    if no_audit or missing:
        problem = no_audit + [f"{name} (not reported)" for name in missing]
        return [CheckResult(
            category=CATEGORY,
            check_name="Audit Policy",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks that key audit policy subcategories log Success/Failure events.",
            details=(
                "Not all expected audit subcategories are confirmed logging: "
                f"{', '.join(problem)}. Security-relevant events may not be recorded."
            ),
            remediation=(
                "Enable audit logging for the listed subcategories so security-relevant "
                "events are recorded. This can also be configured via Group Policy "
                "(secpol.msc → Advanced Audit Policy Configuration)."
            ),
            command="auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="Audit Policy",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        description="Checks that key audit policy subcategories log Success/Failure events.",
        details=f"Auditing is configured for all expected subcategories: {', '.join(_EXPECTED_AUDIT)}.",
        remediation="",
    )]


def _check_screen_lock() -> list[CheckResult]:
    """Check that the screen-lock / screensaver timeout is configured."""
    try:
        data = run_powershell_json(_PS_SCREEN)
    except ApotropeError as exc:
        return [_error("Screen Lock Timeout", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    active = str(data.get("Active") or "0").strip()
    secure = str(data.get("Secure") or "0").strip()
    timeout_raw = data.get("Timeout")

    screensaver_active = active == "1"
    password_on_resume = secure == "1"

    # A machine-wide inactivity limit locks the console even without a per-user
    # screensaver, so a properly hardened machine should not be WARNed here.
    machine_raw = data.get("MachineInactivity")
    try:
        machine_secs = int(machine_raw) if machine_raw is not None else 0
    except (TypeError, ValueError):
        machine_secs = 0
    if 0 < machine_secs <= _LOCK_WARN_SECS:
        return [CheckResult(
            category=CATEGORY,
            check_name="Screen Lock Timeout",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=f"Checks that the screen automatically locks within {_LOCK_WARN_SECS // 60} minutes.",
            details=(
                f"Machine inactivity limit is set to {machine_secs // 60} minute(s); "
                "the machine locks automatically on inactivity."
            ),
            remediation="",
        )]

    if not screensaver_active:
        return [CheckResult(
            category=CATEGORY,
            check_name="Screen Lock Timeout",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description=f"Checks that the screen automatically locks within {_LOCK_WARN_SECS // 60} minutes.",
            details=(
                "Screensaver is not enabled — the screen will not lock automatically on inactivity."
            ),
            remediation=(
                "Enable the screensaver with password protection via: "
                "Settings → Personalization → Screen saver → "
                "set a timeout and check 'On resume, display logon screen'."
            ),
        )]

    try:
        timeout_secs = int(timeout_raw) if timeout_raw is not None else 0
    except (TypeError, ValueError):
        timeout_secs = 0

    if timeout_secs == 0:
        return [CheckResult(
            category=CATEGORY,
            check_name="Screen Lock Timeout",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description=f"Checks that the screen automatically locks within {_LOCK_WARN_SECS // 60} minutes.",
            details="Screensaver is enabled but timeout is 0 or unset.",
            remediation="Set a screen-lock timeout of 15 minutes or less.",
        )]

    too_long = timeout_secs > _LOCK_WARN_SECS
    mins = timeout_secs // 60

    return [CheckResult(
        category=CATEGORY,
        check_name="Screen Lock Timeout",
        status=Status.WARN if (too_long or not password_on_resume) else Status.PASS,
        severity=Severity.MEDIUM,
        description=f"Checks that the screen automatically locks within {_LOCK_WARN_SECS // 60} minutes.",
        details=(
            f"Screen lock timeout: {mins} minute(s)"
            + (" (exceeds 15-minute recommended maximum)." if too_long else ".")
            + ("" if password_on_resume else " Password on resume is NOT enabled.")
        ),
        remediation=(
            "" if (not too_long and password_on_resume) else
            "Set timeout ≤ 15 minutes and enable 'On resume, display logon screen'."
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
