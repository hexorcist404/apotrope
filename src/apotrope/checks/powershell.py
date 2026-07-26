"""Check: PowerShell security — execution policy, logging, constrained mode, PSv2."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell

log = logging.getLogger(__name__)

CATEGORY = "PowerShell"

# Policies that bypass script execution restrictions entirely
_RISKY_POLICIES = {"unrestricted", "bypass"}

_PS_EXEC_POLICY = "Get-ExecutionPolicy -Scope LocalMachine"

_SBL_KEY = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
_PS_SBL = (
    f"$v = (Get-ItemProperty -LiteralPath '{_SBL_KEY}' "
    "-ErrorAction SilentlyContinue).EnableScriptBlockLogging; "
    "if ($null -eq $v) { 'NOTSET' } else { [string]$v }"
)

_ML_KEY = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
_PS_ML = (
    f"$v = (Get-ItemProperty -LiteralPath '{_ML_KEY}' "
    "-ErrorAction SilentlyContinue).EnableModuleLogging; "
    "if ($null -eq $v) { 'NOTSET' } else { [string]$v }"
)

_PS_CLM = "$ExecutionContext.SessionState.LanguageMode"

_PS_V2 = (
    "try { "
    "(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root "
    "-ErrorAction SilentlyContinue).State "
    "} catch { 'UNAVAILABLE' }"
)


def run() -> list[CheckResult]:
    """Return PowerShell security configuration checks.

    Returns:
        list[CheckResult]: Results for execution policy, script block logging,
        module logging, constrained language mode, and PSv2 availability.
    """
    results: list[CheckResult] = []
    results.extend(_check_execution_policy())
    results.extend(_check_script_block_logging())
    results.extend(_check_module_logging())
    results.extend(_check_constrained_language())
    results.extend(_check_psv2())
    return results


def _check_execution_policy() -> list[CheckResult]:
    """Check the LocalMachine PowerShell execution policy."""
    try:
        output = run_powershell(_PS_EXEC_POLICY).strip()
    except ApotropeError as exc:
        return [_error("PowerShell Execution Policy", str(exc))]

    policy = output.lower()
    risky = policy in _RISKY_POLICIES

    return [CheckResult(
        category=CATEGORY,
        check_name="PowerShell Execution Policy",
        status=Status.WARN if risky else Status.INFO,
        severity=Severity.MEDIUM,
        description="Checks the LocalMachine PowerShell execution policy.",
        details=(
            f"Execution policy is '{output}' — allows any script to run without restriction."
            if risky else
            f"Execution policy is '{output}'."
        ),
        remediation=(
            "" if not risky else
            "Tighten the execution policy from Unrestricted to RemoteSigned (or AllSigned)."
        ),
        command=(
            "" if not risky else
            "Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force"
        ),
    )]


def _check_script_block_logging() -> list[CheckResult]:
    """Check whether PowerShell Script Block Logging is enabled."""
    try:
        output = run_powershell(_PS_SBL).strip()
    except ApotropeError as exc:
        return [_error("PowerShell Script Block Logging", str(exc))]

    enabled = output == "1"

    return [CheckResult(
        category=CATEGORY,
        check_name="PowerShell Script Block Logging",
        status=Status.PASS if enabled else Status.WARN,
        severity=Severity.MEDIUM,
        description="Checks whether PowerShell Script Block Logging is enabled (critical for forensics/IR).",
        details=(
            "Script Block Logging is enabled — PowerShell commands are logged to the event log."
            if enabled else
            "Script Block Logging is disabled. Malicious PowerShell activity may go undetected."
        ),
        remediation=(
            "" if enabled else
            "Enable PowerShell Script Block Logging so malicious or obfuscated scripts "
            "are recorded in the event log."
        ),
        command=(
            "" if enabled else
            f"$key = '{_SBL_KEY}'\n"
            "New-Item -Path $key -Force | Out-Null\n"
            "Set-ItemProperty -Path $key -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord"
        ),
    )]


def _check_module_logging() -> list[CheckResult]:
    """Check whether PowerShell Module Logging is enabled."""
    try:
        output = run_powershell(_PS_ML).strip()
    except ApotropeError as exc:
        return [_error("PowerShell Module Logging", str(exc))]

    enabled = output == "1"

    return [CheckResult(
        category=CATEGORY,
        check_name="PowerShell Module Logging",
        status=Status.PASS if enabled else Status.WARN,
        severity=Severity.MEDIUM,
        description="Checks whether PowerShell Module Logging is enabled.",
        details=(
            "Module Logging is enabled — module pipeline execution events are logged."
            if enabled else
            "Module Logging is disabled. Detailed module activity is not recorded."
        ),
        remediation=(
            "" if enabled else
            "Enable PowerShell Module Logging so module pipeline execution is recorded "
            "in the event log."
        ),
        command=(
            "" if enabled else
            f"$key = '{_ML_KEY}'\n"
            "New-Item -Path $key -Force | Out-Null\n"
            "Set-ItemProperty -Path $key -Name 'EnableModuleLogging' -Value 1 -Type DWord\n"
            "New-Item -Path \"$key\\ModuleNames\" -Force | Out-Null\n"
            "Set-ItemProperty -Path \"$key\\ModuleNames\" -Name '*' -Value '*'"
        ),
    )]


def _check_constrained_language() -> list[CheckResult]:
    """Report the current PowerShell language mode (informational)."""
    try:
        output = run_powershell(_PS_CLM).strip()
    except ApotropeError as exc:
        return [_error("PowerShell Constrained Language Mode", str(exc))]

    is_constrained = output.lower() == "constrainedlanguage"

    return [CheckResult(
        category=CATEGORY,
        check_name="PowerShell Constrained Language Mode",
        status=Status.PASS if is_constrained else Status.INFO,
        severity=Severity.LOW,
        description="Checks whether PowerShell Constrained Language Mode is active.",
        details=f"PowerShell language mode: {output}.",
        remediation="",
    )]


def _check_psv2() -> list[CheckResult]:
    """Check whether PowerShell v2 is installed (downgrade attack vector)."""
    try:
        output = run_powershell(_PS_V2).strip()
    except ApotropeError as exc:
        return [_error("PowerShell v2", str(exc))]

    state = output.lower()

    # Enabled / EnabledWithPayloadRemoved both mean v2 engine is present
    if state in ("enabled", "enabledwithpayloadremoved"):
        return [CheckResult(
            category=CATEGORY,
            check_name="PowerShell v2",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether PowerShell v2 is installed (downgrade attack vector).",
            details=(
                "PowerShell v2 is installed. Attackers can invoke 'powershell -Version 2' "
                "to bypass Script Block Logging and other v5+ security controls."
            ),
            remediation="Remove the legacy PowerShell v2 engine (a downgrade-attack vector).",
            command=(
                "Disable-WindowsOptionalFeature -Online "
                "-FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
            ),
        )]

    if state == "disabled":
        return [CheckResult(
            category=CATEGORY,
            check_name="PowerShell v2",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="Checks whether PowerShell v2 is installed (downgrade attack vector).",
            details="PowerShell v2 is not installed or disabled.",
            remediation="",
        )]
    # 'UNAVAILABLE' is the query-failure sentinel (e.g. Get-WindowsOptionalFeature
    # needs elevation) — NOT proof v2 is absent. Fall through to the INFO branch
    # below rather than claiming a secure state we could not confirm.

    # State could not be determined (e.g. non-Windows or missing module)
    return [CheckResult(
        category=CATEGORY,
        check_name="PowerShell v2",
        status=Status.INFO,
        severity=Severity.MEDIUM,
        description="Checks whether PowerShell v2 is installed (downgrade attack vector).",
        details=f"Could not determine PowerShell v2 status (state: '{output}').",
        remediation="",
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
