"""Check: Local accounts, Administrators group, and password policy."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Accounts"

_PS_GUEST = "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"

_PS_ADMIN = (
    "Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue "
    "| Select-Object Name, Enabled | ConvertTo-Json -Compress"
)

_PS_ADMINS = (
    "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue "
    "| Select-Object Name, PrincipalSource, ObjectClass | ConvertTo-Json -Compress"
)

_PS_NET_ACCOUNTS = "net accounts"

# Export local security policy to a temp file, extract complexity setting, clean up.
_PS_COMPLEXITY = (
    "$tmp = [System.IO.Path]::GetTempFileName(); "
    "secedit /export /cfg $tmp /quiet | Out-Null; "
    "$c = Get-Content $tmp -ErrorAction SilentlyContinue; "
    "Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
    "$line = $c | Where-Object { $_ -like 'PasswordComplexity*' }; "
    "if ($line) { ($line -split '=')[1].Trim() } else { 'Unknown' }"
)

_ADMIN_WARN_THRESHOLD = 2
_MIN_PW_FAIL = 8
_MIN_PW_WARN = 12


def run() -> list[CheckResult]:
    """Return local account and password policy checks.

    Returns:
        list[CheckResult]: Results for guest, built-in admin, admin count,
        password length, lockout policy, and complexity.
    """
    results: list[CheckResult] = []
    results.extend(_check_guest_account())
    results.extend(_check_builtin_admin())
    results.extend(_check_admin_count())
    results.extend(_check_password_policy())
    return results


def _check_guest_account() -> list[CheckResult]:
    """Check whether the built-in Guest account is enabled."""
    try:
        output = run_powershell(_PS_GUEST).strip()
    except ApotropeError as exc:
        return [_error("Guest Account", str(exc))]

    if not output:
        return [CheckResult(
            category=CATEGORY,
            check_name="Guest Account",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether the built-in Guest account is disabled.",
            details="Guest account not found (may have been renamed or deleted — good practice).",
            remediation="",
        )]

    enabled = output.lower() == "true"
    return [CheckResult(
        category=CATEGORY,
        check_name="Guest Account",
        status=Status.FAIL if enabled else Status.PASS,
        severity=Severity.HIGH,
        description="Checks whether the built-in Guest account is disabled.",
        details=f"Built-in Guest account is {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if not enabled else
            "Disable the Guest account: Disable-LocalUser -Name 'Guest'"
        ),
    )]


def _check_builtin_admin() -> list[CheckResult]:
    """Check whether the built-in Administrator account is enabled and/or renamed."""
    try:
        data = run_powershell_json(_PS_ADMIN)
    except ApotropeError as exc:
        return [_error("Built-in Administrator Account", str(exc))]

    if not data:
        return [CheckResult(
            category=CATEGORY,
            check_name="Built-in Administrator Account",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks if the built-in Administrator account is enabled and not renamed.",
            details="Administrator account not found (likely renamed — good practice).",
            remediation="",
        )]

    if isinstance(data, list):
        data = data[0] if data else {}

    name = str(data.get("Name", "Administrator"))
    enabled = bool(data.get("Enabled", False))
    is_default_name = name.lower() == "administrator"

    if enabled and is_default_name:
        status, sev = Status.FAIL, Severity.MEDIUM
        details = "Built-in Administrator account is enabled with the default name."
        remediation = (
            "Rename and/or disable the built-in Administrator account. "
            "Rename: Rename-LocalUser -Name 'Administrator' -NewName '<new_name>'. "
            "Disable: Disable-LocalUser -Name 'Administrator'"
        )
    elif enabled:
        status, sev = Status.WARN, Severity.LOW
        details = f"Built-in Administrator account is enabled (renamed to '{name}')."
        remediation = (
            "Consider disabling the built-in Administrator account if it is not in active use: "
            f"Disable-LocalUser -Name '{name}'"
        )
    else:
        status, sev = Status.PASS, Severity.MEDIUM
        rename_note = f" (renamed to '{name}')" if not is_default_name else ""
        details = f"Built-in Administrator account is disabled{rename_note}."
        remediation = ""

    return [CheckResult(
        category=CATEGORY,
        check_name="Built-in Administrator Account",
        status=status,
        severity=sev,
        description="Checks if the built-in Administrator account is enabled and not renamed.",
        details=details,
        remediation=remediation,
    )]


def _check_admin_count() -> list[CheckResult]:
    """Count members of the local Administrators group."""
    try:
        data = run_powershell_json(_PS_ADMINS)
    except ApotropeError as exc:
        return [_error("Local Administrators", str(exc))]

    members = data if isinstance(data, list) else ([data] if data else [])
    count = len(members)
    # Strip domain prefix from display names
    names = [str(m.get("Name", "Unknown")).split("\\")[-1] for m in members]

    over_threshold = count > _ADMIN_WARN_THRESHOLD
    return [CheckResult(
        category=CATEGORY,
        check_name="Local Administrators",
        status=Status.WARN if over_threshold else Status.PASS,
        severity=Severity.MEDIUM,
        description=f"Counts members of the local Administrators group (WARN if >{_ADMIN_WARN_THRESHOLD}).",
        details=f"{count} administrator(s): {', '.join(names) if names else 'none'}",
        remediation=(
            "" if not over_threshold else
            f"Review and reduce the {count} local administrator accounts. "
            "Remove unnecessary members: "
            "Remove-LocalGroupMember -Group 'Administrators' -Member '<username>'"
        ),
    )]


def _check_password_policy() -> list[CheckResult]:
    """Check local password policy via net accounts and secedit."""
    results: list[CheckResult] = []

    # --- net accounts: length and lockout ---
    try:
        net_output = run_powershell(_PS_NET_ACCOUNTS)
    except ApotropeError as exc:
        return [_error("Password Policy", str(exc))]

    policy = _parse_net_accounts(net_output)

    # Minimum password length
    min_len_str = policy.get("minimum password length", "0")
    try:
        min_len = int(min_len_str)
    except ValueError:
        min_len = 0

    if min_len < _MIN_PW_FAIL:
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Password Policy — Minimum Length",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description=f"Minimum password length must be ≥{_MIN_PW_FAIL} (WARN if <{_MIN_PW_WARN}).",
            details=f"Minimum password length: {min_len} characters.",
            remediation=f"Increase minimum password length: net accounts /minpwlen:{_MIN_PW_WARN}",
        ))
    elif min_len < _MIN_PW_WARN:
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Password Policy — Minimum Length",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description=f"Minimum password length must be ≥{_MIN_PW_FAIL} (WARN if <{_MIN_PW_WARN}).",
            details=f"Minimum password length: {min_len} characters (recommended: {_MIN_PW_WARN}+).",
            remediation=f"Increase minimum password length: net accounts /minpwlen:{_MIN_PW_WARN}",
        ))
    else:
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Password Policy — Minimum Length",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=f"Minimum password length must be ≥{_MIN_PW_FAIL} (WARN if <{_MIN_PW_WARN}).",
            details=f"Minimum password length: {min_len} characters.",
            remediation="",
        ))

    # Account lockout
    lockout_raw = policy.get("lockout threshold", "Never")
    lockout_disabled = lockout_raw.lower() in ("never", "0", "none", "")
    lockout_dur = policy.get("lockout duration (minutes)", "N/A")
    results.append(CheckResult(
        category=CATEGORY,
        check_name="Password Policy — Account Lockout",
        status=Status.WARN if lockout_disabled else Status.PASS,
        severity=Severity.MEDIUM,
        description="Checks whether account lockout is configured to deter brute-force attacks.",
        details=(
            "Account lockout is disabled — accounts are not locked after failed login attempts."
            if lockout_disabled else
            f"Lockout threshold: {lockout_raw} attempt(s) | Duration: {lockout_dur} minute(s)."
        ),
        remediation=(
            "" if not lockout_disabled else
            "Enable account lockout: net accounts /lockoutthreshold:5 /lockoutduration:30"
        ),
    ))

    # --- secedit: password complexity ---
    try:
        complexity_val = run_powershell(_PS_COMPLEXITY).strip()
    except ApotropeError as exc:
        results.append(_error("Password Policy — Complexity", str(exc)))
        return results

    if complexity_val == "Unknown":
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Password Policy — Complexity",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether password complexity requirements are enforced.",
            details="Could not determine password complexity setting (secedit output unavailable).",
            remediation="",
        ))
    else:
        enabled = complexity_val.strip() == "1"
        results.append(CheckResult(
            category=CATEGORY,
            check_name="Password Policy — Complexity",
            status=Status.PASS if enabled else Status.FAIL,
            severity=Severity.MEDIUM,
            description="Checks whether password complexity requirements are enforced.",
            details=f"Password complexity requirement: {'enabled' if enabled else 'disabled'}.",
            remediation=(
                "" if enabled else
                "Enable password complexity: "
                "secpol.msc → Account Policies → Password Policy → "
                "Password must meet complexity requirements → Enabled"
            ),
        ))

    return results


def _parse_net_accounts(output: str) -> dict[str, str]:
    """Parse 'net accounts' text output into a lowercase key → value dict."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip().lower()] = val.strip()
    return result


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
