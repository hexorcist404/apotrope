"""Check: Local accounts, Administrators group, and password policy.

Security principals are identified by SID, not by display name: the built-in
Administrator/Guest are matched on their RID suffix (-500 / -501) and the
Administrators group by its well-known SID ``S-1-5-32-544``. This survives
renamed accounts and non-English Windows, where a name-based lookup silently
finds nothing. Every query is written so that a failure (access denied, module
missing) exits non-zero → ``ApotropeError`` → an ERROR result, which is kept
distinct from a *successful* query that legitimately returns no rows.
"""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Accounts"

_ADMINISTRATORS_SID = "S-1-5-32-544"

# Enumerate every local user with a flat SID string. -ErrorAction Stop + the
# try/catch turn any failure into exit 1 → ApotropeError, so a denied query is
# never confused with "no such account". The calculated SID property is required
# because projecting $_.SID directly serialises a nested object, not the string.
_PS_LOCAL_USERS = (
    "try { "
    "Get-LocalUser -ErrorAction Stop | "
    "Select-Object Name, Enabled, @{Name='SID';Expression={$_.SID.Value}} | "
    "ConvertTo-Json -Compress "
    "} catch { Write-Error $_; exit 1 }"
)

# Administrators group by well-known SID (locale-neutral), same failure discipline.
_PS_ADMINS = (
    "try { "
    f"Get-LocalGroupMember -SID '{_ADMINISTRATORS_SID}' -ErrorAction Stop | "
    "Select-Object Name, PrincipalSource, ObjectClass | "
    "ConvertTo-Json -Compress "
    "} catch { Write-Error $_; exit 1 }"
)

# One secedit export → locale-neutral INF keys. The $LASTEXITCODE check surfaces a
# secedit failure that Out-Null would otherwise mask; the temp file is always removed.
_PS_SECEDIT = (
    "$tmp = [System.IO.Path]::GetTempFileName(); "
    "try { "
    "secedit /export /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null; "
    "if ($LASTEXITCODE -ne 0) { throw \"secedit exited $LASTEXITCODE\" }; "
    "Get-Content -LiteralPath $tmp -ErrorAction Stop "
    "} catch { Write-Error $_; exit 1 } "
    "finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }"
)

_ADMIN_WARN_THRESHOLD = 2
_MIN_PW_FAIL = 8
_MIN_PW_WARN = 12
_MIN_PW_TARGET = 14  # CIS 1.1.4 recommended length — the value remediation sets


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


def _local_users() -> list[dict]:
    """Enumerate local users (Name, Enabled, SID). Raises ApotropeError on query failure."""
    data = run_powershell_json(_PS_LOCAL_USERS)
    return data if isinstance(data, list) else ([data] if data else [])


def _find_by_rid(users: list[dict], rid: str) -> dict | None:
    """Return the user whose SID ends in ``-<rid>`` (e.g. ``-500``), else ``None``.

    The leading hyphen anchors the match so RID 500 is never confused with 1500.
    """
    suffix = f"-{rid}"
    return next((u for u in users if str(u.get("SID", "")).endswith(suffix)), None)


def _check_guest_account() -> list[CheckResult]:
    """Check whether the built-in Guest account (RID-501) is disabled."""
    try:
        users = _local_users()
    except ApotropeError as exc:
        return [_error("Guest Account", str(exc))]

    guest = _find_by_rid(users, "501")
    if guest is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="Guest Account",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether the built-in Guest account is disabled.",
            details="Built-in Guest account (RID-501) is not present on this system.",
            remediation="",
        )]

    enabled = bool(guest.get("Enabled", False))
    name = str(guest.get("Name", "Guest"))
    sid = str(guest.get("SID", ""))
    return [CheckResult(
        category=CATEGORY,
        check_name="Guest Account",
        status=Status.FAIL if enabled else Status.PASS,
        severity=Severity.HIGH,
        description="Checks whether the built-in Guest account is disabled.",
        details=f"Built-in Guest account ('{name}', RID-501) is "
                f"{'enabled' if enabled else 'disabled'}.",
        remediation="" if not enabled else "Disable the built-in Guest account.",
        command="" if not enabled else f"Disable-LocalUser -SID '{sid}'",
    )]


def _check_builtin_admin() -> list[CheckResult]:
    """Check whether the built-in Administrator account (RID-500) is enabled/renamed."""
    try:
        users = _local_users()
    except ApotropeError as exc:
        return [_error("Built-in Administrator Account", str(exc))]

    admin = _find_by_rid(users, "500")
    if admin is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="Built-in Administrator Account",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks if the built-in Administrator account is enabled and not renamed.",
            details="Built-in Administrator account (RID-500) is not present on this system.",
            remediation="",
        )]

    name = str(admin.get("Name", "Administrator"))
    enabled = bool(admin.get("Enabled", False))
    sid = str(admin.get("SID", ""))
    is_default_name = name.lower() == "administrator"

    if enabled and is_default_name:
        status, sev = Status.FAIL, Severity.MEDIUM
        details = "Built-in Administrator account is enabled with the default name."
        remediation = (
            "Rename the built-in Administrator account and disable it if it is not in active use."
        )
        command = (
            f"Rename-LocalUser -SID '{sid}' -NewName 'RenamedAdmin'\n"
            f"Disable-LocalUser -SID '{sid}'"
        )
    elif enabled:
        status, sev = Status.WARN, Severity.LOW
        details = f"Built-in Administrator account is enabled (renamed to '{name}')."
        remediation = (
            "Consider disabling the built-in Administrator account if it is not in active use."
        )
        command = f"Disable-LocalUser -SID '{sid}'"
    else:
        status, sev = Status.PASS, Severity.MEDIUM
        rename_note = f" (renamed to '{name}')" if not is_default_name else ""
        details = f"Built-in Administrator account is disabled{rename_note}."
        remediation = ""
        command = ""

    return [CheckResult(
        category=CATEGORY,
        check_name="Built-in Administrator Account",
        status=status,
        severity=sev,
        description="Checks if the built-in Administrator account is enabled and not renamed.",
        details=details,
        remediation=remediation,
        command=command,
    )]


def _check_admin_count() -> list[CheckResult]:
    """Count members of the local Administrators group (well-known SID S-1-5-32-544)."""
    try:
        data = run_powershell_json(_PS_ADMINS)
    except ApotropeError as exc:
        return [_error("Local Administrators", str(exc))]

    members = data if isinstance(data, list) else ([data] if data else [])
    if not members:
        # The built-in Administrators group always has at least one member (the
        # built-in admin). An empty result means the enumeration failed, not that
        # there are zero admins — report ERROR, never a false "0 administrators" PASS.
        return [_error(
            "Local Administrators",
            "Could not enumerate the Administrators group (S-1-5-32-544 returned no "
            "members). Re-run as Administrator for a reliable count.",
        )]

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
            "Review who holds local admin rights and remove standing admin from service "
            "and helpdesk accounts; use just-in-time elevation (LAPS / PIM) instead."
        ),
        command=(
            "" if not over_threshold else
            "# List current local administrators\n"
            "Get-LocalGroupMember -SID 'S-1-5-32-544'\n"
            "\n"
            "# Remove a standing admin (replace with the account to remove)\n"
            "Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'CORP\\svc_backup'"
        ),
    )]


def _check_password_policy() -> list[CheckResult]:
    """Check local password policy via secedit (locale-neutral INF keys)."""
    try:
        inf_text = run_powershell(_PS_SECEDIT)
    except ApotropeError as exc:
        return [_error("Password Policy", str(exc))]

    policy = _parse_secedit_inf(inf_text)
    return [
        _eval_min_length(policy),
        _eval_lockout(policy),
        _eval_complexity(policy),
    ]


def _eval_min_length(policy: dict[str, str]) -> CheckResult:
    name = "Password Policy — Minimum Length"
    raw = policy.get("minimumpasswordlength")
    if raw is None:
        return _error(name, "MinimumPasswordLength missing from the exported security policy.")
    try:
        min_len = int(raw)
    except ValueError:
        return _error(name, f"MinimumPasswordLength is not an integer: {raw!r}.")

    if min_len < _MIN_PW_FAIL:
        status, sev = Status.FAIL, Severity.HIGH
        detail_suffix = ""
    elif min_len < _MIN_PW_WARN:
        status, sev = Status.WARN, Severity.MEDIUM
        detail_suffix = f" (recommended: {_MIN_PW_TARGET}+)"
    else:
        status, sev = Status.PASS, Severity.MEDIUM
        detail_suffix = ""

    return CheckResult(
        category=CATEGORY,
        check_name=name,
        status=status,
        severity=sev,
        description=f"Minimum password length must be ≥{_MIN_PW_FAIL} (WARN if <{_MIN_PW_WARN}).",
        details=f"Minimum password length: {min_len} characters{detail_suffix}.",
        remediation=(
            "" if status is Status.PASS else
            f"Require a minimum password length of {_MIN_PW_TARGET} characters."
        ),
        command=(
            "" if status is Status.PASS else f"net accounts /minpwlen:{_MIN_PW_TARGET}"
        ),
    )


def _eval_lockout(policy: dict[str, str]) -> CheckResult:
    name = "Password Policy — Account Lockout"
    raw = policy.get("lockoutbadcount")
    if raw is None:
        return _error(name, "LockoutBadCount missing from the exported security policy.")
    try:
        threshold = int(raw)
    except ValueError:
        return _error(name, f"LockoutBadCount is not an integer: {raw!r}.")

    lockout_disabled = threshold == 0  # INF 0 = no lockout (unambiguous)
    duration = policy.get("lockoutduration", "N/A")
    return CheckResult(
        category=CATEGORY,
        check_name=name,
        status=Status.WARN if lockout_disabled else Status.PASS,
        severity=Severity.MEDIUM,
        description="Checks whether account lockout is configured to deter brute-force attacks.",
        details=(
            "Account lockout is disabled — accounts are not locked after failed login attempts."
            if lockout_disabled else
            f"Lockout threshold: {threshold} attempt(s) | Duration: {duration} minute(s)."
        ),
        remediation=(
            "" if not lockout_disabled else
            "Enable account lockout so accounts are locked after repeated failed logins."
        ),
        command=(
            "" if not lockout_disabled else
            "net accounts /lockoutthreshold:5 /lockoutduration:30"
        ),
    )


def _eval_complexity(policy: dict[str, str]) -> CheckResult:
    name = "Password Policy — Complexity"
    raw = policy.get("passwordcomplexity")
    if raw not in ("0", "1"):
        return _error(
            name,
            f"PasswordComplexity missing or unrecognized in the security policy: {raw!r}.",
        )

    enabled = raw == "1"
    return CheckResult(
        category=CATEGORY,
        check_name=name,
        status=Status.PASS if enabled else Status.FAIL,
        severity=Severity.MEDIUM,
        description="Checks whether password complexity requirements are enforced.",
        details=f"Password complexity requirement: {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if enabled else
            "Enable the password complexity requirement so passwords must mix "
            "character types."
        ),
        command=(
            "" if enabled else
            "# Enable the password-complexity policy via secedit (no reboot needed).\n"
            "$inf = \"$env:TEMP\\pwcomplexity.inf\"\n"
            "@'\n"
            "[Unicode]\n"
            "Unicode=yes\n"
            "[Version]\n"
            "signature=\"$CHICAGO$\"\n"
            "[System Access]\n"
            "PasswordComplexity = 1\n"
            "'@ | Set-Content -Path $inf -Encoding Unicode\n"
            "secedit /configure /db \"$env:TEMP\\pwcomplexity.sdb\" "
            "/cfg $inf /areas SECURITYPOLICY"
        ),
    )


def _parse_secedit_inf(text: str) -> dict[str, str]:
    """Parse ``Key = Value`` lines from a secedit INF into a lowercase-key dict.

    INF keys (MinimumPasswordLength, LockoutBadCount, PasswordComplexity, …) are
    locale-neutral template identifiers, unlike ``net accounts`` display labels.
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if "=" in s and not s.startswith("["):
            key, _, val = s.partition("=")
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
