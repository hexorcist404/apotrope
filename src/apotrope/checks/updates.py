"""Check: Windows Update status — last install date, pending updates, service state."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell

log = logging.getLogger(__name__)

CATEGORY = "Patching"

_DEFAULT_FAIL_DAYS = 60   # CRITICAL: no updates installed in this many days
_DEFAULT_WARN_DAYS = 30   # HIGH: no updates installed in this many days

_FAIL_DAYS = _DEFAULT_FAIL_DAYS
_WARN_DAYS = _DEFAULT_WARN_DAYS


def configure(thresholds: dict) -> None:
    """Apply profile threshold overrides for this module.

    Recognised keys: ``max_update_age_warn`` (int days), ``max_update_age_fail`` (int days).
    Called by the scanner before run() when a profile with thresholds is active. The
    scanner calls :func:`reset` afterwards, so an override never leaks into a later scan
    in the same process.
    """
    global _WARN_DAYS, _FAIL_DAYS  # noqa: PLW0603
    if "max_update_age_warn" in thresholds:
        _WARN_DAYS = int(thresholds["max_update_age_warn"])
    if "max_update_age_fail" in thresholds:
        _FAIL_DAYS = int(thresholds["max_update_age_fail"])


def reset() -> None:
    """Restore the default thresholds, undoing any prior :func:`configure` call.

    The scanner calls this after running the module so a profile's thresholds do not
    persist into a subsequent scan that uses a different profile or none at all.
    """
    global _WARN_DAYS, _FAIL_DAYS  # noqa: PLW0603
    _WARN_DAYS = _DEFAULT_WARN_DAYS
    _FAIL_DAYS = _DEFAULT_FAIL_DAYS

# Get the most recently installed hotfix with a valid date.
# Some hotfixes have a null InstalledOn; filter those out.
_PS_LAST_HOTFIX = (
    "$hf = Get-HotFix "
    "| Where-Object { $_.InstalledOn -ne $null } "
    "| Sort-Object InstalledOn -Descending "
    "| Select-Object -First 1; "
    "if ($hf) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { 'NONE' }"
)

# Emit "<StartType>|<Status>" e.g. "Automatic|Stopped". StartType is the stable
# config signal: wuauserv starts on demand/trigger and idles to Stopped on
# modern Windows, so a momentary Stopped state is normal, not a finding — only a
# Disabled start type actually blocks updates.
_PS_WU_SERVICE = (
    "$s = Get-Service -Name wuauserv -ErrorAction SilentlyContinue; "
    "if ($s) { \"$($s.StartType)|$($s.Status)\" }"
)

# Query pending updates via COM. Returns count or 'UNAVAILABLE' on failure.
_PS_PENDING = (
    "try { "
    "$s = New-Object -ComObject Microsoft.Update.Session; "
    "$r = $s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\"); "
    "$r.Updates.Count "
    "} catch { 'UNAVAILABLE' }"
)

# Install pending Windows updates. Leads with the reliable built-in path (opens the
# Windows Update pane); the scripted PSWindowsUpdate route is offered as commented
# lines because that module is not installed by default and -AutoReboot restarts the
# machine — a bare "Install-WindowsUpdate" fails with "not recognized" on a stock box.
_CMD_INSTALL_UPDATES = (
    "# Install pending updates. Reliable built-in path — opens Windows Update:\n"
    "Start-Process 'ms-settings:windowsupdate'\n"
    "# Scripted alternative (installs the PSWindowsUpdate community module; may reboot):\n"
    "#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force\n"
    "#   Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null\n"
    "#   Install-Module PSWindowsUpdate -Force -Scope CurrentUser -Confirm:$false\n"
    "#   Import-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -AutoReboot"
)


def _now() -> datetime:
    """Return current UTC time. Exists as a separate function to allow mocking in tests."""
    return datetime.now(tz=timezone.utc)


def run() -> list[CheckResult]:
    """Return Windows Update status checks.

    Returns:
        list[CheckResult]: Results for last update age, WU service, and pending count.
    """
    results: list[CheckResult] = []
    results.extend(_check_last_update())
    results.extend(_check_wu_service())
    results.extend(_check_pending_updates())
    return results


def _check_last_update() -> list[CheckResult]:
    """Check when the last Windows Update was installed."""
    try:
        output = run_powershell(_PS_LAST_HOTFIX).strip()
    except ApotropeError as exc:
        return [_error("Last Windows Update", str(exc))]

    if not output or output == "NONE":
        return [CheckResult(
            category=CATEGORY,
            check_name="Last Windows Update",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks when the most recent Windows Update was installed.",
            details="No hotfixes with a valid install date were found in the hotfix log.",
            remediation=(
                "Install all pending quality and security updates. "
                "Schedule a maintenance window if reboots are deferred."
            ),
            command=_CMD_INSTALL_UPDATES,
        )]

    try:
        last_update = datetime.strptime(output, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        return [_error("Last Windows Update", f"Could not parse date {output!r}: {exc}")]

    now = _now()
    age_days = (now - last_update).days

    if age_days >= _FAIL_DAYS:
        return [CheckResult(
            category=CATEGORY,
            check_name="Last Windows Update",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Checks when the most recent Windows Update was installed.",
            details=(
                f"Last update installed {age_days} days ago "
                f"({last_update.strftime('%Y-%m-%d')}). "
                f"System is {age_days - _FAIL_DAYS} days past the {_FAIL_DAYS}-day threshold."
            ),
            remediation=(
                "Install all pending quality and security updates. "
                "Schedule a maintenance window if reboots are deferred."
            ),
            command=_CMD_INSTALL_UPDATES,
        )]

    if age_days >= _WARN_DAYS:
        return [CheckResult(
            category=CATEGORY,
            check_name="Last Windows Update",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks when the most recent Windows Update was installed.",
            details=(
                f"Last update installed {age_days} days ago "
                f"({last_update.strftime('%Y-%m-%d')})."
            ),
            remediation=(
                "Install all pending quality and security updates. "
                "Schedule a maintenance window if reboots are deferred."
            ),
            command=_CMD_INSTALL_UPDATES,
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="Last Windows Update",
        status=Status.PASS,
        severity=Severity.CRITICAL,
        description="Checks when the most recent Windows Update was installed.",
        details=(
            f"Last update installed {age_days} day(s) ago "
            f"({last_update.strftime('%Y-%m-%d')})."
        ),
        remediation="",
    )]


def _check_wu_service() -> list[CheckResult]:
    """Check whether the Windows Update service is running."""
    try:
        output = run_powershell(_PS_WU_SERVICE).strip()
    except ApotropeError as exc:
        return [_error("Windows Update Service", str(exc))]

    if not output:
        return [CheckResult(
            category=CATEGORY,
            check_name="Windows Update Service",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Checks whether the Windows Update (wuauserv) service is running.",
            details="Could not determine Windows Update service status (service may not exist).",
            remediation="Verify the service exists: Get-Service -Name wuauserv",
        )]

    start_type, _, status = output.partition("|")
    start_type = start_type.strip()
    status = status.strip()

    if start_type.lower() == "disabled":
        return [CheckResult(
            category=CATEGORY,
            check_name="Windows Update Service",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether the Windows Update (wuauserv) service can run.",
            details=(
                f"Windows Update service start type is Disabled "
                f"(current state: {status or 'unknown'}). The service cannot "
                "start, so the system will not receive updates."
            ),
            remediation=(
                "Set the Windows Update service to start automatically (or on "
                "demand) so updates can install."
            ),
            command="Set-Service -Name wuauserv -StartupType Automatic",
        )]

    # Automatic or Manual, any current Status. wuauserv is started on
    # demand/trigger and idles to Stopped on modern Windows, so a Stopped state
    # is normal and deterministic across runs — flagging it produced a
    # shell-dependent false positive. Only a Disabled start type is a finding.
    return [CheckResult(
        category=CATEGORY,
        check_name="Windows Update Service",
        status=Status.PASS,
        severity=Severity.HIGH,
        description="Checks whether the Windows Update (wuauserv) service can run.",
        details=(
            f"Windows Update service start type is {start_type or 'unknown'} "
            f"(current state: {status or 'unknown'}); it starts on demand when "
            "updates are needed."
        ),
        remediation="",
        command="",
    )]


def _check_pending_updates() -> list[CheckResult]:
    """Count Windows Updates that are available but not yet installed."""
    try:
        # COM object query can be slow on machines with many updates pending;
        # use a 60s timeout to avoid stalling the entire scan.
        output = run_powershell(_PS_PENDING, timeout=60).strip()
    except ApotropeError as exc:
        return [_error("Pending Windows Updates", str(exc))]

    if output == "UNAVAILABLE":
        return [CheckResult(
            category=CATEGORY,
            check_name="Pending Windows Updates",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Counts Windows Updates that are available but not yet installed.",
            details=(
                "Could not query pending updates "
                "(Windows Update COM object unavailable or access denied)."
            ),
            remediation="",
        )]

    try:
        count = int(output)
    except ValueError:
        return [CheckResult(
            category=CATEGORY,
            check_name="Pending Windows Updates",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Counts Windows Updates that are available but not yet installed.",
            details=f"Unexpected output from pending update check: {output!r}",
            remediation="",
        )]

    if count == 0:
        return [CheckResult(
            category=CATEGORY,
            check_name="Pending Windows Updates",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Counts Windows Updates that are available but not yet installed.",
            details="No pending Windows Updates found.",
            remediation="",
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="Pending Windows Updates",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description="Counts Windows Updates that are available but not yet installed.",
        details=f"{count} pending Windows Update(s) are available but not installed.",
        remediation=(
            f"Install the {count} pending update(s) from Windows Update "
            "(or the scripted PSWindowsUpdate path shown below)."
        ),
        command=_CMD_INSTALL_UPDATES,
    )]


def _error(check_name: str, details: str) -> CheckResult:
    """Return a synthetic ERROR result for a failed sub-check."""
    return CheckResult(
        category=CATEGORY,
        check_name=check_name,
        status=Status.ERROR,
        severity=Severity.INFO,
        description="An error occurred while running this check.",
        details=details,
        remediation="Run with --log-level DEBUG for more detail.",
    )
