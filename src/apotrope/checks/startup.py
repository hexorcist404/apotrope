"""Check: Startup programs and scheduled tasks (persistence points)."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Persistence"

# Win32_StartupCommand covers HKLM/HKCU Run/RunOnce keys and startup folders.
_PS_STARTUP = (
    "Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue "
    "| Select-Object Name, Command, Location, User "
    "| ConvertTo-Json -Compress"
)

# Non-Microsoft scheduled tasks that are not disabled.
_PS_TASKS = (
    "Get-ScheduledTask -ErrorAction SilentlyContinue "
    "| Where-Object { "
    "    $_.TaskPath -notlike '\\Microsoft\\*' -and "
    "    $_.State -ne 'Disabled' "
    "} "
    "| Select-Object TaskName, TaskPath, "
    "@{N='RunAs';E={$_.Principal.UserId}}, "
    "@{N='State';E={$_.State.ToString()}} "
    "| ConvertTo-Json -Compress"
)

_MAX_DISPLAY = 20


def run() -> list[CheckResult]:
    """Return persistence / startup checks.

    Returns:
        list[CheckResult]: Results for startup programs and scheduled tasks.
    """
    results: list[CheckResult] = []
    results.extend(_check_startup_programs())
    results.extend(_check_scheduled_tasks())
    return results


def _check_startup_programs() -> list[CheckResult]:
    """Enumerate startup programs via Win32_StartupCommand."""
    try:
        data = run_powershell_json(_PS_STARTUP)
    except ApotropeError as exc:
        return [_error("Startup Programs", str(exc))]

    items = data if isinstance(data, list) else ([data] if data else [])
    count = len(items)

    names = [str(i.get("Name") or "Unknown") for i in items]
    display = ", ".join(names[:_MAX_DISPLAY])
    if count > _MAX_DISPLAY:
        display += f" … (+{count - _MAX_DISPLAY} more)"

    return [CheckResult(
        category=CATEGORY,
        check_name="Startup Programs",
        status=Status.INFO,
        severity=Severity.LOW,
        description="Enumerates programs configured to run at startup (registry Run keys + startup folders).",
        details=(
            f"{count} startup program(s): {display}"
            if count else
            "No startup programs found via Win32_StartupCommand."
        ),
        remediation="",
    )]


def _check_scheduled_tasks() -> list[CheckResult]:
    """Enumerate non-Microsoft enabled scheduled tasks."""
    try:
        data = run_powershell_json(_PS_TASKS)
    except ApotropeError as exc:
        return [_error("Scheduled Tasks", str(exc))]

    items = data if isinstance(data, list) else ([data] if data else [])
    count = len(items)

    names = [str(i.get("TaskName") or "Unknown") for i in items]
    display = ", ".join(names[:_MAX_DISPLAY])
    if count > _MAX_DISPLAY:
        display += f" … (+{count - _MAX_DISPLAY} more)"

    return [CheckResult(
        category=CATEGORY,
        check_name="Scheduled Tasks",
        status=Status.INFO,
        severity=Severity.LOW,
        description="Enumerates non-Microsoft scheduled tasks (potential persistence points).",
        details=(
            f"{count} non-Microsoft task(s): {display}"
            if count else
            "No non-Microsoft scheduled tasks found."
        ),
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
