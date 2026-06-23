"""Shared helper utilities for Apotrope.

All PowerShell, WMI, and registry access goes through this module so that
check modules stay clean and testable (mock subprocess.run in tests, not
internal helpers).
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys

from apotrope.exceptions import ApotropeError

log = logging.getLogger(__name__)

# Base PowerShell invocation flags shared by every helper
_PS_CMD = [
    "powershell.exe",
    "-NonInteractive",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
]


def _child_env() -> dict[str, str]:
    """Environment for powershell.exe children, minus ``PSModulePath``.

    A PowerShell 7 parent leaves its own Core-only module paths in the
    inherited ``PSModulePath``; Windows PowerShell 5.1 then resolves modules
    that exist in both editions (e.g. Microsoft.PowerShell.Security, home of
    ``Get-ExecutionPolicy``) to the PS7 copy and fails to load it. pwsh strips
    its paths when launching powershell.exe itself, but a Python parent passes
    the environment through raw, so we strip the variable here — powershell.exe
    rebuilds its correct default when it is absent.
    """
    return {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}


# ---------------------------------------------------------------------------
# Core PowerShell runner
# ---------------------------------------------------------------------------


def run_powershell(command: str, timeout: int = 30) -> str:
    """Run a PowerShell command and return its stdout as a string.

    Args:
        command: The PowerShell command or script block to execute.
        timeout: Seconds before the subprocess is killed (default 30).

    Returns:
        stdout stripped of leading/trailing whitespace.

    Raises:
        ApotropeError: On non-zero exit code, timeout, or launch failure.
    """
    log.debug("run_powershell: %s", command[:200])
    try:
        result = subprocess.run(
            [*_PS_CMD, command],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_child_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ApotropeError(
            f"PowerShell command timed out after {timeout}s: {command[:80]}"
        ) from exc
    except FileNotFoundError as exc:
        raise ApotropeError("powershell.exe not found — is this Windows?") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ApotropeError(
            f"PowerShell exited {result.returncode}: {stderr}"
        )

    return result.stdout.strip()


# ---------------------------------------------------------------------------
# JSON variant
# ---------------------------------------------------------------------------


def run_powershell_json(command: str, timeout: int = 30) -> dict | list:
    """Run a PowerShell command whose output is JSON and parse it.

    The command is responsible for piping through ``ConvertTo-Json``.

    Args:
        command: PowerShell command that writes valid JSON to stdout.
        timeout: Seconds before the subprocess is killed (default 30).

    Returns:
        Parsed Python ``dict`` or ``list``.  An **empty list** is returned
        when the command produces no output: a PowerShell pipeline matching
        zero objects emits empty stdout after ``ConvertTo-Json``, which is a
        valid "nothing found" result — not an error (mirrors
        :func:`get_wmi_object`).  Callers should treat a falsy result as
        "none found".

    Raises:
        ApotropeError: On PowerShell failure or invalid (non-empty) JSON.
    """
    output = run_powershell(command, timeout=timeout)

    # Zero pipeline objects -> empty stdout. Treat as "no rows" ([]) so that
    # callers' graceful "none found" paths are reachable on real machines;
    # only *malformed* non-empty JSON below is a genuine error.
    if not output:
        return []

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise ApotropeError(
            f"Failed to parse PowerShell JSON output: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Registry reader
# ---------------------------------------------------------------------------


def read_registry(hive: str, path: str, value_name: str) -> str | int | None:
    """Read a single Windows registry value via PowerShell.

    Uses ``Get-ItemProperty`` so the implementation is fully testable by
    mocking ``subprocess.run`` — no ``winreg`` import required.

    Args:
        hive:       Registry hive abbreviation: ``HKLM``, ``HKCU``, or ``HKU``.
        path:       Key path below the hive, e.g.
                    ``SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion``.
        value_name: Name of the registry value to read.

    Returns:
        The value data as ``str`` or ``int``, or ``None`` if the key or
        value does not exist or access is denied.

    Raises:
        ApotropeError: If *hive* is not one of the supported abbreviations.
    """
    _SUPPORTED_HIVES = {"HKLM", "HKCU", "HKU"}
    hive_upper = hive.upper()
    if hive_upper not in _SUPPORTED_HIVES:
        raise ApotropeError(
            f"Unsupported registry hive {hive!r}. "
            f"Supported: {', '.join(sorted(_SUPPORTED_HIVES))}"
        )

    ps_path = f"{hive_upper}:\\{path}"
    # Emit nothing (exit 0) when key/value is absent; print the value otherwise
    script = (
        f"$p = Get-ItemProperty -LiteralPath '{ps_path}' "
        f"-Name '{value_name}' -ErrorAction SilentlyContinue; "
        f"if ($null -ne $p) {{ $p.'{value_name}' }}"
    )

    try:
        output = run_powershell(script)
    except ApotropeError as exc:
        log.warning(
            "Registry read failed (%s\\%s\\%s): %s", hive, path, value_name, exc
        )
        return None

    if not output:
        log.debug("Registry value not found: %s\\%s\\%s", hive, path, value_name)
        return None

    # Preserve integer type when the value looks like a plain integer
    try:
        return int(output)
    except ValueError:
        return output


# ---------------------------------------------------------------------------
# WMI / CIM query
# ---------------------------------------------------------------------------


def get_wmi_object(
    wmi_class: str,
    namespace: str = "root\\cimv2",
    properties: list[str] | None = None,
) -> list[dict]:
    """Query WMI via ``Get-CimInstance`` and return a list of property dicts.

    Args:
        wmi_class:  WMI class name, e.g. ``Win32_OperatingSystem``.
        namespace:  WMI namespace (default ``root\\cimv2``).
        properties: Specific property names to select; ``None`` selects all.

    Returns:
        A list of dicts, one per WMI instance.  Returns an empty list on
        access-denied, class-not-found, or any other error — callers should
        treat an empty list as "could not retrieve data" and produce an
        appropriate ``Status.ERROR`` result.
    """
    select = ", ".join(properties) if properties else "*"
    script = (
        f"Get-CimInstance -ClassName '{wmi_class}' -Namespace '{namespace}' "
        f"| Select-Object {select} "
        f"| ConvertTo-Json -Depth 3 -Compress"
    )

    try:
        output = run_powershell(script)
    except ApotropeError as exc:
        log.warning("WMI query failed for %s: %s", wmi_class, exc)
        return []

    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        log.warning("Failed to parse WMI JSON for %s: %s", wmi_class, exc)
        return []

    # ConvertTo-Json emits a bare object (dict) when only one instance exists
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# Platform / privilege helpers
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    """Return ``True`` if the current process has administrator privileges.

    Always returns ``False`` on non-Windows platforms.
    """
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_windows() -> None:
    """Raise ``ApotropeError`` if not running on Windows.

    Call once at startup or at the top of any check that is Windows-only.

    Raises:
        ApotropeError: When ``sys.platform`` is not ``"win32"``.
    """
    if sys.platform != "win32":
        raise ApotropeError(
            f"Apotrope requires Windows. Current platform: {sys.platform!r}"
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def ps_bool(command: str) -> bool:
    """Run a PowerShell command and parse a ``True``/``False`` string result.

    Args:
        command: PowerShell command whose last output line is ``True`` or
                 ``False`` (case-insensitive).

    Returns:
        ``True`` if the output is ``"true"`` (case-insensitive), else ``False``.
    """
    return run_powershell(command).lower() == "true"
