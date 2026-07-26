"""Shared helper utilities for Apotrope.

All PowerShell, WMI, and registry access goes through this module so that
check modules stay clean and testable (mock subprocess.run in tests, not
internal helpers).
"""

from __future__ import annotations

import ctypes
import json
import logging
import ntpath
import os
import subprocess
import sys
from typing import cast

from apotrope.exceptions import ApotropeError, PowerShellUnavailableError

log = logging.getLogger(__name__)

_MAX_PATH = 260


def _system_windows_directory() -> str:
    """Return the shared Windows directory, via Win32 rather than the environment.

    ``%SystemRoot%`` is part of the process environment block, which is supplied
    by whoever created the process — so a hostile parent that elevates Apotrope
    can point it at a directory it controls. ``GetSystemWindowsDirectoryW`` asks
    the kernel instead. It is preferred over ``GetWindowsDirectoryW`` because
    under Terminal Services / RDS the latter returns a *per-user* private
    directory, while this one always returns the shared system directory where
    the real ``powershell.exe`` lives.

    Raises:
        ApotropeError: If the API fails or returns anything but an absolute path.
            Failing closed matters: the documented failure modes leave the buffer
            untouched, and a caller that used it anyway would build the *relative*
            path ``System32\\...\\powershell.exe`` and resolve it against the
            current directory — reinstating the very hijack this exists to close.
    """
    if sys.platform != "win32":
        # Unreachable via _powershell_path, which returns early off Windows.
        # Kept explicit so the ctypes.WinDLL access below type-checks on the
        # Linux CI legs, where typeshed marks it win32-only.
        raise ApotropeError("GetSystemWindowsDirectoryW is Windows-only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_dir = kernel32.GetSystemWindowsDirectoryW
    # uSize is documented in TCHARs (WCHARs here), NOT bytes: passing
    # ctypes.sizeof(buf) would claim twice the real capacity and invite the API
    # to write past the end of the allocation.
    get_dir.argtypes = (ctypes.c_wchar_p, ctypes.c_uint)
    get_dir.restype = ctypes.c_uint

    # On success the return value is the length excluding the terminating null,
    # so it is strictly less than uSize. If the buffer is too small the return
    # value is instead the required size *including* the null, and nothing was
    # copied — hence ``>=`` rather than ``>`` for the too-small test.
    buf = ctypes.create_unicode_buffer(_MAX_PATH)
    written = get_dir(buf, len(buf))
    if written >= len(buf):
        buf = ctypes.create_unicode_buffer(written)
        written = get_dir(buf, len(buf))
    if written == 0 or written >= len(buf):
        # get_last_error only exists on a Windows ctypes build; the mocked tests
        # reach here with sys.platform patched on Linux.
        last_error = getattr(ctypes, "get_last_error", lambda: 0)()
        raise ApotropeError(
            f"GetSystemWindowsDirectoryW failed (error {last_error})"
        )

    # cast: ctypes special-cases c_wchar arrays so slicing one returns str, but
    # typeshed declares Array.__getitem__(slice) as list[T]. Only the Windows
    # mypy legs see this — the sys.platform guard above makes the whole function
    # unreachable to mypy on Linux, so the ubuntu legs never type-check it.
    path = cast("str", buf[:written])
    # ntpath, not os.path: this is always a Windows path, and os.path is
    # posixpath on the Linux CI legs where the mocked tests run.
    if not ntpath.isabs(path):
        raise ApotropeError(
            f"GetSystemWindowsDirectoryW returned a relative path: {path!r}"
        )
    return path


def _powershell_path() -> str:
    """Resolve the absolute path to Windows PowerShell.

    Resolving the full ``System32`` path — ``Sysnative`` first so a 32-bit
    process on 64-bit Windows still reaches the native binary — avoids the
    executable-search hijack where an elevated run would otherwise pick up a
    ``powershell.exe`` planted in the application directory or the current
    directory ahead of the real one. On Windows we fail closed (never fall back
    to a ``PATH``/CWD search) if the trusted binary is missing; off Windows the
    bare name is returned so the mocked test suite is unaffected.

    Deliberately pure and uncached — :func:`_ps_executable` owns the caching, so
    tests can drive this directly without cross-test contamination.
    """
    if sys.platform != "win32":
        return "powershell.exe"
    system_root = _system_windows_directory()
    for subdir in ("Sysnative", "System32"):
        candidate = os.path.join(
            system_root, subdir, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(candidate):
            return candidate
    raise PowerShellUnavailableError(
        rf"Trusted powershell.exe not found under {system_root}\System32"
    )


# Resolution result, cached after the first attempt. A dict rather than a plain
# module global so the cache is *mutated* rather than rebound — no ``global``
# statement, and therefore no lint suppression, for what is only a memo.
# Both outcomes are cached: retrying a failure once per helper call would mean
# ~39 identical failures and ~39 identical log lines in a single scan.
_ps_resolution: dict[str, str | PowerShellUnavailableError] = {}


def _ps_executable() -> str:
    """Return the cached PowerShell path, resolving it on first use.

    Resolution is deliberately *lazy*. Doing it at import time meant a machine
    without a trusted ``powershell.exe`` raised while ``apotrope.utils`` was
    still being imported — an uncaught traceback that killed ``--dry-run`` and
    exited 1, which the CLI documents as "complete assessment, failing score".

    Raises:
        PowerShellUnavailableError: If the trusted binary cannot be resolved.
    """
    if "exe" not in _ps_resolution:
        try:
            _ps_resolution["exe"] = _powershell_path()
        except ApotropeError as exc:
            _ps_resolution["exe"] = PowerShellUnavailableError(str(exc))
    resolved = _ps_resolution["exe"]
    if isinstance(resolved, PowerShellUnavailableError):
        raise resolved
    return resolved


def _reset_ps_cache() -> None:
    """Clear the cached resolution. For tests; see ``tests/conftest.py``."""
    _ps_resolution.clear()


# Base PowerShell invocation flags shared by every helper
_PS_FLAGS = [
    "-NonInteractive",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
]


def _ps_argv(command: str) -> list[str]:
    """Build the full argv for a PowerShell invocation of *command*."""
    return [_ps_executable(), *_PS_FLAGS, command]


# Force PowerShell to emit UTF-8 so the ``encoding="utf-8"`` decode below is
# correct for localized / non-ASCII output (service names, usernames), instead
# of depending on the host's OEM/ANSI console code page.
_OUTPUT_ENCODING_PREAMBLE = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "


def _child_env() -> dict[str, str]:
    """Environment for powershell.exe children.

    Two adjustments to the inherited environment:

    ``PSModulePath`` is stripped. A PowerShell 7 parent leaves its own Core-only
    module paths there; Windows PowerShell 5.1 then resolves modules that exist
    in both editions (e.g. Microsoft.PowerShell.Security, home of
    ``Get-ExecutionPolicy``) to the PS7 copy and fails to load it. pwsh strips
    its paths when launching powershell.exe itself, but a Python parent passes
    the environment through raw — powershell.exe rebuilds its correct default
    when the variable is absent.

    ``SystemRoot``, ``windir`` and ``PATH`` are pinned to the kernel-reported
    Windows directory. :func:`_powershell_path` goes to some trouble to resolve
    a *trustworthy* binary; handing that binary an attacker-supplied
    ``%SystemRoot%`` and ``%PATH%`` would let the hostile parent redirect what
    the script it runs then loads. Off Windows the values are left alone, since
    the whole path is mocked there.
    """
    env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
    if sys.platform != "win32":
        return env
    try:
        system_root = _system_windows_directory()
    except ApotropeError:
        # Nothing trustworthy to pin to. run_powershell will fail at
        # _ps_executable() anyway; don't mask that with a second error here.
        return env
    env["SystemRoot"] = system_root
    env["windir"] = system_root
    # ntpath and an explicit ';' — this is a Windows PATH, and os.path/os.pathsep
    # are the posix flavours on the Linux CI legs where the mocked tests run.
    env["PATH"] = ";".join((
        ntpath.join(system_root, "System32"),
        system_root,
        ntpath.join(system_root, "System32", "Wbem"),
        ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0"),
    ))
    return env


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
            _ps_argv(_OUTPUT_ENCODING_PREAMBLE + command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_child_env(),
            check=False,
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
        # json.loads is typed Any; the declared return type is the contract.
        return cast("dict | list", json.loads(output))
    except json.JSONDecodeError as exc:
        raise ApotropeError(
            f"Failed to parse PowerShell JSON output: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# PowerShell string-literal escaping
# ---------------------------------------------------------------------------


def _ps_single_quote(value: str) -> str:
    """Escape a string for safe interpolation inside a single-quoted PowerShell literal.

    PowerShell escapes a single quote inside a single-quoted string by doubling it
    (``'`` -> ``''``). Apply this to any caller-supplied value (registry paths, value
    names, WMI class/namespace, property names) before building a command string, so a
    stray quote cannot break out of the literal and inject PowerShell. The structured
    helpers below build scripts from typed arguments and are the right chokepoint for
    this; ``run_powershell`` itself intentionally does not escape — it is the raw runner.
    """
    return value.replace("'", "''")


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

    ps_path = _ps_single_quote(f"{hive_upper}:\\{path}")
    safe_value = _ps_single_quote(value_name)
    # Emit nothing (exit 0) when key/value is absent; print the value otherwise
    script = (
        f"$p = Get-ItemProperty -LiteralPath '{ps_path}' "
        f"-Name '{safe_value}' -ErrorAction SilentlyContinue; "
        f"if ($null -ne $p) {{ $p.'{safe_value}' }}"
    )

    try:
        output = run_powershell(script)
    except PowerShellUnavailableError:
        # No PowerShell at all: every read would fail identically. Returning
        # None here would read as "value not set" and produce a confident
        # verdict from no data, so let it propagate.
        raise
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
    if properties:
        # Quote each property name so it is a literal Select-Object argument and any
        # quote in a (future, caller-supplied) name cannot break out of the literal.
        select = ", ".join(f"'{_ps_single_quote(p)}'" for p in properties)
    else:
        select = "*"
    safe_class = _ps_single_quote(wmi_class)
    safe_namespace = _ps_single_quote(namespace)
    script = (
        f"Get-CimInstance -ClassName '{safe_class}' -Namespace '{safe_namespace}' "
        f"| Select-Object {select} "
        f"| ConvertTo-Json -Depth 3 -Compress"
    )

    try:
        output = run_powershell(script)
    except PowerShellUnavailableError:
        # See read_registry: [] would read as "no instances found".
        raise
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
# Local password policy (netapi32)
# ---------------------------------------------------------------------------

# NetUserModalsGet reads the local SAM's password policy. It is the API that
# `net accounts` itself wraps, and it matters here for two reasons:
#
#   * it is readable by a **standard user**, where `secedit /export` is not —
#     secedit reads %windir%\security\database\secedit.sdb, which is ACL'd to
#     SYSTEM and Administrators only, so the documented non-elevated invocation
#     can never use it; and
#   * it returns **integers**, not the localized text `net accounts` prints, so
#     it survives non-English Windows — which is the whole reason the check
#     stopped parsing `net accounts` in the first place.
#
# It does NOT expose PasswordComplexity; that is an LSA policy setting with no
# field in any USER_MODALS_INFO level. Callers must not synthesise one.


class _UserModals0(ctypes.Structure):
    """``USER_MODALS_INFO_0`` — password length, ages, and history depth."""

    _fields_ = (
        ("min_passwd_len", ctypes.c_uint32),
        ("max_passwd_age", ctypes.c_uint32),
        ("min_passwd_age", ctypes.c_uint32),
        ("force_logoff", ctypes.c_uint32),
        ("password_hist_len", ctypes.c_uint32),
    )


class _UserModals3(ctypes.Structure):
    """``USER_MODALS_INFO_3`` — account lockout.

    All three fields are ``DWORD``. Declaring the two durations wider does not
    fail: the call still returns success and the struct is simply misread, so
    the error surfaces as plausible-looking garbage rather than an exception.
    Both durations are in **seconds**; the secedit INF expresses them in
    minutes, which is why :func:`read_password_policy` converts.
    """

    _fields_ = (
        ("lockout_duration", ctypes.c_uint32),
        ("lockout_observation_window", ctypes.c_uint32),
        ("lockout_threshold", ctypes.c_uint32),
    )


# TIMEQ_FOREVER: "never expires" / "until an administrator unlocks". The secedit
# INF spells the same thing -1, and the evaluators read INF conventions.
_TIMEQ_FOREVER = 0xFFFFFFFF


def _query_user_modals(level: int, struct_type: type[ctypes.Structure]) -> ctypes.Structure:
    """Call ``NetUserModalsGet`` for *level* and return a copy of the struct.

    The buffer is always released with ``NetApiBufferFree``; the copy is taken
    first so the returned object does not point into freed memory.

    Raises:
        ApotropeError: Off Windows, or when the call returns a non-zero status.
    """
    if sys.platform != "win32":
        raise ApotropeError("NetUserModalsGet is Windows-only")
    netapi32 = ctypes.WinDLL("netapi32", use_last_error=True)
    get_modals = netapi32.NetUserModalsGet
    # servername NULL = this machine. bufptr is an out-param the API allocates.
    get_modals.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p))
    get_modals.restype = ctypes.c_uint32
    free_buffer = netapi32.NetApiBufferFree
    free_buffer.argtypes = (ctypes.c_void_p,)
    free_buffer.restype = ctypes.c_uint32

    buf = ctypes.c_void_p()
    status = get_modals(None, level, ctypes.byref(buf))
    if status != 0:
        raise ApotropeError(
            f"NetUserModalsGet(level={level}) failed with status {status}"
        )
    try:
        # copy(): the struct lives in the API-allocated buffer freed below.
        return struct_type.from_buffer_copy(
            ctypes.cast(buf, ctypes.POINTER(struct_type)).contents
        )
    finally:
        free_buffer(buf)


def read_password_policy() -> dict[str, str]:
    """Read the local password policy, keyed like a parsed secedit INF.

    Returns the same lowercase ``key -> str`` shape that a ``secedit /export``
    INF parses to, so a caller can feed either source to the same evaluators.
    Durations are converted from the API's seconds to the INF's minutes.

    ``PasswordComplexity`` is deliberately absent — see the module comment
    above. A caller must report that control as unmeasurable rather than
    inferring a value.

    Raises:
        ApotropeError: Off Windows, or when either query fails.
    """
    modals0 = cast("_UserModals0", _query_user_modals(0, _UserModals0))
    modals3 = cast("_UserModals3", _query_user_modals(3, _UserModals3))

    def _minutes(seconds: int) -> str:
        # The INF writes -1 for "forever"; preserve that rather than emitting a
        # 71-million-minute duration that would read as a real threshold.
        if seconds == _TIMEQ_FOREVER:
            return "-1"
        return str(seconds // 60)

    return {
        "minimumpasswordlength": str(modals0.min_passwd_len),
        "passwordhistorysize": str(modals0.password_hist_len),
        "lockoutbadcount": str(modals3.lockout_threshold),
        "lockoutduration": _minutes(modals3.lockout_duration),
        "resetlockoutcount": _minutes(modals3.lockout_observation_window),
    }


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
    except (AttributeError, OSError):
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
