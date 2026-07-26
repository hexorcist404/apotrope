"""Tests for apotrope.utils.

All subprocess.run calls are mocked so the suite runs on any platform.
"""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from apotrope.exceptions import ApotropeError, PowerShellUnavailableError
from apotrope import utils


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_ps(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    """Return a mock CompletedProcess-like object."""
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


# ---------------------------------------------------------------------------
# run_powershell
# ---------------------------------------------------------------------------


class TestRunPowershell:
    def test_returns_stripped_stdout(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("  hello  ")):
            assert utils.run_powershell("echo hello") == "hello"

    def test_passes_correct_flags(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("ok")) as mock_run:
            utils.run_powershell("Get-Date")
            args = mock_run.call_args[0][0]
            assert "-NonInteractive" in args
            assert "-NoProfile" in args
            assert "-ExecutionPolicy" in args
            assert "Bypass" in args
            # The command rides in the last argument (behind the UTF-8 preamble).
            assert any("Get-Date" in a for a in args)

    def test_nonzero_exit_raises_apotrope_error(self):
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="Access denied"),
        ):
            with pytest.raises(ApotropeError, match="PowerShell exited 1"):
                utils.run_powershell("some-command")

    def test_stderr_included_in_error(self):
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="Some specific error text"),
        ):
            with pytest.raises(ApotropeError, match="Some specific error text"):
                utils.run_powershell("bad-command")

    def test_timeout_raises_apotrope_error(self):
        with patch(
            "apotrope.utils.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=30),
        ):
            with pytest.raises(ApotropeError, match="timed out after 30s"):
                utils.run_powershell("Start-Sleep 999")

    def test_powershell_not_found_raises_apotrope_error(self):
        with patch(
            "apotrope.utils.subprocess.run",
            side_effect=FileNotFoundError("powershell.exe not found"),
        ):
            with pytest.raises(ApotropeError, match="powershell.exe not found"):
                utils.run_powershell("anything")

    def test_empty_output_returns_empty_string(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            assert utils.run_powershell("Write-Host ''") == ""

    def test_logs_command_at_debug(self, caplog):
        import logging
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("out")):
            with caplog.at_level(logging.DEBUG, logger="apotrope.utils"):
                utils.run_powershell("Get-Process")
        assert "Get-Process" in caplog.text

    def test_long_command_truncated_in_log(self, caplog):
        import logging
        long_cmd = "X" * 500
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("out")):
            with caplog.at_level(logging.DEBUG, logger="apotrope.utils"):
                utils.run_powershell(long_cmd)
        # The log message should be truncated to 200 chars, not the full 500
        log_entry = next(r for r in caplog.records if "apotrope.utils" in r.name)
        assert len(log_entry.getMessage()) < len(long_cmd)

    def test_custom_timeout_passed_to_subprocess(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("ok")) as mock_run:
            utils.run_powershell("Get-Date", timeout=5)
            _, kwargs = mock_run.call_args
            assert kwargs["timeout"] == 5

    def test_psmodulepath_stripped_from_child_env(self):
        # Only asserts the platform-independent half of _child_env's contract.
        # PATH is deliberately NOT asserted here: on Windows it is pinned to the
        # kernel-reported system directory, so an equality check against the
        # inherited value passes on Linux and fails on the Windows matrix legs.
        # Both branches are pinned explicitly in the platform-specific tests below.
        polluted = {
            "PSModulePath": r"C:\Program Files\PowerShell\7\Modules",
            "PATH": r"C:\Windows\System32",
        }
        with patch.dict("apotrope.utils.os.environ", polluted, clear=True):
            with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("ok")) as mock_run:
                utils.run_powershell("Get-Date")
                _, kwargs = mock_run.call_args
        env = kwargs["env"]
        assert not any(k.lower() == "psmodulepath" for k in env)

    def test_child_env_pins_systemroot_and_path_on_windows(self):
        """A trustworthy binary handed an attacker-supplied %SystemRoot% is not safe."""
        hostile = {"SystemRoot": r"C:\Evil", "windir": r"C:\Evil", "PATH": r"C:\Evil"}
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils._system_windows_directory", return_value=r"C:\Windows"),
            patch.dict("apotrope.utils.os.environ", hostile, clear=True),
        ):
            env = utils._child_env()
        assert env["SystemRoot"] == r"C:\Windows"
        assert env["windir"] == r"C:\Windows"
        assert "Evil" not in env["PATH"]
        assert env["PATH"].startswith("C:\\Windows\\System32")

    def test_child_env_left_alone_off_windows(self):
        with (
            patch.object(utils.sys, "platform", "linux"),
            patch.dict("apotrope.utils.os.environ", {"PATH": "/usr/bin"}, clear=True),
        ):
            assert utils._child_env()["PATH"] == "/usr/bin"

    def test_child_env_degrades_when_windows_dir_unreadable(self):
        """Don't mask the real failure with a second one — _ps_executable reports it."""
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch(
                "apotrope.utils._system_windows_directory",
                side_effect=ApotropeError("nope"),
            ),
            patch.dict("apotrope.utils.os.environ", {"PATH": r"C:\X"}, clear=True),
        ):
            assert utils._child_env()["PATH"] == r"C:\X"


class TestPowershellExecutable:
    """powershell.exe is resolved to a trusted absolute path (no PATH/CWD hijack)."""

    def test_resolves_system32_path_on_windows(self):
        def _isfile(p):
            return "System32" in p and p.endswith("powershell.exe")
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils._system_windows_directory", return_value=r"C:\FakeWin"),
            patch("apotrope.utils.os.path.isfile", side_effect=_isfile),
        ):
            path = utils._powershell_path()
        assert "System32" in path
        assert path.endswith("powershell.exe")

    def test_prefers_sysnative_when_present(self):
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils._system_windows_directory", return_value=r"C:\FakeWin"),
            patch("apotrope.utils.os.path.isfile", side_effect=lambda p: "Sysnative" in p),
        ):
            assert "Sysnative" in utils._powershell_path()

    def test_fails_closed_when_binary_missing_on_windows(self):
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils._system_windows_directory", return_value=r"C:\FakeWin"),
            patch("apotrope.utils.os.path.isfile", return_value=False),
        ):
            with pytest.raises(ApotropeError, match="Trusted powershell.exe not found"):
                utils._powershell_path()

    def test_windows_directory_comes_from_win32_not_the_environment(self):
        """%SystemRoot% is attacker-controllable; it must not steer resolution."""
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch.dict("apotrope.utils.os.environ", {"SystemRoot": r"C:\Evil"}),
            patch("apotrope.utils._system_windows_directory", return_value=r"C:\FakeWin"),
            patch("apotrope.utils.os.path.isfile", return_value=True),
        ):
            path = utils._powershell_path()
        assert path.startswith(r"C:\FakeWin")
        assert "Evil" not in path

    def test_bare_name_off_windows(self):
        with patch.object(utils.sys, "platform", "linux"):
            assert utils._powershell_path() == "powershell.exe"


class TestSystemWindowsDirectory:
    """GetSystemWindowsDirectoryW must be called correctly and fail closed.

    A mishandled return value yields an empty buffer, hence the *relative* path
    ``System32\\...\\powershell.exe`` — which os.path.isfile then resolves
    against the CWD, reinstating the hijack the helper exists to prevent.
    """

    @staticmethod
    def _windll(path: str | None):
        """kernel32 stub faithful to the documented GetSystemWindowsDirectoryW contract.

        Copies *path* and returns its length when it fits; otherwise copies
        nothing and returns the required size *including* the null terminator.
        Pass ``path=None`` to model outright API failure (returns 0).
        """
        calls = []

        def _fn(buf, size):
            calls.append((buf, size))
            if path is None:
                return 0
            if len(path) + 1 > size:
                return len(path) + 1      # required size, nothing copied
            buf.value = path
            return len(path)

        windll = MagicMock()
        windll.GetSystemWindowsDirectoryW = _fn
        return windll, calls

    def _run(self, windll):
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils.ctypes.WinDLL", return_value=windll, create=True),
        ):
            return utils._system_windows_directory()

    def test_returns_the_reported_directory(self):
        windll, _ = self._windll(r"C:\Windows")
        assert self._run(windll) == r"C:\Windows"

    def test_buffer_size_is_passed_in_wchars_not_bytes(self):
        """uSize is TCHARs; sizeof() would claim double and risk a heap overflow."""
        windll, calls = self._windll(r"C:\Windows")
        self._run(windll)
        _, size = calls[0]
        assert size == utils._MAX_PATH        # 260, not 520

    def test_raises_when_api_returns_zero(self):
        windll, _ = self._windll(None)
        with pytest.raises(ApotropeError, match="GetSystemWindowsDirectoryW failed"):
            self._run(windll)

    def test_retries_once_when_buffer_too_small(self):
        long_path = "C:\\" + "W" * 300        # longer than MAX_PATH
        windll, calls = self._windll(long_path)
        assert self._run(windll) == long_path
        assert len(calls) == 2
        assert calls[1][1] == len(long_path) + 1   # resized to the size asked for

    def test_raises_on_a_relative_path(self):
        """An empty/relative result would build a CWD-relative powershell path."""
        windll, _ = self._windll("Windows")
        with pytest.raises(ApotropeError, match="relative path"):
            self._run(windll)


class TestPowerShellResolutionCache:
    """Resolution is lazy and cached; failure must not silently fail open."""

    def test_resolution_is_lazy_and_cached(self):
        with patch("apotrope.utils._powershell_path", return_value="ps.exe") as resolve:
            utils._ps_executable()
            utils._ps_executable()
        resolve.assert_called_once()

    def test_failure_is_cached_not_retried(self):
        boom = ApotropeError("no powershell")
        with patch("apotrope.utils._powershell_path", side_effect=boom) as resolve:
            for _ in range(3):
                with pytest.raises(PowerShellUnavailableError):
                    utils._ps_executable()
        resolve.assert_called_once()

    def test_read_registry_reraises_rather_than_returning_none(self):
        """None would read as 'value not set' and produce a verdict from no data."""
        with patch(
            "apotrope.utils.run_powershell",
            side_effect=PowerShellUnavailableError("no powershell"),
        ):
            with pytest.raises(PowerShellUnavailableError):
                utils.read_registry("HKLM", "SOFTWARE\\X", "Y")

    def test_get_wmi_object_reraises_rather_than_returning_empty(self):
        with patch(
            "apotrope.utils.run_powershell",
            side_effect=PowerShellUnavailableError("no powershell"),
        ):
            with pytest.raises(PowerShellUnavailableError):
                utils.get_wmi_object("Win32_Service")

    def test_ordinary_failures_still_degrade(self):
        """A per-query failure is not a total one — the old behaviour stands."""
        with patch("apotrope.utils.run_powershell", side_effect=ApotropeError("denied")):
            assert utils.read_registry("HKLM", "SOFTWARE\\X", "Y") is None
            assert utils.get_wmi_object("Win32_Service") == []


class TestSubprocessDecoding:
    def test_decodes_utf8_and_forces_ps_utf8_output(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("ok")) as mock_run:
            utils.run_powershell("Get-Thing")
        _, kwargs = mock_run.call_args
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        # PS is told to emit UTF-8 so the decode above is correct for non-ASCII.
        assert "OutputEncoding" in mock_run.call_args[0][0][-1]


# ---------------------------------------------------------------------------
# run_powershell_json
# ---------------------------------------------------------------------------


class TestRunPowershellJson:
    def test_parses_json_object(self):
        payload = json.dumps({"Name": "Defender", "Enabled": True})
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.run_powershell_json("... | ConvertTo-Json")
        assert result == {"Name": "Defender", "Enabled": True}

    def test_parses_json_array(self):
        payload = json.dumps([{"Port": 80}, {"Port": 443}])
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.run_powershell_json("... | ConvertTo-Json")
        assert result == [{"Port": 80}, {"Port": 443}]

    def test_empty_output_returns_empty_list(self):
        # Zero pipeline objects -> empty stdout is a valid "no rows" result,
        # not an error: the helper returns [] so callers' "none found" paths
        # stay reachable (test_malformed_json_raises covers real bad JSON).
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            result = utils.run_powershell_json("Get-Nothing | ConvertTo-Json")
        assert result == []

    def test_malformed_json_raises(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("{not valid json}")):
            with pytest.raises(ApotropeError, match="Failed to parse"):
                utils.run_powershell_json("some-command")

    def test_powershell_failure_propagates(self):
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="Access is denied"),
        ):
            with pytest.raises(ApotropeError, match="Access is denied"):
                utils.run_powershell_json("Get-Something | ConvertTo-Json")

    def test_single_item_array(self):
        payload = json.dumps([{"Key": "Value"}])
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.run_powershell_json("cmd")
        assert result == [{"Key": "Value"}]

    def test_nested_json(self):
        payload = json.dumps({"outer": {"inner": [1, 2, 3]}})
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.run_powershell_json("cmd")
        assert result["outer"]["inner"] == [1, 2, 3]


# ---------------------------------------------------------------------------
# read_registry
# ---------------------------------------------------------------------------


class TestReadRegistry:
    def test_returns_string_value(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("Windows 11 Pro")):
            result = utils.read_registry("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
        assert result == "Windows 11 Pro"

    def test_returns_integer_when_value_is_numeric(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("1")):
            result = utils.read_registry(
                "HKLM", "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1"
            )
        assert result == 1
        assert isinstance(result, int)

    def test_returns_none_for_missing_key(self):
        # PS emits empty output when key doesn't exist
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            result = utils.read_registry("HKLM", "SOFTWARE\\DoesNotExist", "Value")
        assert result is None

    def test_returns_none_on_ps_error(self):
        # Access denied scenario — PS exits non-zero
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="Access denied"),
        ):
            result = utils.read_registry("HKCU", "SomePath", "SomeValue")
        assert result is None

    def test_unsupported_hive_raises(self):
        with pytest.raises(ApotropeError, match="Unsupported registry hive"):
            utils.read_registry("HKCR", "path", "value")

    def test_hklm_hive_accepted(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("data")):
            assert utils.read_registry("HKLM", "path", "val") == "data"

    def test_hkcu_hive_accepted(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("data")):
            assert utils.read_registry("HKCU", "path", "val") == "data"

    def test_hku_hive_accepted(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("data")):
            assert utils.read_registry("HKU", "path", "val") == "data"

    def test_hive_is_case_insensitive(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("data")):
            assert utils.read_registry("hklm", "path", "val") == "data"

    def test_zero_value_returns_int_zero(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("0")):
            result = utils.read_registry("HKLM", "path", "val")
        assert result == 0
        assert isinstance(result, int)

    def test_ps_path_built_correctly(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")) as mock_run:
            utils.read_registry("HKLM", "SOFTWARE\\Test", "MyValue")
            called_command = mock_run.call_args[0][0][-1]
        assert "HKLM:\\SOFTWARE\\Test" in called_command
        assert "MyValue" in called_command

    def test_single_quotes_in_path_and_value_are_escaped(self):
        """A quote in the path or value name is doubled so it can't break out of the PS literal."""
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")) as mock_run:
            utils.read_registry("HKLM", "SOFTWARE\\It's", "Quote'Name")
            called_command = mock_run.call_args[0][0][-1]
        assert "It''s" in called_command
        assert "Quote''Name" in called_command
        # no single (un-doubled) quote sequence survives in the interpolated value
        assert "Quote'Name" not in called_command


# ---------------------------------------------------------------------------
# get_wmi_object
# ---------------------------------------------------------------------------


class TestGetWmiObject:
    def test_returns_list_of_dicts_for_array(self):
        payload = json.dumps([
            {"Caption": "Windows 11 Pro", "BuildNumber": "22621"},
            {"Caption": "Windows 11 Pro", "BuildNumber": "22621"},
        ])
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.get_wmi_object("Win32_OperatingSystem")
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["Caption"] == "Windows 11 Pro"

    def test_wraps_single_dict_in_list(self):
        """PS ConvertTo-Json emits a bare object when only one instance exists."""
        payload = json.dumps({"Caption": "Windows 11 Pro", "BuildNumber": "22621"})
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)):
            result = utils.get_wmi_object("Win32_OperatingSystem")
        assert isinstance(result, list)
        assert len(result) == 1

    def test_returns_empty_list_on_ps_error(self):
        """Access denied or class-not-found: return [] not raise."""
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="Access is denied"),
        ):
            result = utils.get_wmi_object("Win32_Tpm")
        assert result == []

    def test_returns_empty_list_on_empty_output(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            result = utils.get_wmi_object("Win32_SomethingEmpty")
        assert result == []

    def test_returns_empty_list_on_invalid_json(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("not json at all")):
            result = utils.get_wmi_object("Win32_BadOutput")
        assert result == []

    def test_property_filter_included_in_script(self):
        payload = json.dumps([{"Name": "svchost"}])
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)) as mock_run:
            utils.get_wmi_object("Win32_Process", properties=["Name", "ProcessId"])
            called_command = mock_run.call_args[0][0][-1]
        assert "Name" in called_command
        assert "ProcessId" in called_command

    def test_custom_namespace(self):
        payload = json.dumps({"IsActivated_InitialValue": True})
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps(payload)) as mock_run:
            utils.get_wmi_object("SoftwareLicensingProduct", namespace="root\\cimv2")
            called_command = mock_run.call_args[0][0][-1]
        assert "root\\cimv2" in called_command

    def test_single_quotes_in_class_and_properties_are_escaped(self):
        """Quotes in the class name or a property name are doubled so they can't break the literal."""
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")) as mock_run:
            utils.get_wmi_object("Win32_O'Brien", properties=["Wei'rd", "Name"])
            called_command = mock_run.call_args[0][0][-1]
        assert "Win32_O''Brien" in called_command
        assert "Wei''rd" in called_command

    def test_class_not_found_returns_empty_list(self):
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps(
                "", returncode=1, stderr="Invalid class \"Win32_NoSuchClass\""
            ),
        ):
            result = utils.get_wmi_object("Win32_NoSuchClass")
        assert result == []


# ---------------------------------------------------------------------------
# is_admin
# ---------------------------------------------------------------------------


class TestIsAdmin:
    def test_returns_false_on_non_windows(self):
        with patch.object(utils.sys, "platform", "linux"):
            assert utils.is_admin() is False

    def test_returns_false_on_darwin(self):
        with patch.object(sys, "platform", "darwin"):
            assert utils.is_admin() is False

    def test_returns_true_when_ctypes_reports_admin(self):
        with patch.object(sys, "platform", "win32"):
            mock_windll = MagicMock()
            mock_windll.shell32.IsUserAnAdmin.return_value = 1
            with patch("apotrope.utils.ctypes.windll", mock_windll, create=True):
                assert utils.is_admin() is True

    def test_returns_false_when_ctypes_reports_non_admin(self):
        with patch.object(sys, "platform", "win32"):
            mock_windll = MagicMock()
            mock_windll.shell32.IsUserAnAdmin.return_value = 0
            with patch("apotrope.utils.ctypes.windll", mock_windll, create=True):
                assert utils.is_admin() is False

    def test_returns_false_when_ctypes_raises(self):
        with patch.object(sys, "platform", "win32"):
            mock_windll = MagicMock()
            mock_windll.shell32.IsUserAnAdmin.side_effect = OSError("access denied")
            with patch("apotrope.utils.ctypes.windll", mock_windll, create=True):
                assert utils.is_admin() is False


# ---------------------------------------------------------------------------
# require_windows
# ---------------------------------------------------------------------------


class TestRequireWindows:
    def test_raises_on_linux(self):
        with patch.object(utils.sys, "platform", "linux"):
            with pytest.raises(ApotropeError, match="requires Windows"):
                utils.require_windows()

    def test_raises_on_darwin(self):
        with patch.object(sys, "platform", "darwin"):
            with pytest.raises(ApotropeError, match="requires Windows"):
                utils.require_windows()

    def test_error_includes_platform_name(self):
        with patch.object(sys, "platform", "freebsd"):
            with pytest.raises(ApotropeError, match="freebsd"):
                utils.require_windows()

    def test_passes_on_win32(self):
        with patch.object(sys, "platform", "win32"):
            utils.require_windows()  # must not raise


# ---------------------------------------------------------------------------
# ps_bool
# ---------------------------------------------------------------------------


class TestPsBool:
    def test_true_string_returns_true(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("True")):
            assert utils.ps_bool("some-command") is True

    def test_false_string_returns_false(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("False")):
            assert utils.ps_bool("some-command") is False

    def test_case_insensitive_true(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("TRUE")):
            assert utils.ps_bool("some-command") is True

    def test_unexpected_output_returns_false(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("1")):
            assert utils.ps_bool("some-command") is False

    def test_empty_output_returns_false(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            assert utils.ps_bool("some-command") is False

    def test_ps_failure_propagates(self):
        with patch(
            "apotrope.utils.subprocess.run",
            return_value=_mock_ps("", returncode=1, stderr="err"),
        ):
            with pytest.raises(ApotropeError):
                utils.ps_bool("broken-command")


# ---------------------------------------------------------------------------
# get_wmi_object — scalar JSON payload fallback
# ---------------------------------------------------------------------------

class TestGetWmiObjectScalarJson:
    def test_scalar_json_returns_empty_list(self):
        with patch("apotrope.utils.run_powershell", return_value="42"):
            assert utils.get_wmi_object("Win32_Weird") == []


# ---------------------------------------------------------------------------
# read_password_policy / NetUserModalsGet
# ---------------------------------------------------------------------------

class TestUserModalsStructs:
    """Field widths are load-bearing and fail silently if wrong.

    ``NetUserModalsGet`` returns success regardless of how the caller declares
    the struct, so a too-wide field is not an error — it is plausible-looking
    garbage. (Declaring the two durations as 64-bit produced a lockout duration
    of 7,730,941,134,600 during development, which would have rendered as a
    perfectly straight-faced finding.) These sizes pin the layout.
    """

    def test_modals0_layout(self):
        import ctypes
        assert ctypes.sizeof(utils._UserModals0) == 5 * 4
        assert [n for n, _ in utils._UserModals0._fields_][0] == "min_passwd_len"

    def test_modals3_layout(self):
        import ctypes
        assert ctypes.sizeof(utils._UserModals3) == 3 * 4
        assert [n for n, _ in utils._UserModals3._fields_] == [
            "lockout_duration", "lockout_observation_window", "lockout_threshold",
        ]


class TestReadPasswordPolicy:
    def _query(self, *, min_len=8, hist=5, threshold=10, duration_s=1800, window_s=1800):
        m0 = utils._UserModals0(
            min_passwd_len=min_len, max_passwd_age=0, min_passwd_age=0,
            force_logoff=0, password_hist_len=hist,
        )
        m3 = utils._UserModals3(
            lockout_duration=duration_s,
            lockout_observation_window=window_s,
            lockout_threshold=threshold,
        )
        return lambda level, struct_type: m0 if level == 0 else m3

    def _run(self, **kw):
        with patch.object(utils, "_query_user_modals", self._query(**kw)):
            return utils.read_password_policy()

    def test_keys_match_the_secedit_inf_shape(self):
        # The evaluators are shared with the secedit path, so the fallback must
        # speak the same lowercase INF key names.
        policy = self._run()
        assert policy["minimumpasswordlength"] == "8"
        assert policy["lockoutbadcount"] == "10"

    def test_durations_convert_seconds_to_minutes(self):
        # The API reports seconds; the INF (and therefore the evaluators and the
        # rendered "Duration: N minute(s)") use minutes.
        policy = self._run(duration_s=1800, window_s=900)
        assert policy["lockoutduration"] == "30"
        assert policy["resetlockoutcount"] == "15"

    def test_forever_duration_renders_as_the_inf_sentinel(self):
        # TIMEQ_FOREVER means "until an administrator unlocks". Dividing it by 60
        # would report a 71-million-minute lockout as a real threshold.
        policy = self._run(duration_s=0xFFFFFFFF)
        assert policy["lockoutduration"] == "-1"

    def test_complexity_is_never_synthesised(self):
        # No USER_MODALS_INFO level carries PasswordComplexity. Emitting a key
        # here would let the evaluator render a guess as a real verdict.
        assert "passwordcomplexity" not in self._run()

    def test_values_are_strings(self):
        assert all(isinstance(v, str) for v in self._run().values())


class TestQueryUserModals:
    def test_raises_off_windows(self):
        with patch.object(utils.sys, "platform", "linux"):
            with pytest.raises(ApotropeError, match="Windows-only"):
                utils._query_user_modals(0, utils._UserModals0)

    def test_non_zero_status_raises(self):
        netapi32 = MagicMock()
        netapi32.NetUserModalsGet.return_value = 5  # ERROR_ACCESS_DENIED
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils.ctypes.WinDLL", return_value=netapi32, create=True),
        ):
            with pytest.raises(ApotropeError, match="status 5"):
                utils._query_user_modals(0, utils._UserModals0)
        netapi32.NetApiBufferFree.assert_not_called()

    def test_success_path_copies_then_frees_the_api_buffer(self):
        import ctypes
        source = utils._UserModals3(
            lockout_duration=1800, lockout_observation_window=1800, lockout_threshold=7,
        )

        def _get(_server, _level, bufptr):
            # bufptr is byref(buf); ._obj reaches the c_void_p the caller passed.
            bufptr._obj.value = ctypes.addressof(source)
            return 0

        netapi32 = MagicMock()
        netapi32.NetUserModalsGet.side_effect = _get
        with (
            patch.object(utils.sys, "platform", "win32"),
            patch("apotrope.utils.ctypes.WinDLL", return_value=netapi32, create=True),
        ):
            out = utils._query_user_modals(3, utils._UserModals3)

        assert out.lockout_threshold == 7
        # The buffer is API-allocated; not freeing it leaks once per scan.
        netapi32.NetApiBufferFree.assert_called_once()
        # A copy, not a view into the freed buffer.
        assert ctypes.addressof(out) != ctypes.addressof(source)
