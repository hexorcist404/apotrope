"""Tests for apotrope.utils.

All subprocess.run calls are mocked so the suite runs on any platform.
"""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from apotrope.exceptions import ApotropeError
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
            assert "Get-Date" in args

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

    def test_empty_output_raises(self):
        with patch("apotrope.utils.subprocess.run", return_value=_mock_ps("")):
            with pytest.raises(ApotropeError, match="empty output"):
                utils.run_powershell_json("Get-Nothing | ConvertTo-Json")

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
            result = utils.read_registry("HKLM", "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1")
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
        with patch.object(sys, "platform", "linux"):
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
        with patch.object(sys, "platform", "linux"):
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
