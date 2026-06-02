"""Tests for apotrope.checks.smb."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import smb
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _data(smb1=False, require_signing=True, enable_signing=True, encrypt=False):
    """Return a dict mirroring Get-SmbServerConfiguration output."""
    return {
        "EnableSMB1Protocol": smb1,
        "RequireSecuritySignature": require_signing,
        "EnableSecuritySignature": enable_signing,
        "EncryptData": encrypt,
    }


# ---------------------------------------------------------------------------
# _check_smb1
# ---------------------------------------------------------------------------

class TestCheckSmb1:
    def _run(self, data):
        return smb._check_smb1(data)

    def test_smb1_disabled_is_pass(self):
        r = self._run(_data(smb1=False))[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.CRITICAL

    def test_smb1_enabled_is_fail(self):
        r = self._run(_data(smb1=True))[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.CRITICAL
        assert "EternalBlue" in r.description

    def test_smb1_enabled_has_remediation(self):
        r = self._run(_data(smb1=True))[0]
        assert "Set-SmbServerConfiguration" in r.remediation

    def test_null_value_is_warn(self):
        r = smb._check_smb1({"EnableSMB1Protocol": None})[0]
        assert r.status == Status.WARN

    def test_check_name(self):
        r = self._run(_data())[0]
        assert r.check_name == "SMBv1 Disabled"


# ---------------------------------------------------------------------------
# _check_smb_signing
# ---------------------------------------------------------------------------

class TestCheckSmbSigning:
    def _run(self, data):
        return smb._check_smb_signing(data)

    def test_required_is_pass(self):
        r = self._run(_data(require_signing=True))[0]
        assert r.status == Status.PASS

    def test_enabled_not_required_is_warn(self):
        r = self._run(_data(require_signing=False, enable_signing=True))[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.HIGH

    def test_neither_enabled_nor_required_is_fail(self):
        r = self._run(_data(require_signing=False, enable_signing=False))[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.HIGH

    def test_fail_has_both_commands_in_remediation(self):
        r = self._run(_data(require_signing=False, enable_signing=False))[0]
        assert "EnableSecuritySignature" in r.remediation
        assert "RequireSecuritySignature" in r.remediation

    def test_null_required_is_warn(self):
        r = smb._check_smb_signing({"RequireSecuritySignature": None})[0]
        assert r.status == Status.WARN


# ---------------------------------------------------------------------------
# _check_smb_encryption
# ---------------------------------------------------------------------------

class TestCheckSmbEncryption:
    def _run(self, data):
        return smb._check_smb_encryption(data)

    def test_encryption_enabled_is_pass(self):
        r = self._run(_data(encrypt=True))[0]
        assert r.status == Status.PASS

    def test_encryption_disabled_is_info(self):
        r = self._run(_data(encrypt=False))[0]
        assert r.status == Status.INFO

    def test_encryption_disabled_has_remediation(self):
        r = self._run(_data(encrypt=False))[0]
        assert "Set-SmbServerConfiguration" in r.remediation

    def test_null_value_is_info(self):
        r = smb._check_smb_encryption({"EncryptData": None})[0]
        assert r.status == Status.INFO


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_three_results_on_good_config(self):
        good = _data(smb1=False, require_signing=True, enable_signing=True, encrypt=True)
        with patch("apotrope.checks.smb.run_powershell_json", return_value=good):
            results = smb.run()
        assert len(results) == 3
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_returns_all_passes_on_good_config(self):
        good = _data(smb1=False, require_signing=True, enable_signing=True, encrypt=True)
        with patch("apotrope.checks.smb.run_powershell_json", return_value=good):
            results = smb.run()
        non_pass = [r for r in results if r.status not in (Status.PASS, Status.INFO)]
        assert non_pass == []

    def test_run_handles_powershell_error(self):
        with patch("apotrope.checks.smb.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            results = smb.run()
        assert results[0].status == Status.ERROR

    def test_run_wraps_list_data(self):
        good = [_data()]
        with patch("apotrope.checks.smb.run_powershell_json", return_value=good):
            results = smb.run()
        assert len(results) == 3
