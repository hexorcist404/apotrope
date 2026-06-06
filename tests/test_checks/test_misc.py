"""Tests for apotrope.checks.misc (Hardening category)."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import misc
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# _check_autoplay
# ---------------------------------------------------------------------------

class TestCheckAutoplay:
    def _run(self, output: str):
        with patch("apotrope.checks.misc.run_powershell", return_value=output):
            return misc._check_autoplay()

    def test_fully_disabled_255_is_pass(self):
        r = self._run("255")[0]
        assert r.status == Status.PASS

    def test_not_set_is_warn(self):
        r = self._run("NOTSET")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_partial_disable_is_warn(self):
        r = self._run("91")[0]
        assert r.status == Status.WARN

    def test_zero_is_warn(self):
        r = self._run("0")[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run("NOTSET")[0]
        assert "NoDriveTypeAutoRun" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell",
                   side_effect=ApotropeError("denied")):
            r = misc._check_autoplay()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_winrm
# ---------------------------------------------------------------------------

class TestCheckWinrm:
    def _run(self, output: str):
        with patch("apotrope.checks.misc.run_powershell", return_value=output):
            return misc._check_winrm()

    def test_stopped_is_pass(self):
        r = self._run("Stopped")[0]
        assert r.status == Status.PASS

    def test_running_is_warn(self):
        r = self._run("Running")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_not_found_is_info(self):
        r = self._run("")[0]
        assert r.status == Status.INFO

    def test_running_has_remediation(self):
        r = self._run("Running")[0]
        assert "WinRM" in r.remediation

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell",
                   side_effect=ApotropeError("boom")):
            r = misc._check_winrm()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_spectre
# ---------------------------------------------------------------------------

class TestCheckSpectre:
    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_spectre()

    def test_no_override_key_is_info(self):
        r = self._run({"Override": None, "Mask": None})[0]
        assert r.status == Status.INFO
        assert "default" in r.details.lower()

    def test_mitigations_disabled_is_warn(self):
        # Override & 3 == 3, Mask == 3 → disabled
        r = self._run({"Override": 3, "Mask": 3})[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_mitigations_enabled_via_override_is_info(self):
        # Override = 0, Mask = 3 → mitigations on
        r = self._run({"Override": 0, "Mask": 3})[0]
        assert r.status == Status.INFO

    def test_list_data_wrapped(self):
        r = self._run([{"Override": None, "Mask": None}])[0]
        assert r.status == Status.INFO

    def test_disabled_has_remediation(self):
        r = self._run({"Override": 3, "Mask": 3})[0]
        assert "FeatureSettingsOverride" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            r = misc._check_spectre()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_audit_policy
# ---------------------------------------------------------------------------

class TestCheckAuditPolicy:
    def _entry(self, name: str, setting: str = "Success and Failure") -> dict:
        return {"Subcategory": name, "Inclusion Setting": setting}

    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_audit_policy()

    def test_all_audited_is_pass(self):
        entries = [
            self._entry("Logon", "Success and Failure"),
            self._entry("Credential Validation", "Failure"),
        ]
        r = self._run(entries)[0]
        assert r.status == Status.PASS

    def test_no_auditing_entry_is_warn(self):
        entries = [
            self._entry("Logon", "No Auditing"),
            self._entry("Account Lockout", "Success"),
        ]
        r = self._run(entries)[0]
        assert r.status == Status.WARN
        assert "Logon" in r.details

    def test_empty_list_is_warn(self):
        r = self._run([])[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run([self._entry("Logon", "No Auditing")])[0]
        assert "auditpol" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            r = misc._check_audit_policy()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_screen_lock
# ---------------------------------------------------------------------------

class TestCheckScreenLock:
    def _data(self, active="1", secure="1", timeout=600):
        return {"Active": active, "Secure": secure, "Timeout": timeout}

    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_screen_lock()

    def test_good_config_is_pass(self):
        # 10-minute timeout, password on resume
        r = self._run(self._data(active="1", secure="1", timeout=600))[0]
        assert r.status == Status.PASS

    def test_screensaver_disabled_is_warn(self):
        r = self._run(self._data(active="0"))[0]
        assert r.status == Status.WARN

    def test_timeout_over_15min_is_warn(self):
        r = self._run(self._data(timeout=1200))[0]
        assert r.status == Status.WARN
        assert "exceeds" in r.details.lower()

    def test_exactly_15_min_is_pass(self):
        r = self._run(self._data(timeout=900))[0]
        assert r.status == Status.PASS

    def test_no_password_on_resume_is_warn(self):
        r = self._run(self._data(secure="0", timeout=300))[0]
        assert r.status == Status.WARN

    def test_zero_timeout_is_warn(self):
        r = self._run(self._data(timeout=0))[0]
        assert r.status == Status.WARN

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            r = misc._check_screen_lock()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_five_results(self):
        good_screen = {"Active": "1", "Secure": "1", "Timeout": 600}
        good_spectre = {"Override": None, "Mask": None}
        audit_entries = [{"Subcategory": "Logon", "Inclusion Setting": "Success and Failure"}]
        with (
            patch("apotrope.checks.misc.run_powershell",
                  side_effect=["255", "Stopped"]),
            patch("apotrope.checks.misc.run_powershell_json",
                  side_effect=[good_spectre, audit_entries, good_screen]),
        ):
            results = misc.run()
        assert len(results) == 5
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_category_is_hardening(self):
        good_screen = {"Active": "1", "Secure": "1", "Timeout": 600}
        good_spectre = {"Override": None, "Mask": None}
        audit_entries = [{"Subcategory": "Logon", "Inclusion Setting": "Success"}]
        with (
            patch("apotrope.checks.misc.run_powershell",
                  side_effect=["255", "Stopped"]),
            patch("apotrope.checks.misc.run_powershell_json",
                  side_effect=[good_spectre, audit_entries, good_screen]),
        ):
            results = misc.run()
        assert all(r.category == "Hardening" for r in results)
