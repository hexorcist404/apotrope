"""Tests for apotrope.checks.uac."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import uac
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _data(lua=1, admin_behavior=5, user_behavior=3, secure_desktop=1, virt=1):
    """Return a dict mirroring the UAC registry values PowerShell call."""
    return {
        "EnableLUA": lua,
        "ConsentPromptBehaviorAdmin": admin_behavior,
        "ConsentPromptBehaviorUser": user_behavior,
        "PromptOnSecureDesktop": secure_desktop,
        "EnableVirtualization": virt,
    }


# ---------------------------------------------------------------------------
# _check_uac_enabled
# ---------------------------------------------------------------------------

class TestCheckUacEnabled:
    def test_uac_enabled_is_pass(self):
        r = uac._check_uac_enabled(_data(lua=1))[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.CRITICAL

    def test_uac_disabled_is_fail(self):
        r = uac._check_uac_enabled(_data(lua=0))[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.CRITICAL
        assert "EnableLUA" in r.command

    def test_uac_disabled_reboot_command_is_commented(self):
        # The EnableLUA fix requires a reboot, but a bare Restart-Computer must
        # not restart the machine the moment the block is pasted.
        r = uac._check_uac_enabled(_data(lua=0))[0]
        active = [ln for ln in r.command.splitlines()
                  if not ln.strip().startswith("#")]
        assert not any("Restart-Computer" in ln for ln in active)

    def test_uac_absent_is_warn(self):
        r = uac._check_uac_enabled({})[0]
        assert r.status == Status.WARN

    def test_uac_enabled_no_remediation(self):
        r = uac._check_uac_enabled(_data(lua=1))[0]
        assert r.remediation == ""


# ---------------------------------------------------------------------------
# _check_admin_behavior
# ---------------------------------------------------------------------------

class TestCheckAdminBehavior:
    def test_level_0_silent_is_warn(self):
        r = uac._check_admin_behavior(_data(admin_behavior=0))[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.HIGH
        assert "silent" in r.details.lower()

    def test_level_2_secure_desktop_is_pass(self):
        r = uac._check_admin_behavior(_data(admin_behavior=2))[0]
        assert r.status == Status.PASS

    def test_level_5_default_is_pass(self):
        r = uac._check_admin_behavior(_data(admin_behavior=5))[0]
        assert r.status == Status.PASS

    def test_absent_key_is_info(self):
        r = uac._check_admin_behavior({})[0]
        assert r.status == Status.INFO
        assert "default" in r.details.lower()

    def test_warn_has_remediation(self):
        r = uac._check_admin_behavior(_data(admin_behavior=0))[0]
        assert "ConsentPromptBehaviorAdmin" in r.command

    def test_level_description_in_details(self):
        r = uac._check_admin_behavior(_data(admin_behavior=2))[0]
        assert "2" in r.details


# ---------------------------------------------------------------------------
# _check_secure_desktop
# ---------------------------------------------------------------------------

class TestCheckSecureDesktop:
    def test_secure_desktop_on_is_pass(self):
        r = uac._check_secure_desktop(_data(secure_desktop=1))[0]
        assert r.status == Status.PASS

    def test_secure_desktop_off_is_warn(self):
        r = uac._check_secure_desktop(_data(secure_desktop=0))[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM
        assert "spoof" in r.details.lower()

    def test_absent_key_is_info(self):
        r = uac._check_secure_desktop({})[0]
        assert r.status == Status.INFO

    def test_off_has_remediation(self):
        r = uac._check_secure_desktop(_data(secure_desktop=0))[0]
        assert "PromptOnSecureDesktop" in r.command


# ---------------------------------------------------------------------------
# _check_user_behavior
# ---------------------------------------------------------------------------

class TestCheckUserBehavior:
    def test_level_3_default_is_info(self):
        r = uac._check_user_behavior(_data(user_behavior=3))[0]
        assert r.status == Status.INFO
        assert r.severity == Severity.LOW

    def test_level_0_deny_all_is_info(self):
        r = uac._check_user_behavior(_data(user_behavior=0))[0]
        assert r.status == Status.INFO

    def test_absent_key_is_info(self):
        r = uac._check_user_behavior({})[0]
        assert r.status == Status.INFO

    def test_unknown_value_shown_in_details(self):
        r = uac._check_user_behavior(_data(user_behavior=99))[0]
        assert "99" in r.details


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_four_results_on_normal_config(self):
        with patch("apotrope.checks.uac.run_powershell_json", return_value=_data()):
            results = uac.run()
        assert len(results) == 4
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_returns_all_non_fail_on_good_config(self):
        with patch("apotrope.checks.uac.run_powershell_json", return_value=_data()):
            results = uac.run()
        fail_results = [r for r in results if r.status == Status.FAIL]
        assert fail_results == []

    def test_run_handles_powershell_error(self):
        with patch("apotrope.checks.uac.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = uac.run()
        assert len(results) == 1
        assert results[0].status == Status.ERROR

    def test_run_wraps_list_data(self):
        with patch("apotrope.checks.uac.run_powershell_json", return_value=[_data()]):
            results = uac.run()
        assert len(results) == 4

    def test_uac_disabled_scan_includes_fail(self):
        with patch("apotrope.checks.uac.run_powershell_json",
                   return_value=_data(lua=0)):
            results = uac.run()
        statuses = {r.check_name: r.status for r in results}
        assert statuses["UAC Enabled"] == Status.FAIL
