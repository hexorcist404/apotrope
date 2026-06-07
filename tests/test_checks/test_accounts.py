"""Tests for apotrope.checks.accounts."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import accounts
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# _check_guest_account
# ---------------------------------------------------------------------------

class TestCheckGuestAccount:
    def test_guest_disabled_is_pass(self):
        with patch("apotrope.checks.accounts.run_powershell", return_value="False"):
            results = accounts._check_guest_account()
        assert len(results) == 1
        r = results[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.HIGH

    def test_guest_enabled_is_fail(self):
        with patch("apotrope.checks.accounts.run_powershell", return_value="True"):
            results = accounts._check_guest_account()
        r = results[0]
        assert r.status == Status.FAIL
        assert "enabled" in r.details.lower()
        assert "Disable-LocalUser" in r.command

    def test_guest_not_found_is_info(self):
        with patch("apotrope.checks.accounts.run_powershell", return_value=""):
            results = accounts._check_guest_account()
        r = results[0]
        assert r.status == Status.INFO
        assert "not found" in r.details.lower()

    def test_powershell_error_returns_error(self):
        with patch("apotrope.checks.accounts.run_powershell",
                   side_effect=ApotropeError("boom")):
            results = accounts._check_guest_account()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_builtin_admin
# ---------------------------------------------------------------------------

class TestCheckBuiltinAdmin:
    def _run(self, data):
        with patch("apotrope.checks.accounts.run_powershell_json", return_value=data):
            return accounts._check_builtin_admin()

    def test_enabled_default_name_is_fail(self):
        results = self._run({"Name": "Administrator", "Enabled": True})
        r = results[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.MEDIUM

    def test_enabled_renamed_is_warn(self):
        results = self._run({"Name": "sysadmin", "Enabled": True})
        r = results[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.LOW
        assert "sysadmin" in r.details

    def test_disabled_is_pass(self):
        results = self._run({"Name": "Administrator", "Enabled": False})
        r = results[0]
        assert r.status == Status.PASS

    def test_disabled_renamed_is_pass(self):
        results = self._run({"Name": "sysadmin", "Enabled": False})
        r = results[0]
        assert r.status == Status.PASS
        assert "sysadmin" in r.details

    def test_empty_data_returns_info(self):
        results = self._run(None)
        r = results[0]
        assert r.status == Status.INFO
        assert "not found" in r.details.lower()

    def test_list_data_uses_first_element(self):
        results = self._run([{"Name": "Administrator", "Enabled": False}])
        assert results[0].status == Status.PASS

    def test_error_returns_error_result(self):
        with patch("apotrope.checks.accounts.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = accounts._check_builtin_admin()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_admin_count
# ---------------------------------------------------------------------------

class TestCheckAdminCount:
    def _run(self, members):
        with patch("apotrope.checks.accounts.run_powershell_json", return_value=members):
            return accounts._check_admin_count()

    def test_one_admin_is_pass(self):
        results = self._run([{"Name": "MACHINE\\Admin", "PrincipalSource": "Local", "ObjectClass": "User"}])
        assert results[0].status == Status.PASS

    def test_two_admins_is_pass(self):
        members = [
            {"Name": "MACHINE\\Admin", "PrincipalSource": "Local", "ObjectClass": "User"},
            {"Name": "MACHINE\\Domain Admins", "PrincipalSource": "ActiveDirectory", "ObjectClass": "Group"},
        ]
        results = self._run(members)
        assert results[0].status == Status.PASS

    def test_three_admins_is_warn(self):
        members = [
            {"Name": "MACHINE\\Admin1"},
            {"Name": "MACHINE\\Admin2"},
            {"Name": "MACHINE\\Admin3"},
        ]
        results = self._run(members)
        r = results[0]
        assert r.status == Status.WARN
        assert "3" in r.details

    def test_domain_prefix_stripped_from_display(self):
        results = self._run([{"Name": "MACHINE\\Alice"}])
        assert "Alice" in results[0].details
        assert "MACHINE" not in results[0].details

    def test_single_dict_wrapped(self):
        results = self._run({"Name": "MACHINE\\Admin"})
        assert results[0].status == Status.PASS

    def test_error_returns_error(self):
        with patch("apotrope.checks.accounts.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            results = accounts._check_admin_count()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _parse_net_accounts helper
# ---------------------------------------------------------------------------

class TestParseNetAccounts:
    _SAMPLE = (
        "Force user logoff how long after time expires?: Never\n"
        "Minimum password age (days): 0\n"
        "Maximum password age (days): 42\n"
        "Minimum password length: 7\n"
        "Length of password history maintained: None\n"
        "Lockout threshold: Never\n"
        "Lockout duration (minutes): 30\n"
        "Lockout observation window (minutes): 30\n"
        "Computer role: WORKSTATION\n"
        "The command completed successfully.\n"
    )

    def test_parses_min_length(self):
        parsed = accounts._parse_net_accounts(self._SAMPLE)
        assert parsed["minimum password length"] == "7"

    def test_parses_lockout_threshold(self):
        parsed = accounts._parse_net_accounts(self._SAMPLE)
        assert parsed["lockout threshold"] == "Never"

    def test_keys_are_lowercase(self):
        parsed = accounts._parse_net_accounts(self._SAMPLE)
        assert "minimum password age (days)" in parsed

    def test_empty_output(self):
        assert accounts._parse_net_accounts("") == {}


# ---------------------------------------------------------------------------
# _check_password_policy (integration-level unit tests)
# ---------------------------------------------------------------------------

class TestCheckPasswordPolicy:
    _NET_GOOD = (
        "Minimum password length: 14\n"
        "Lockout threshold: 5\n"
        "Lockout duration (minutes): 30\n"
    )
    _NET_SHORT = (
        "Minimum password length: 6\n"
        "Lockout threshold: 5\n"
        "Lockout duration (minutes): 30\n"
    )
    _NET_WARN_LEN = (
        "Minimum password length: 10\n"
        "Lockout threshold: 5\n"
        "Lockout duration (minutes): 30\n"
    )
    _NET_NO_LOCKOUT = (
        "Minimum password length: 14\n"
        "Lockout threshold: Never\n"
        "Lockout duration (minutes): 30\n"
    )

    def _run(self, net_output, complexity_val):
        with (
            patch("apotrope.checks.accounts.run_powershell",
                  side_effect=[net_output, complexity_val]),
        ):
            return accounts._check_password_policy()

    def test_all_good_returns_passes(self):
        results = self._run(self._NET_GOOD, "1")
        statuses = {r.check_name: r.status for r in results}
        assert statuses["Password Policy — Minimum Length"] == Status.PASS
        assert statuses["Password Policy — Account Lockout"] == Status.PASS
        assert statuses["Password Policy — Complexity"] == Status.PASS

    def test_short_password_is_fail(self):
        results = self._run(self._NET_SHORT, "1")
        r = next(r for r in results if "Length" in r.check_name)
        assert r.status == Status.FAIL
        assert r.severity == Severity.HIGH

    def test_warn_length_is_warn(self):
        results = self._run(self._NET_WARN_LEN, "1")
        r = next(r for r in results if "Length" in r.check_name)
        assert r.status == Status.WARN

    def test_no_lockout_is_warn(self):
        results = self._run(self._NET_NO_LOCKOUT, "1")
        r = next(r for r in results if "Lockout" in r.check_name)
        assert r.status == Status.WARN
        assert "net accounts" in r.command

    def test_complexity_disabled_is_fail(self):
        results = self._run(self._NET_GOOD, "0")
        r = next(r for r in results if "Complexity" in r.check_name)
        assert r.status == Status.FAIL

    def test_complexity_unknown_is_info(self):
        results = self._run(self._NET_GOOD, "Unknown")
        r = next(r for r in results if "Complexity" in r.check_name)
        assert r.status == Status.INFO

    def test_net_accounts_error_returns_error(self):
        with patch("apotrope.checks.accounts.run_powershell",
                   side_effect=ApotropeError("denied")):
            results = accounts._check_password_policy()
        assert any(r.status == Status.ERROR for r in results)


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_list_of_check_results(self):
        net_output = (
            "Minimum password length: 14\n"
            "Lockout threshold: 5\n"
            "Lockout duration (minutes): 30\n"
        )
        with (
            patch("apotrope.checks.accounts.run_powershell",
                  side_effect=["False", "1", net_output, "1"]),
            patch("apotrope.checks.accounts.run_powershell_json",
                  side_effect=[
                      {"Name": "Administrator", "Enabled": False},
                      [{"Name": "MACHINE\\Admin"}],
                  ]),
        ):
            results = accounts.run()
        assert all(isinstance(r, CheckResult) for r in results)
        assert len(results) >= 6
