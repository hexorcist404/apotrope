"""Tests for apotrope.checks.rdp."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import rdp
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _data(deny=1, nla=1, port=3389):
    """Mimic registry data returned by the PowerShell batch call."""
    return {
        "fDenyTSConnections": deny,
        "UserAuthentication": nla,
        "PortNumber": port,
    }


# ---------------------------------------------------------------------------
# _check_rdp_enabled
# ---------------------------------------------------------------------------

class TestCheckRdpEnabled:
    def test_rdp_disabled_deny_1_is_pass(self):
        results, enabled = rdp._check_rdp_enabled(_data(deny=1))
        assert results[0].status == Status.PASS
        assert enabled is False

    def test_rdp_enabled_deny_0_is_warn(self):
        results, enabled = rdp._check_rdp_enabled(_data(deny=0))
        assert results[0].status == Status.WARN
        assert results[0].severity == Severity.HIGH
        assert enabled is True

    def test_rdp_enabled_has_remediation(self):
        results, _ = rdp._check_rdp_enabled(_data(deny=0))
        assert "fDenyTSConnections" in results[0].command

    def test_both_keys_absent_is_warn_not_pass(self):
        # Fail-closed: with neither the Terminal Server value nor the policy
        # override readable, do NOT assume RDP is disabled.
        results, enabled = rdp._check_rdp_enabled({})
        assert results[0].status == Status.WARN
        assert enabled is False

    def test_policy_override_enables_rdp(self):
        # The GPO key overrides the Terminal Server value.
        results, enabled = rdp._check_rdp_enabled(
            {"fDenyTSConnections": 1, "PolicyDenyTSConnections": 0}
        )
        assert enabled is True
        # A local Set-ItemProperty is reverted at the next policy refresh, so
        # the verdict source must decide the remediation: point at the GPO and
        # hand over no command that cannot work.
        assert results[0].command == ""
        assert "Group Policy" in results[0].remediation
        assert "gpresult" in results[0].remediation

    def test_non_policy_enabled_rdp_still_has_a_command(self):
        results, enabled = rdp._check_rdp_enabled({"fDenyTSConnections": 0})
        assert enabled is True
        assert "fDenyTSConnections" in results[0].command

    def test_policy_nla_override_fails(self):
        r = rdp._check_rdp_nla({"UserAuthentication": 1, "PolicyUserAuthentication": 0})[0]
        assert r.status == Status.FAIL
        assert r.command == ""
        assert "Group Policy" in r.remediation
        assert "Network Level Authentication" in r.remediation

    def test_non_policy_nla_fail_still_has_a_command(self):
        r = rdp._check_rdp_nla({"UserAuthentication": 0})[0]
        assert r.status == Status.FAIL
        assert "UserAuthentication" in r.command

    def test_unreadable_nla_still_has_a_command(self):
        """Neither source readable -> policy_managed is False by construction."""
        r = rdp._check_rdp_nla({})[0]
        assert r.status == Status.WARN
        assert "UserAuthentication" in r.command


class TestLocaleNeutralFirewallSelector:
    """-DisplayGroup is a localized MUI string and matches nothing on de-DE/ja-JP."""

    def test_disable_uses_group_id_not_displaygroup(self):
        results, _ = rdp._check_rdp_enabled({"fDenyTSConnections": 0})
        cmd = results[0].command
        assert "@FirewallAPI.dll,-28752" in cmd
        assert "-DisplayGroup" not in cmd

    def test_returns_tuple(self):
        result = rdp._check_rdp_enabled(_data())
        assert isinstance(result, tuple)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _check_rdp_nla
# ---------------------------------------------------------------------------

class TestCheckRdpNla:
    def test_nla_required_is_pass(self):
        r = rdp._check_rdp_nla(_data(nla=1))[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.HIGH

    def test_nla_not_required_is_fail(self):
        r = rdp._check_rdp_nla(_data(nla=0))[0]
        assert r.status == Status.FAIL
        assert "brute" in r.details.lower()

    def test_nla_absent_is_warn(self):
        r = rdp._check_rdp_nla({})[0]
        assert r.status == Status.WARN
        assert "UserAuthentication" in r.command

    def test_nla_fail_includes_remediation(self):
        r = rdp._check_rdp_nla(_data(nla=0))[0]
        assert "UserAuthentication" in r.command


# ---------------------------------------------------------------------------
# _check_rdp_port
# ---------------------------------------------------------------------------

class TestCheckRdpPort:
    def test_default_port_is_info(self):
        r = rdp._check_rdp_port(_data(port=3389))[0]
        assert r.status == Status.INFO
        assert "default" in r.details.lower()

    def test_non_standard_port_noted(self):
        r = rdp._check_rdp_port(_data(port=13389))[0]
        assert r.status == Status.INFO
        assert "non-standard" in r.details.lower()

    def test_absent_port_defaults_to_3389(self):
        r = rdp._check_rdp_port({})[0]
        assert "3389" in r.details


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_rdp_disabled_returns_one_result(self):
        with patch("apotrope.checks.rdp.run_powershell_json", return_value=_data(deny=1)):
            results = rdp.run()
        assert len(results) == 1
        assert results[0].status == Status.PASS

    def test_rdp_enabled_returns_three_results(self):
        with patch("apotrope.checks.rdp.run_powershell_json", return_value=_data(deny=0)):
            results = rdp.run()
        assert len(results) == 3

    def test_rdp_enabled_nla_off_has_fail(self):
        with patch("apotrope.checks.rdp.run_powershell_json",
                   return_value=_data(deny=0, nla=0)):
            results = rdp.run()
        statuses = {r.check_name: r.status for r in results}
        assert statuses["RDP Network Level Authentication"] == Status.FAIL

    def test_run_handles_powershell_error(self):
        with patch("apotrope.checks.rdp.run_powershell_json",
                   side_effect=ApotropeError("timeout")):
            results = rdp.run()
        assert results[0].status == Status.ERROR

    def test_run_wraps_list_data(self):
        with patch("apotrope.checks.rdp.run_powershell_json",
                   return_value=[_data(deny=0)]):
            results = rdp.run()
        assert len(results) == 3

    def test_all_results_are_check_results(self):
        with patch("apotrope.checks.rdp.run_powershell_json", return_value=_data(deny=0)):
            results = rdp.run()
        assert all(isinstance(r, CheckResult) for r in results)
