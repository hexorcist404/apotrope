"""Tests for apotrope.checks.firewall."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import firewall
from apotrope.exceptions import ApotropeError
from apotrope.models import Status, Severity


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_PROFILE_GOOD = {"Name": "Domain", "Enabled": True,
                 "DefaultInboundAction": 4, "DefaultOutboundAction": 2}
_PROFILE_DISABLED = {"Name": "Public", "Enabled": False,
                     "DefaultInboundAction": 4, "DefaultOutboundAction": 2}
_PROFILE_ALLOW_INBOUND = {"Name": "Private", "Enabled": True,
                          "DefaultInboundAction": 2, "DefaultOutboundAction": 2}
_PROFILE_NOT_CONFIGURED = {"Name": "Domain", "Enabled": True,
                           "DefaultInboundAction": 0, "DefaultOutboundAction": 2}

_ALL_GOOD = [
    {"Name": "Domain",  "Enabled": True, "DefaultInboundAction": 4, "DefaultOutboundAction": 2},
    {"Name": "Private", "Enabled": True, "DefaultInboundAction": 4, "DefaultOutboundAction": 2},
    {"Name": "Public",  "Enabled": True, "DefaultInboundAction": 4, "DefaultOutboundAction": 2},
]

_STRING_ACTIONS = [
    {"Name": "Domain",  "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
    {"Name": "Private", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
    {"Name": "Public",  "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
]


# ---------------------------------------------------------------------------
# _parse_action helper
# ---------------------------------------------------------------------------

class TestParseAction:
    def test_integer_4_is_block(self):
        assert firewall._parse_action(4) == "Block"

    def test_integer_2_is_allow(self):
        assert firewall._parse_action(2) == "Allow"

    def test_integer_0_is_not_configured(self):
        assert firewall._parse_action(0) == "NotConfigured"

    def test_string_passthrough(self):
        assert firewall._parse_action("Block") == "Block"
        assert firewall._parse_action("Allow") == "Allow"

    def test_unknown_integer_returns_unknown_string(self):
        result = firewall._parse_action(99)
        assert "Unknown" in result

    def test_none_returns_not_configured(self):
        assert firewall._parse_action(None) == "NotConfigured"


# ---------------------------------------------------------------------------
# run() — happy path
# ---------------------------------------------------------------------------

class TestFirewallRunHappyPath:
    def test_all_profiles_good_returns_six_pass(self):
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=_ALL_GOOD):
            results = firewall.run()
        assert len(results) == 6
        assert all(r.status == Status.PASS for r in results)

    def test_returns_two_results_per_profile(self):
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=_ALL_GOOD):
            results = firewall.run()
        names = [r.check_name for r in results]
        for profile in ("Domain", "Private", "Public"):
            assert any(f"{profile} Profile Enabled" in n for n in names)
            assert any(f"{profile} Default Inbound" in n for n in names)

    def test_all_results_have_firewall_category(self):
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=_ALL_GOOD):
            results = firewall.run()
        assert all(r.category == "Firewall" for r in results)

    def test_string_enum_values_ps7_format(self):
        """PS 7+ serialises Action enum as strings; all should still PASS."""
        with patch("apotrope.checks.firewall.run_powershell_json",
                   return_value=_STRING_ACTIONS):
            results = firewall.run()
        assert all(r.status == Status.PASS for r in results)

    def test_single_profile_dict_wrapped_in_list(self):
        """PS may return a bare dict for a single profile."""
        with patch("apotrope.checks.firewall.run_powershell_json",
                   return_value=_PROFILE_GOOD):
            results = firewall.run()
        assert len(results) == 2


# ---------------------------------------------------------------------------
# run() — failure scenarios
# ---------------------------------------------------------------------------

class TestFirewallRunFailures:
    def test_disabled_profile_returns_fail(self):
        profiles = [_PROFILE_DISABLED]
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=profiles):
            results = firewall.run()
        enabled_check = next(r for r in results if "Enabled" in r.check_name)
        assert enabled_check.status == Status.FAIL
        assert enabled_check.severity == Severity.HIGH
        assert "Set-NetFirewallProfile" in enabled_check.command

    def test_explicit_allow_inbound_returns_warn(self):
        profiles = [_PROFILE_ALLOW_INBOUND]
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=profiles):
            results = firewall.run()
        inbound_check = next(r for r in results if "Inbound" in r.check_name)
        assert inbound_check.status == Status.WARN
        assert inbound_check.severity == Severity.MEDIUM
        assert "Set-NetFirewallProfile" in inbound_check.command

    def test_not_configured_inbound_is_not_a_warn(self):
        """NotConfigured inherits Block from system policy — not a finding."""
        profiles = [_PROFILE_NOT_CONFIGURED]
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=profiles):
            results = firewall.run()
        inbound_check = next(r for r in results if "Inbound" in r.check_name)
        assert inbound_check.status == Status.PASS

    def test_public_profile_disabled_has_remediation(self):
        profiles = [{"Name": "Public", "Enabled": False,
                     "DefaultInboundAction": 4, "DefaultOutboundAction": 2}]
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=profiles):
            results = firewall.run()
        enabled_check = next(r for r in results if "Enabled" in r.check_name)
        assert "Public" in enabled_check.remediation

    def test_all_profiles_disabled_returns_three_fails(self):
        profiles = [{"Name": n, "Enabled": False,
                     "DefaultInboundAction": 4, "DefaultOutboundAction": 2}
                    for n in ("Domain", "Private", "Public")]
        with patch("apotrope.checks.firewall.run_powershell_json", return_value=profiles):
            results = firewall.run()
        enabled_checks = [r for r in results if "Enabled" in r.check_name]
        assert all(r.status == Status.FAIL for r in enabled_checks)


# ---------------------------------------------------------------------------
# run() — error handling
# ---------------------------------------------------------------------------

class TestFirewallRunErrors:
    def test_ps_error_returns_single_error_result(self):
        with patch("apotrope.checks.firewall.run_powershell_json",
                   side_effect=ApotropeError("Get-NetFirewallProfile not found")):
            results = firewall.run()
        assert len(results) == 1
        assert results[0].status == Status.ERROR

    def test_error_result_has_details(self):
        with patch("apotrope.checks.firewall.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = firewall.run()
        assert "access denied" in results[0].details
