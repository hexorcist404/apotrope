"""Tests for apotrope.checks.antivirus."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import antivirus
from apotrope.exceptions import ApotropeError
from apotrope.models import Status, Severity


# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

def _defender(am=True, rtp=True, av=True, tamper=True, sig_age=1, running_mode="Normal") -> dict:
    return {
        "AMServiceEnabled": am,
        "RealTimeProtectionEnabled": rtp,
        "AntivirusEnabled": av,
        "IsTamperProtected": tamper,
        "AntivirusSignatureAge": sig_age,
        "AMRunningMode": running_mode,
    }


_SC2_DEFENDER = [{"displayName": "Windows Defender", "productState": 397568}]
_SC2_THIRD_PARTY = [{"displayName": "CrowdStrike Falcon", "productState": 266240}]
_SC2_MULTI = [
    {"displayName": "Windows Defender", "productState": 397568},
    {"displayName": "Malwarebytes",     "productState": 266240},
]


# ---------------------------------------------------------------------------
# _check_defender
# ---------------------------------------------------------------------------

class TestCheckDefender:
    def test_all_good_returns_three_pass(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender()):
            results = antivirus._check_defender()
        assert len(results) == 3
        assert all(r.status == Status.PASS for r in results)

    def test_rtp_disabled_returns_critical_fail(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(rtp=False)):
            results = antivirus._check_defender()
        rtp = next(r for r in results if "Real-Time" in r.check_name)
        assert rtp.status == Status.FAIL
        assert rtp.severity == Severity.CRITICAL
        assert rtp.remediation != ""

    def test_old_signatures_returns_warn(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(sig_age=10)):
            results = antivirus._check_defender()
        sig = next(r for r in results if "Signature" in r.check_name)
        assert sig.status == Status.WARN
        assert sig.severity == Severity.HIGH
        assert "Update-MpSignature" in sig.command

    def test_signatures_at_threshold_returns_warn(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(sig_age=8)):
            results = antivirus._check_defender()
        sig = next(r for r in results if "Signature" in r.check_name)
        assert sig.status == Status.WARN

    def test_signatures_within_threshold_returns_pass(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(sig_age=7)):
            results = antivirus._check_defender()
        sig = next(r for r in results if "Signature" in r.check_name)
        assert sig.status == Status.PASS

    def test_tamper_protection_off_returns_warn(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(tamper=False)):
            results = antivirus._check_defender()
        tp = next(r for r in results if "Tamper" in r.check_name)
        assert tp.status == Status.WARN
        assert tp.severity == Severity.MEDIUM
        assert tp.remediation != ""

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   side_effect=ApotropeError("cmdlet not found")):
            results = antivirus._check_defender()
        assert len(results) == 1
        assert results[0].status == Status.ERROR

    def test_list_response_unwrapped(self):
        """ConvertTo-Json may emit a list for single objects on some PS versions."""
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=[_defender()]):
            results = antivirus._check_defender()
        assert all(r.status == Status.PASS for r in results)

    def test_sig_age_none_treated_as_zero(self):
        data = _defender()
        data["AntivirusSignatureAge"] = None
        with patch("apotrope.checks.antivirus.run_powershell_json", return_value=data):
            results = antivirus._check_defender()
        sig = next(r for r in results if "Signature" in r.check_name)
        assert sig.status == Status.PASS

    def test_genuinely_disabled_rtp_is_still_critical_fail(self):
        """Real data (cmdlet succeeded) reporting RTP off is a genuine CRITICAL fail —
        distinct from the unavailable-provider case below."""
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(am=False, rtp=False, av=False, tamper=False, sig_age=999)):
            results = antivirus._check_defender()
        assert len(results) == 3
        rtp = next(r for r in results if "Real-Time" in r.check_name)
        assert rtp.status == Status.FAIL
        assert rtp.severity == Severity.CRITICAL

    def test_unavailable_provider_returns_single_info(self):
        """A {"_QueryError": true} marker (cmdlet unavailable) must report unknown, not FAIL."""
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value={"_QueryError": True}):
            results = antivirus._check_defender()
        assert len(results) == 1
        assert results[0].status == Status.INFO
        assert "could not be determined" in results[0].details.lower()

    def test_passive_mode_returns_single_info(self):
        """Passive Defender (a third-party AV is the active provider) is expected, not a CRITICAL fail."""
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_defender(rtp=False, running_mode="Passive")):
            results = antivirus._check_defender()
        assert len(results) == 1
        assert results[0].status == Status.INFO
        assert "passive" in results[0].details.lower()

    def test_empty_response_treated_as_unavailable(self):
        """Empty output (no JSON at all) is unknown, not a disabled Defender."""
        with patch("apotrope.checks.antivirus.run_powershell_json", return_value=[]):
            results = antivirus._check_defender()
        assert len(results) == 1
        assert results[0].status == Status.INFO


# ---------------------------------------------------------------------------
# _check_security_center
# ---------------------------------------------------------------------------

class TestCheckSecurityCenter:
    def test_defender_registered_returns_info(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_SC2_DEFENDER):
            results = antivirus._check_security_center()
        assert results[0].status == Status.INFO
        assert "Windows Defender" in results[0].details

    def test_third_party_av_returns_info(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_SC2_THIRD_PARTY):
            results = antivirus._check_security_center()
        assert results[0].status == Status.INFO
        assert "CrowdStrike" in results[0].details

    def test_multiple_av_products_listed(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   return_value=_SC2_MULTI):
            results = antivirus._check_security_center()
        assert "Windows Defender" in results[0].details
        assert "Malwarebytes" in results[0].details

    def test_no_av_registered_on_client_returns_critical_fail(self):
        with patch("apotrope.checks.antivirus.run_powershell_json", return_value=[]), \
             patch("apotrope.checks.antivirus._is_server_sku", return_value=False):
            results = antivirus._check_security_center()
        assert results[0].status == Status.FAIL
        assert results[0].severity == Severity.CRITICAL
        assert results[0].remediation != ""

    def test_no_av_on_server_sku_returns_info_not_fail(self):
        """Empty SecurityCenter2 on a Server SKU is expected (it's a client-only feature),
        so it must report INFO, not a spurious 'no AV registered' CRITICAL."""
        with patch("apotrope.checks.antivirus.run_powershell_json", return_value=[]), \
             patch("apotrope.checks.antivirus._is_server_sku", return_value=True):
            results = antivirus._check_security_center()
        assert results[0].status == Status.INFO
        assert results[0].severity == Severity.INFO

    def test_ps_error_returns_error(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   side_effect=ApotropeError("namespace not found")):
            results = antivirus._check_security_center()
        assert results[0].status == Status.ERROR

    def test_single_dict_response_handled(self):
        single = {"displayName": "Windows Defender", "productState": 397568}
        with patch("apotrope.checks.antivirus.run_powershell_json", return_value=single):
            results = antivirus._check_security_center()
        assert results[0].status == Status.INFO


# ---------------------------------------------------------------------------
# _is_server_sku
# ---------------------------------------------------------------------------

class TestIsServerSku:
    def test_server_product_type_is_server(self):
        with patch("apotrope.checks.antivirus.get_wmi_object", return_value=[{"ProductType": 3}]):
            assert antivirus._is_server_sku() is True

    def test_domain_controller_is_server(self):
        with patch("apotrope.checks.antivirus.get_wmi_object", return_value=[{"ProductType": 2}]):
            assert antivirus._is_server_sku() is True

    def test_workstation_is_not_server(self):
        with patch("apotrope.checks.antivirus.get_wmi_object", return_value=[{"ProductType": 1}]):
            assert antivirus._is_server_sku() is False

    def test_unreadable_product_type_is_not_server(self):
        with patch("apotrope.checks.antivirus.get_wmi_object", return_value=[]):
            assert antivirus._is_server_sku() is False

    def test_non_int_product_type_is_not_server(self):
        with patch("apotrope.checks.antivirus.get_wmi_object", return_value=[{"ProductType": None}]):
            assert antivirus._is_server_sku() is False


# ---------------------------------------------------------------------------
# run() — integration
# ---------------------------------------------------------------------------

class TestAntivirusRun:
    def test_returns_four_results_when_all_good(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   side_effect=[_defender(), _SC2_DEFENDER]):
            results = antivirus.run()
        assert len(results) == 4   # 3 defender + 1 security center

    def test_all_have_antivirus_category(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   side_effect=[_defender(), _SC2_DEFENDER]):
            results = antivirus.run()
        assert all(r.category == "Antivirus" for r in results)

    def test_error_in_defender_does_not_crash_sc2_check(self):
        with patch("apotrope.checks.antivirus.run_powershell_json",
                   side_effect=[ApotropeError("no Defender"), _SC2_DEFENDER]):
            results = antivirus.run()
        assert len(results) == 2   # 1 error + 1 security center
        assert results[0].status == Status.ERROR
        assert results[1].status == Status.INFO
