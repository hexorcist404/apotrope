"""Tests for apotrope.checks.os_info."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch


from apotrope.checks import os_info
from apotrope.exceptions import ApotropeError
from apotrope.models import Status


# ---------------------------------------------------------------------------
# Shared mock data helpers
# ---------------------------------------------------------------------------

def _os_json(caption: str = "Microsoft Windows 11 Pro",
             build: str = "22631",
             version: str = "10.0.22631") -> dict:
    return {"Caption": caption, "BuildNumber": build, "Version": version}


def _domain_json(part_of_domain: bool = False,
                 domain: str = "WORKGROUP") -> dict:
    return {"PartOfDomain": part_of_domain, "Domain": domain, "Workgroup": "WORKGROUP"}


def _tpm_json(present: bool = True, ready: bool = True,
              version: str = "2.0") -> dict:
    return {"TpmPresent": present, "TpmReady": ready, "ManufacturerVersion": version}


# Fixed reference date used in all EOL tests
_REF_DATE = datetime(2026, 3, 17, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# _check_os_build
# ---------------------------------------------------------------------------

class TestCheckOsBuild:
    def test_supported_build_returns_pass(self):
        """Build 22631 (Win11 23H2, EOL Nov 2026) should PASS on ref date."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="22631")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS

    def test_eol_build_returns_fail(self):
        """Build 19045 (Win10 22H2, EOL Oct 2025) should FAIL on ref date Mar 2026."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="19045")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.FAIL
        assert "end of support" in eol.details.lower()
        assert eol.remediation != ""

    def test_very_old_build_returns_fail(self):
        """Build 10240 (Win10 1507, EOL 2017) should always FAIL."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="10240")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.FAIL

    def test_unknown_build_returns_warn(self):
        """A build below all known ranges (pre-Win10) should WARN, not crash."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="5000")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.WARN

    def test_post_ga_cu_build_resolves_via_range(self):
        """Build 26200 (post-24H2 CU) should resolve to Windows 11 24H2 and PASS."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="26200")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "24H2" in eol.details

    def test_os_version_result_is_info(self):
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json()), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        ver = next(r for r in results if r.check_name == "OS Version")
        assert ver.status == Status.INFO
        assert "22631" in ver.details

    def test_ps_error_returns_two_error_results(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=ApotropeError("Access denied")):
            results = os_info._check_os_build()
        assert len(results) == 2
        assert all(r.status == Status.ERROR for r in results)

    def test_single_dict_response_handled(self):
        """PS may return a dict instead of a list; should not crash."""
        data = _os_json(build="22631")  # already a dict
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=data), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        assert len(results) == 2

    def test_list_response_handled(self):
        """PS may wrap in a list; should unwrap and use first element."""
        data = [_os_json(build="22631")]
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=data), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        assert len(results) == 2


# ---------------------------------------------------------------------------
# _check_uptime
# ---------------------------------------------------------------------------

class TestCheckUptime:
    def test_low_uptime_returns_pass(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="5"):
            results = os_info._check_uptime()
        assert results[0].status == Status.PASS
        assert "5 day" in results[0].details

    def test_uptime_at_threshold_returns_pass(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="30"):
            results = os_info._check_uptime()
        assert results[0].status == Status.PASS

    def test_uptime_over_threshold_returns_warn(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="45"):
            results = os_info._check_uptime()
        assert results[0].status == Status.WARN
        assert "45 days" in results[0].details
        assert results[0].remediation != ""

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.os_info.run_powershell",
                   side_effect=ApotropeError("timeout")):
            results = os_info._check_uptime()
        assert results[0].status == Status.ERROR

    def test_non_integer_output_returns_error(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="not-a-number"):
            results = os_info._check_uptime()
        assert results[0].status == Status.ERROR

    def test_zero_uptime_returns_pass(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="0"):
            results = os_info._check_uptime()
        assert results[0].status == Status.PASS


# ---------------------------------------------------------------------------
# _check_domain
# ---------------------------------------------------------------------------

class TestCheckDomain:
    def test_workgroup_returns_info(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_domain_json(part_of_domain=False, domain="WORKGROUP")):
            results = os_info._check_domain()
        assert results[0].status == Status.INFO
        assert "Workgroup" in results[0].details

    def test_domain_joined_returns_info(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_domain_json(part_of_domain=True, domain="CORP")):
            results = os_info._check_domain()
        assert results[0].status == Status.INFO
        assert "Domain-joined" in results[0].details
        assert "CORP" in results[0].details

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            results = os_info._check_domain()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_secure_boot
# ---------------------------------------------------------------------------

class TestCheckSecureBoot:
    def test_enabled_returns_pass(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="True"):
            results = os_info._check_secure_boot()
        assert results[0].status == Status.PASS

    def test_disabled_returns_fail(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="False"):
            results = os_info._check_secure_boot()
        assert results[0].status == Status.FAIL
        assert results[0].remediation != ""

    def test_unsupported_returns_warn(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="UNSUPPORTED"):
            results = os_info._check_secure_boot()
        assert results[0].status == Status.WARN

    def test_case_insensitive_unsupported(self):
        with patch("apotrope.checks.os_info.run_powershell", return_value="unsupported"):
            results = os_info._check_secure_boot()
        assert results[0].status == Status.WARN

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.os_info.run_powershell",
                   side_effect=ApotropeError("not supported")):
            results = os_info._check_secure_boot()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_tpm
# ---------------------------------------------------------------------------

class TestCheckTpm:
    def test_tpm_present_and_ready_returns_pass(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_tpm_json(present=True, ready=True, version="2.0")):
            results = os_info._check_tpm()
        assert results[0].status == Status.PASS
        assert "2.0" in results[0].details

    def test_tpm_present_not_ready_returns_warn(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_tpm_json(present=True, ready=False)):
            results = os_info._check_tpm()
        assert results[0].status == Status.WARN

    def test_no_tpm_returns_warn(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_tpm_json(present=False, ready=False)):
            results = os_info._check_tpm()
        assert results[0].status == Status.WARN
        assert "No TPM" in results[0].details

    def test_ps_error_returns_error_result(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=ApotropeError("WMI error")):
            results = os_info._check_tpm()
        assert results[0].status == Status.ERROR

    def test_null_version_handled(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value={"TpmPresent": True, "TpmReady": True, "ManufacturerVersion": None}):
            results = os_info._check_tpm()
        assert results[0].status == Status.PASS
        assert "Unknown" in results[0].details


# ---------------------------------------------------------------------------
# run() — integration
# ---------------------------------------------------------------------------

class TestOsInfoRun:
    def test_run_returns_list_of_check_results(self):
        from apotrope.models import CheckResult
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=[_os_json(), _domain_json(), _tpm_json()]), \
             patch("apotrope.checks.os_info.run_powershell", return_value="5"), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info.run()
        assert all(isinstance(r, CheckResult) for r in results)
        assert len(results) >= 5  # version, eol, uptime, domain, secure boot, tpm

    def test_all_results_have_category_system(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=[_os_json(), _domain_json(), _tpm_json()]), \
             patch("apotrope.checks.os_info.run_powershell", return_value="5"), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info.run()
        assert all(r.category == "System" for r in results)

    def test_one_module_error_does_not_crash_run(self):
        """Even if one sub-check raises, run() should complete and return ERROR results."""
        with patch("apotrope.checks.os_info.run_powershell_json",
                   side_effect=ApotropeError("access denied")), \
             patch("apotrope.checks.os_info.run_powershell",
                   side_effect=ApotropeError("timeout")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info.run()
        assert len(results) > 0
        assert all(r.status == Status.ERROR for r in results)


# ---------------------------------------------------------------------------
# Parse fallbacks and list-shaped JSON payloads
# ---------------------------------------------------------------------------

class TestBuildParseFallback:
    def test_non_numeric_build_does_not_crash(self):
        data = _os_json(build="garbage")
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=data), \
             patch("apotrope.checks.os_info._now",
                   return_value=datetime(2026, 1, 1, tzinfo=timezone.utc)):
            results = os_info._check_os_build()
        assert results
        assert all(r.status != Status.ERROR for r in results)
        version = next(r for r in results if r.check_name == "OS Version")
        assert version.status == Status.INFO


class TestListShapedPayloads:
    def test_domain_json_as_list_unwrapped(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=[_domain_json(part_of_domain=True, domain="CORP")]):
            results = os_info._check_domain()
        assert results[0].status != Status.ERROR
        assert "CORP" in results[0].details

    def test_domain_empty_list_treated_as_unknown(self):
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=[]):
            results = os_info._check_domain()
        assert results[0].status != Status.ERROR
        assert "UNKNOWN" in results[0].details

    def test_tpm_json_as_list_unwrapped(self):
        payload = [{"TpmPresent": True, "TpmReady": True,
                    "ManufacturerVersion": "7.2"}]
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=payload):
            results = os_info._check_tpm()
        assert results[0].status != Status.ERROR
        assert "TPM" in results[0].check_name


class TestNowHelper:
    def test_now_returns_utc_aware_datetime(self):
        assert os_info._now().tzinfo is timezone.utc
