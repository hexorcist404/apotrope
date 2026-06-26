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
             version: str = "10.0.22631",
             product_type: int | None = 1) -> dict:
    data: dict = {"Caption": caption, "BuildNumber": build, "Version": version}
    if product_type is not None:
        data["ProductType"] = product_type
    return data


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
        """Build 26100 (Win11 24H2, Home/Pro EOL 2026-10-13) should PASS on ref date Mar 2026."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="26100")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "24H2" in eol.details

    def test_win11_23h2_eol_under_home_pro_dates(self):
        """Build 22631 (Win11 23H2) Home/Pro support ended 2025-11-11, so it FAILs on ref date Mar 2026.

        Regression guard for the Fugu/Codex finding: the table previously held 23H2's
        Enterprise date (2026-11-10), which wrongly reported a consumer box as supported.
        """
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="22631")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.FAIL
        assert "23H2" in eol.details

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

    def test_25h2_build_resolves(self):
        """Build 26200 is Windows 11 25H2 (an exact entry), not 24H2 via a range fallback."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="26200")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "25H2" in eol.details
        assert "24H2" not in eol.details

    def test_intermediate_build_resolves_to_nearest_lower_base(self):
        """A build between known bases (e.g. a post-GA CU 26150) resolves to its base release (24H2)."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="26150")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "24H2" in eol.details

    def test_26h1_build_resolves(self):
        """Build 28000 is Windows 11 26H1."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="28000")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "26H1" in eol.details

    def test_server_2025_resolves_distinct_from_client_24h2(self):
        """Build 26100 is shared: ProductType 3 -> Windows Server 2025; ProductType 1 -> Windows 11 24H2.

        Headline disambiguation test — without ProductType the server was mislabelled as
        the Win11 client edition with the wrong (much earlier) support date.
        """
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_os_json(caption="Microsoft Windows Server 2025",
                                         build="26100", product_type=3)), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            server = os_info._check_os_build()
        server_eol = next(r for r in server if r.check_name == "OS End-of-Support Status")
        assert "Server 2025" in server_eol.details
        assert "24H2" not in server_eol.details

        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_os_json(build="26100", product_type=1)), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            client = os_info._check_os_build()
        client_eol = next(r for r in client if r.check_name == "OS End-of-Support Status")
        assert "24H2" in client_eol.details
        assert "Server" not in client_eol.details

    def test_unknown_future_build_warns(self):
        """A build newer than the whole table must WARN, not silently inherit the newest release."""
        with patch("apotrope.checks.os_info.run_powershell_json", return_value=_os_json(build="30000")), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.WARN
        assert "newer" in eol.details.lower()
        assert "2026-06-26" in eol.details  # _LAST_VERIFIED stamp

    def test_edition_date_correctness_pins_home_pro_policy(self):
        """24H2 client between Home/Pro (2026-10-13) and Enterprise (2027-10-12) EOL must FAIL.

        Pins the Home/Pro policy: if the table ever reverted to Enterprise dates this would
        wrongly PASS.
        """
        between = datetime(2026, 12, 1, tzinfo=timezone.utc)
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_os_json(build="26100", product_type=1)), \
             patch("apotrope.checks.os_info._now", return_value=between):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.FAIL

    def test_product_type_none_falls_back_to_client(self):
        """Missing ProductType resolves the shared 26100 build to the client edition (24H2)."""
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_os_json(build="26100", product_type=None)), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "24H2" in eol.details

    def test_server_only_build_resolves_as_server_without_product_type(self):
        """Build 20348 exists only as Windows Server 2022, so it resolves server-side even without ProductType."""
        with patch("apotrope.checks.os_info.run_powershell_json",
                   return_value=_os_json(caption="Microsoft Windows Server 2022",
                                         build="20348", product_type=None)), \
             patch("apotrope.checks.os_info._now", return_value=_REF_DATE):
            results = os_info._check_os_build()
        eol = next(r for r in results if r.check_name == "OS End-of-Support Status")
        assert eol.status == Status.PASS
        assert "Server 2022" in eol.details

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
