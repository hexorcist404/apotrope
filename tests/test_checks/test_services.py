"""Tests for apotrope.checks.services."""

from __future__ import annotations

import pytest
from unittest.mock import patch


from apotrope.checks import services
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


def _svc(name: str, display: str = "") -> dict:
    return {"Name": name, "DisplayName": display or name, "Status": "Running"}


def _unquoted(name: str, path: str) -> dict:
    return {"Name": name, "DisplayName": name, "PathName": path}


# ---------------------------------------------------------------------------
# _check_risky_services
# ---------------------------------------------------------------------------

class TestCheckRiskyServices:
    def _run(self, services_data):
        with patch("apotrope.checks.services.run_powershell_json", return_value=services_data):
            return services._check_risky_services()

    def test_no_risky_services_returns_pass(self):
        r = self._run([_svc("Spooler"), _svc("WSearch")])[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.MEDIUM

    def test_remote_registry_running_is_warn(self):
        results = self._run([_svc("RemoteRegistry")])
        assert any(r.status == Status.WARN and r.severity == Severity.HIGH for r in results)

    def test_telnet_server_running_is_fail_critical(self):
        results = self._run([_svc("TlntSvr")])
        assert any(r.status == Status.FAIL and r.severity == Severity.CRITICAL for r in results)

    def test_telnet_service_running_is_fail_critical(self):
        results = self._run([_svc("Telnet")])
        assert any(r.status == Status.FAIL and r.severity == Severity.CRITICAL for r in results)

    def test_snmp_running_is_warn_medium(self):
        results = self._run([_svc("SNMP")])
        assert any(r.status == Status.WARN and r.severity == Severity.MEDIUM for r in results)

    def test_multiple_risky_services_each_get_result(self):
        results = self._run([_svc("RemoteRegistry"), _svc("SNMP"), _svc("Spooler")])
        risky = [r for r in results if r.status != Status.PASS]
        assert len(risky) == 2

    def test_service_name_in_check_name(self):
        results = self._run([_svc("RemoteRegistry")])
        names = [r.check_name for r in results]
        assert any("RemoteRegistry" in n for n in names)

    def test_case_insensitive_match(self):
        results = self._run([_svc("remoteregistry")])
        assert any(r.status == Status.WARN for r in results)

    def test_single_dict_wrapped(self):
        results = self._run(_svc("Spooler"))
        assert results[0].status == Status.PASS

    def test_error_returns_error(self):
        with patch("apotrope.checks.services.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            r = services._check_risky_services()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_unquoted_paths
# ---------------------------------------------------------------------------

class TestCheckUnquotedPaths:
    def _run(self, data):
        with patch("apotrope.checks.services.run_powershell_json", return_value=data):
            return services._check_unquoted_paths()

    def test_no_unquoted_paths_is_pass(self):
        r = self._run([])[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.HIGH

    def test_unquoted_path_is_fail(self):
        r = self._run([_unquoted("MySvc", "C:\\Program Files\\My Service\\svc.exe")])[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.HIGH

    def test_fail_includes_service_name(self):
        r = self._run([_unquoted("MySvc", "C:\\Program Files\\svc.exe")])[0]
        assert "MySvc" in r.details

    def test_fail_includes_path(self):
        path = "C:\\Program Files\\My Service\\svc.exe"
        r = self._run([_unquoted("MySvc", path)])[0]
        assert path in r.details

    def test_fail_has_remediation(self):
        r = self._run([_unquoted("MySvc", "C:\\My Path\\svc.exe")])[0]
        assert "ImagePath" in r.command

    def test_multiple_unquoted_paths_counted(self):
        items = [
            _unquoted("Svc1", "C:\\My App\\svc1.exe"),
            _unquoted("Svc2", "C:\\Other App\\svc2.exe"),
        ]
        r = self._run(items)[0]
        assert r.status == Status.FAIL
        assert "2" in r.details

    def test_error_returns_error(self):
        with patch("apotrope.checks.services.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            r = services._check_unquoted_paths()[0]
        assert r.status == Status.ERROR

    def test_empty_powershell_output_is_pass(self):
        """Empty PS output (no matches) should be PASS, not ERROR."""
        with patch("apotrope.checks.services.run_powershell_json",
                   side_effect=ApotropeError("PowerShell command returned empty output (expected JSON)")):
            r = services._check_unquoted_paths()[0]
        assert r.status == Status.PASS


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_list_of_check_results(self):
        with patch("apotrope.checks.services.run_powershell_json", return_value=[]):
            results = services.run()
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_no_risky_no_unquoted_two_pass_results(self):
        with patch("apotrope.checks.services.run_powershell_json", return_value=[]):
            results = services.run()
        assert len(results) == 2
        assert all(r.status == Status.PASS for r in results)

    def test_run_category_is_services(self):
        with patch("apotrope.checks.services.run_powershell_json", return_value=[]):
            results = services.run()
        assert all(r.category == "Services" for r in results)

class TestRiskyServiceAssignment:
    """The emitted CheckResult must carry the RiskyService fields it names.

    tests/test_remediation_commands.py compares the lint inventory against
    _RISKY directly, so it cannot see the assignment in between: swapping
    `command=risky.command` for `command=risky.remediation` would leave both
    the inventory and that test unchanged.
    """

    def _run_with(self, service: str):
        running = [{"Name": service, "DisplayName": service, "Status": "Running"}]
        with patch("apotrope.checks.services.run_powershell_json", return_value=running):
            return services._check_risky_services()

    @pytest.mark.parametrize("service", sorted(services._RISKY))
    def test_fields_reach_the_result_unswapped(self, service: str) -> None:
        result = next(
            r for r in self._run_with(service) if r.check_name.endswith(service)
        )
        expected = services._RISKY[service]

        assert result.command == expected.command
        assert result.remediation == expected.remediation
        assert result.details == expected.details
        assert result.status == expected.status
        assert result.severity == expected.severity
