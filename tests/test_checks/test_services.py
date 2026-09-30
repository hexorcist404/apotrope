"""Tests for apotrope.checks.services."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest


from apotrope.checks import services
from apotrope.exceptions import ApotropeError
from apotrope.compare import save_baseline
from apotrope.models import AuditReport, CheckResult, Status, Severity
from apotrope.reporter import Reporter


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

    def test_fail_withholds_path(self):
        path = "C:\\Program Files\\My Service\\svc.exe"
        r = self._run([_unquoted("MySvc", path)])[0]
        assert path not in r.details
        assert "Command lines withheld" in r.details

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


@pytest.mark.parametrize("command_line", [
    r"C:\Program Files\Agent\svc.exe --password SECRET_PASSWORD --token SECRET_TOKEN",
    r'C:\Program Files\Agent\svc.exe --config="C:\secrets\SECRET_TOKEN.exe"',
    r"C:\Program Files\Agent\svc.dll /password:SECRET_PASSWORD",
    r"C:\Program Files\SECRET_PASSWORD.exe folder\svc.exe --token=SECRET_TOKEN",
    r"C:\Program Files\Agent\svc --token SECRET_TOKEN",
])
@pytest.mark.parametrize("single", [False, True])
def test_unquoted_service_secrets_do_not_reach_exports(
    tmp_path: Path, command_line: str, single: bool,
) -> None:
    """Service command lines stay out of every exported representation."""
    item = _unquoted("SentinelService", command_line)
    data = item if single else [item, _unquoted("SecondService", command_line)]
    with patch("apotrope.checks.services.run_powershell_json", return_value=data):
        results = services._check_unquoted_paths()
    result = results[0]
    assert result.status == Status.FAIL
    assert result.severity == Severity.HIGH
    assert "SentinelService" in result.details
    assert f"{1 if single else 2} service(s)" in result.details
    assert "preserving any arguments" in result.remediation
    report = AuditReport("TEST-PC", "Windows 11", datetime.now(timezone.utc), 1.0, results, 90)
    reporter = Reporter()
    outputs = [
        (reporter.generate_json_report, "report.json"),
        (save_baseline, "baseline.json"),
        (reporter.generate_html_report, "report.html"),
        (reporter.generate_executive_report, "executive.html"),
    ]
    for exporter, filename in outputs:
        output = tmp_path / filename
        assert exporter(report, str(output))
        text = output.read_text(encoding="utf-8")
        assert "SentinelService" in text
        for secret in ("SECRET_PASSWORD", "SECRET_TOKEN"):
            assert secret.lower() not in text.lower()
    assert command_line not in result.details


def test_unquoted_query_exports_only_service_identity() -> None:
    """Keep argument-bearing PathName inside the detection filter."""
    projection = services._PS_UNQUOTED.split("| Select-Object", 1)[1]
    assert projection.strip() == "Name | ConvertTo-Json -Compress"
