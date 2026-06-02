"""Tests for apotrope.checks.network."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import network
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# _check_listening_ports
# ---------------------------------------------------------------------------

def _conn(port: int, addr: str = "0.0.0.0", proc: str = "svchost") -> dict:
    return {"LocalPort": port, "LocalAddress": addr, "ProcessName": proc}


class TestListeningPorts:
    def _run(self, conns):
        with patch("apotrope.checks.network.run_powershell_json", return_value=conns):
            return network._check_listening_ports()

    def test_no_risky_ports_no_flag(self):
        results = self._run([_conn(8080), _conn(443)])
        statuses = [r.status for r in results]
        assert Status.WARN not in statuses
        assert Status.FAIL not in statuses

    def test_telnet_is_fail_critical(self):
        results = self._run([_conn(23)])
        risky = [r for r in results if "23" in r.check_name]
        assert len(risky) == 1
        assert risky[0].status == Status.FAIL
        assert risky[0].severity == Severity.CRITICAL

    def test_ftp_is_warn_high(self):
        results = self._run([_conn(21)])
        risky = [r for r in results if "21" in r.check_name]
        assert risky[0].status == Status.WARN
        assert risky[0].severity == Severity.HIGH

    def test_tftp_is_warn_high(self):
        results = self._run([_conn(69)])
        risky = [r for r in results if "69" in r.check_name]
        assert risky[0].status == Status.WARN
        assert risky[0].severity == Severity.HIGH

    def test_rdp_3389_is_warn_medium(self):
        results = self._run([_conn(3389)])
        risky = [r for r in results if "3389" in r.check_name]
        assert risky[0].status == Status.WARN
        assert risky[0].severity == Severity.MEDIUM

    def test_summary_always_present(self):
        results = self._run([_conn(8080)])
        summary = [r for r in results if "Summary" in r.check_name]
        assert len(summary) == 1
        assert summary[0].status == Status.INFO

    def test_empty_connections_summary_no_ports(self):
        results = self._run([])
        summary = next(r for r in results if "Summary" in r.check_name)
        assert "No listening" in summary.details

    def test_summary_truncated_at_30(self):
        conns = [_conn(p) for p in range(1, 40)]
        results = self._run(conns)
        summary = next(r for r in results if "Summary" in r.check_name)
        assert "+9 more" in summary.details

    def test_single_dict_wrapped(self):
        results = self._run(_conn(80))
        summary = next(r for r in results if "Summary" in r.check_name)
        assert "1" in summary.details

    def test_error_returns_error_result(self):
        with patch("apotrope.checks.network.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            results = network._check_listening_ports()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_llmnr
# ---------------------------------------------------------------------------

class TestCheckLlmnr:
    def _run(self, output):
        with patch("apotrope.checks.network.run_powershell", return_value=output):
            return network._check_llmnr()

    def test_notset_is_warn(self):
        results = self._run("NOTSET")
        assert results[0].status == Status.WARN

    def test_value_1_is_warn(self):
        results = self._run("1")
        assert results[0].status == Status.WARN
        assert results[0].severity == Severity.MEDIUM

    def test_value_0_is_pass(self):
        results = self._run("0")
        assert results[0].status == Status.PASS

    def test_warn_mentions_responder(self):
        results = self._run("NOTSET")
        assert "Responder" in results[0].details

    def test_error_returns_error(self):
        with patch("apotrope.checks.network.run_powershell",
                   side_effect=ApotropeError("denied")):
            results = network._check_llmnr()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_netbios
# ---------------------------------------------------------------------------

class TestCheckNetbios:
    def _run(self, data):
        with patch("apotrope.checks.network.run_powershell_json", return_value=data):
            return network._check_netbios()

    def test_all_disabled_is_pass(self):
        results = self._run([2, 2])
        assert results[0].status == Status.PASS

    def test_explicit_enabled_is_warn_medium(self):
        results = self._run([1, 2])
        r = results[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_dhcp_only_is_warn_low(self):
        results = self._run([0, 0])
        r = results[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.LOW

    def test_empty_is_info(self):
        results = self._run([])
        assert results[0].status == Status.INFO

    def test_invalid_values_skipped(self):
        results = self._run([None, "bad", 2])
        assert results[0].status == Status.PASS

    def test_error_returns_error(self):
        with patch("apotrope.checks.network.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            results = network._check_netbios()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_ipv6
# ---------------------------------------------------------------------------

class TestCheckIpv6:
    def _run(self, output):
        with patch("apotrope.checks.network.run_powershell", return_value=output):
            return network._check_ipv6()

    def test_active_adapters_reported(self):
        results = self._run("3")
        assert results[0].status == Status.INFO
        assert "3" in results[0].details

    def test_zero_adapters_reported(self):
        results = self._run("0")
        assert "not active" in results[0].details.lower()

    def test_non_digit_output_treated_as_zero(self):
        results = self._run("n/a")
        assert results[0].status == Status.INFO


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_list_of_check_results(self):
        conns = [_conn(443), _conn(80)]
        with (
            patch("apotrope.checks.network.run_powershell_json", return_value=conns),
            patch("apotrope.checks.network.run_powershell", side_effect=["0", "0"]),
        ):
            results = network.run()
        assert all(isinstance(r, CheckResult) for r in results)
        assert len(results) >= 4
