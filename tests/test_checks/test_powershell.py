"""Tests for apotrope.checks.powershell."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import powershell
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# _check_execution_policy
# ---------------------------------------------------------------------------

class TestCheckExecutionPolicy:
    def _run(self, output: str):
        with patch("apotrope.checks.powershell.run_powershell", return_value=output):
            return powershell._check_execution_policy()

    def test_restricted_is_info(self):
        r = self._run("Restricted")[0]
        assert r.status == Status.INFO

    def test_remotesigned_is_info(self):
        r = self._run("RemoteSigned")[0]
        assert r.status == Status.INFO

    def test_allsigned_is_info(self):
        r = self._run("AllSigned")[0]
        assert r.status == Status.INFO

    def test_unrestricted_is_warn(self):
        r = self._run("Unrestricted")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_bypass_is_warn(self):
        r = self._run("Bypass")[0]
        assert r.status == Status.WARN

    def test_case_insensitive_match(self):
        r = self._run("bypass")[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run("Unrestricted")[0]
        assert "RemoteSigned" in r.remediation

    def test_policy_value_in_details(self):
        r = self._run("RemoteSigned")[0]
        assert "RemoteSigned" in r.details

    def test_error_returns_error(self):
        with patch("apotrope.checks.powershell.run_powershell",
                   side_effect=ApotropeError("denied")):
            r = powershell._check_execution_policy()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_script_block_logging
# ---------------------------------------------------------------------------

class TestCheckScriptBlockLogging:
    def _run(self, output: str):
        with patch("apotrope.checks.powershell.run_powershell", return_value=output):
            return powershell._check_script_block_logging()

    def test_enabled_value_1_is_pass(self):
        r = self._run("1")[0]
        assert r.status == Status.PASS

    def test_disabled_value_0_is_warn(self):
        r = self._run("0")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_notset_is_warn(self):
        r = self._run("NOTSET")[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run("NOTSET")[0]
        assert "EnableScriptBlockLogging" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.powershell.run_powershell",
                   side_effect=ApotropeError("boom")):
            r = powershell._check_script_block_logging()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_module_logging
# ---------------------------------------------------------------------------

class TestCheckModuleLogging:
    def _run(self, output: str):
        with patch("apotrope.checks.powershell.run_powershell", return_value=output):
            return powershell._check_module_logging()

    def test_enabled_is_pass(self):
        r = self._run("1")[0]
        assert r.status == Status.PASS

    def test_notset_is_warn(self):
        r = self._run("NOTSET")[0]
        assert r.status == Status.WARN

    def test_zero_is_warn(self):
        r = self._run("0")[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run("0")[0]
        assert "EnableModuleLogging" in r.command


# ---------------------------------------------------------------------------
# _check_constrained_language
# ---------------------------------------------------------------------------

class TestCheckConstrainedLanguage:
    def _run(self, output: str):
        with patch("apotrope.checks.powershell.run_powershell", return_value=output):
            return powershell._check_constrained_language()

    def test_constrained_mode_is_pass(self):
        r = self._run("ConstrainedLanguage")[0]
        assert r.status == Status.PASS

    def test_full_language_mode_is_info(self):
        r = self._run("FullLanguage")[0]
        assert r.status == Status.INFO

    def test_mode_in_details(self):
        r = self._run("FullLanguage")[0]
        assert "FullLanguage" in r.details

    def test_no_remediation(self):
        r = self._run("FullLanguage")[0]
        assert r.remediation == ""


# ---------------------------------------------------------------------------
# _check_psv2
# ---------------------------------------------------------------------------

class TestCheckPsv2:
    def _run(self, output: str):
        with patch("apotrope.checks.powershell.run_powershell", return_value=output):
            return powershell._check_psv2()

    def test_enabled_is_warn(self):
        r = self._run("Enabled")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_enabled_with_payload_removed_is_warn(self):
        r = self._run("EnabledWithPayloadRemoved")[0]
        assert r.status == Status.WARN

    def test_disabled_is_pass(self):
        r = self._run("Disabled")[0]
        assert r.status == Status.PASS

    def test_unavailable_is_info_not_pass(self):
        # 'UNAVAILABLE' is a query-failure sentinel (needs elevation), not proof
        # v2 is absent — it must not be reported as a secure PASS.
        r = self._run("UNAVAILABLE")[0]
        assert r.status == Status.INFO

    def test_unknown_state_is_info(self):
        r = self._run("SomeOtherState")[0]
        assert r.status == Status.INFO

    def test_warn_mentions_downgrade(self):
        r = self._run("Enabled")[0]
        assert "v2" in r.details.lower() or "Version 2" in r.details

    def test_warn_has_remediation(self):
        r = self._run("Enabled")[0]
        assert "Disable-WindowsOptionalFeature" in r.command


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_five_results(self):
        side_effects = [
            "RemoteSigned",  # exec policy
            "0",             # script block logging
            "0",             # module logging
            "FullLanguage",  # CLM
            "Disabled",      # PSv2
        ]
        with patch("apotrope.checks.powershell.run_powershell", side_effect=side_effects):
            results = powershell.run()
        assert len(results) == 5
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_category_is_powershell(self):
        side_effects = ["RemoteSigned", "1", "1", "ConstrainedLanguage", "Disabled"]
        with patch("apotrope.checks.powershell.run_powershell", side_effect=side_effects):
            results = powershell.run()
        assert all(r.category == "PowerShell" for r in results)


# ---------------------------------------------------------------------------
# Error handling for the remaining sub-checks
# ---------------------------------------------------------------------------

class TestSubCheckErrorPaths:
    def _error_run(self, fn):
        with patch("apotrope.checks.powershell.run_powershell",
                   side_effect=ApotropeError("access denied")):
            return fn()[0]

    def test_module_logging_error(self):
        r = self._error_run(powershell._check_module_logging)
        assert r.status == Status.ERROR
        assert "access denied" in r.details

    def test_constrained_language_error(self):
        r = self._error_run(powershell._check_constrained_language)
        assert r.status == Status.ERROR
        assert "access denied" in r.details

    def test_psv2_error(self):
        r = self._error_run(powershell._check_psv2)
        assert r.status == Status.ERROR
        assert "access denied" in r.details
