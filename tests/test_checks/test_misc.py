"""Tests for apotrope.checks.misc (Hardening category)."""

from __future__ import annotations

from unittest.mock import patch


from apotrope.checks import misc
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


# ---------------------------------------------------------------------------
# _check_autoplay
# ---------------------------------------------------------------------------

class TestCheckAutoplay:
    def _run(self, output: str):
        with patch("apotrope.checks.misc.run_powershell", return_value=output):
            return misc._check_autoplay()

    def test_fully_disabled_255_is_pass(self):
        r = self._run("255")[0]
        assert r.status == Status.PASS

    def test_not_set_is_warn(self):
        r = self._run("NOTSET")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_partial_disable_is_warn(self):
        r = self._run("91")[0]
        assert r.status == Status.WARN

    def test_zero_is_warn(self):
        r = self._run("0")[0]
        assert r.status == Status.WARN

    def test_warn_has_remediation(self):
        r = self._run("NOTSET")[0]
        assert "NoDriveTypeAutoRun" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell",
                   side_effect=ApotropeError("denied")):
            r = misc._check_autoplay()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_winrm
# ---------------------------------------------------------------------------

class TestCheckWinrm:
    def _run(self, output: str):
        with patch("apotrope.checks.misc.run_powershell", return_value=output):
            return misc._check_winrm()

    def test_stopped_is_pass(self):
        r = self._run("Stopped")[0]
        assert r.status == Status.PASS

    def test_running_is_warn(self):
        r = self._run("Running")[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_not_found_is_info(self):
        r = self._run("")[0]
        assert r.status == Status.INFO

    def test_running_has_remediation(self):
        r = self._run("Running")[0]
        assert "WinRM" in r.remediation

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell",
                   side_effect=ApotropeError("boom")):
            r = misc._check_winrm()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_spectre
# ---------------------------------------------------------------------------

class TestCheckSpectre:
    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_spectre()

    def test_no_override_key_is_info(self):
        r = self._run({"Override": None, "Mask": None})[0]
        assert r.status == Status.INFO
        assert "default" in r.details.lower()

    def test_mitigations_disabled_is_warn(self):
        # Override & 3 == 3, Mask == 3 → disabled
        r = self._run({"Override": 3, "Mask": 3})[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.MEDIUM

    def test_mitigations_enabled_via_override_is_info(self):
        # Override = 0, Mask = 3 → mitigations on
        r = self._run({"Override": 0, "Mask": 3})[0]
        assert r.status == Status.INFO

    def test_list_data_wrapped(self):
        r = self._run([{"Override": None, "Mask": None}])[0]
        assert r.status == Status.INFO

    def test_disabled_has_remediation(self):
        r = self._run({"Override": 3, "Mask": 3})[0]
        assert "FeatureSettingsOverride" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            r = misc._check_spectre()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_audit_policy
# ---------------------------------------------------------------------------

class TestCheckAuditPolicy:
    def _entry(self, name: str, setting: str = "Success and Failure") -> dict:
        return {"Subcategory": name, "Inclusion Setting": setting}

    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_audit_policy()

    def test_all_audited_is_pass(self):
        # PASS requires ALL expected subcategories present and auditing.
        entries = [self._entry(name) for name in misc._EXPECTED_AUDIT]
        r = self._run(entries)[0]
        assert r.status == Status.PASS

    def test_partial_subset_is_warn(self):
        # A nonempty subset that omits expected subcategories must not PASS.
        r = self._run([self._entry("Logon")])[0]
        assert r.status == Status.WARN

    def test_no_auditing_entry_is_warn(self):
        entries = [
            self._entry("Logon", "No Auditing"),
            self._entry("Account Lockout", "Success"),
        ]
        r = self._run(entries)[0]
        assert r.status == Status.WARN
        assert "Logon" in r.details

    def test_empty_list_is_info_not_warn(self):
        # Non-admin / localized auditpol returns nothing; that is "could not
        # assess" (INFO), not a scored WARN penalising a healthy machine.
        r = self._run([])[0]
        assert r.status == Status.INFO

    def test_warn_has_remediation(self):
        r = self._run([self._entry("Logon", "No Auditing")])[0]
        assert "auditpol" in r.command

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            r = misc._check_audit_policy()[0]
        assert r.status == Status.ERROR

    # -- the command must remediate the finding it reports -------------------
    #
    # It used to be the literal `auditpol /set /subcategory:'Logon' ...` no
    # matter which subcategory was disabled, so a host missing only 'Sensitive
    # Privilege Use' got a command that ran cleanly and fixed nothing.

    def _all_auditing_except(self, disabled=(), omitted=()):
        return [
            self._entry(name, "No Auditing" if name in disabled else "Success and Failure")
            for name in misc._EXPECTED_AUDIT
            if name not in omitted
        ]

    def test_command_names_the_disabled_subcategory(self):
        r = self._run(self._all_auditing_except(disabled=["Sensitive Privilege Use"]))[0]
        assert "Sensitive Privilege Use" in r.command
        assert "Logon" not in r.command, "the old hardcoded subcategory is back"
        assert r.command.count("auditpol") == 1

    def test_subcategory_names_are_quoted_as_one_argument(self):
        # Every auditpol subcategory name contains spaces. Unquoted,
        # `/subcategory:Sensitive Privilege Use` parses fine as PowerShell and
        # reaches auditpol as three arguments, so verify_commands.py's parser
        # cannot catch this — only an assertion on the exact text can.
        r = self._run(self._all_auditing_except(disabled=["Sensitive Privilege Use"]))[0]
        assert (
            "/subcategory:'Sensitive Privilege Use'" in r.command
        ), f"subcategory not quoted as a single argument: {r.command!r}"

    def test_command_covers_every_disabled_subcategory_in_order(self):
        disabled = ["Sensitive Privilege Use", "Logoff"]
        r = self._run(self._all_auditing_except(disabled=disabled))[0]

        lines = r.command.splitlines()
        assert len(lines) == 2, f"expected one line per disabled subcategory, got {lines}"
        # Sorted, so the emitted command is stable across scans.
        assert lines == sorted(lines)
        for name in disabled:
            assert sum(f"'{name}'" in ln for ln in lines) == 1, f"{name} missing or duplicated"

    def test_unreported_subcategories_get_no_command(self):
        # auditpol never reported it — usually a localized name this check could
        # not match. Enabling auditing the operator never asked for is a change
        # they did not consent to, so this is verification guidance, not a fix.
        r = self._run(self._all_auditing_except(omitted=["Logon"]))[0]
        assert r.status == Status.WARN
        assert r.command == ""
        assert "verify" in r.remediation.lower()

    def test_mixed_targets_only_the_confirmed_disabled(self):
        r = self._run(self._all_auditing_except(
            disabled=["Sensitive Privilege Use"], omitted=["Logon"],
        ))[0]
        assert "Sensitive Privilege Use" in r.command
        assert "Logon" not in r.command
        assert "Logon" in r.details and "not reported" in r.details
        assert "Logon" in r.remediation

    def test_pass_branch_still_emits_nothing(self):
        r = self._run([self._entry(name) for name in misc._EXPECTED_AUDIT])[0]
        assert r.command == "" and r.remediation == ""

    def test_emitted_command_clears_the_shipped_lint(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
        import command_audit

        r = self._run(self._all_auditing_except(
            disabled=["Sensitive Privilege Use", "Credential Validation"],
        ))[0]
        violations = command_audit.lint_commands(
            [command_audit.Command(module="misc.py", line=0, text=r.command)]
        )
        assert violations == [], violations


# ---------------------------------------------------------------------------
# _check_screen_lock
# ---------------------------------------------------------------------------

class TestCheckScreenLock:
    def _data(self, active="1", secure="1", timeout=600):
        return {"Active": active, "Secure": secure, "Timeout": timeout}

    def _run(self, data):
        with patch("apotrope.checks.misc.run_powershell_json", return_value=data):
            return misc._check_screen_lock()

    def test_good_config_is_pass(self):
        # 10-minute timeout, password on resume
        r = self._run(self._data(active="1", secure="1", timeout=600))[0]
        assert r.status == Status.PASS

    def test_screensaver_disabled_is_warn(self):
        r = self._run(self._data(active="0"))[0]
        assert r.status == Status.WARN

    def test_timeout_over_15min_is_warn(self):
        r = self._run(self._data(timeout=1200))[0]
        assert r.status == Status.WARN
        assert "exceeds" in r.details.lower()

    def test_exactly_15_min_is_pass(self):
        r = self._run(self._data(timeout=900))[0]
        assert r.status == Status.PASS

    def test_no_password_on_resume_is_warn(self):
        r = self._run(self._data(secure="0", timeout=300))[0]
        assert r.status == Status.WARN

    def test_zero_timeout_is_warn(self):
        r = self._run(self._data(timeout=0))[0]
        assert r.status == Status.WARN

    def test_error_returns_error(self):
        with patch("apotrope.checks.misc.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            r = misc._check_screen_lock()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_five_results(self):
        good_screen = {"Active": "1", "Secure": "1", "Timeout": 600}
        good_spectre = {"Override": None, "Mask": None}
        audit_entries = [{"Subcategory": "Logon", "Inclusion Setting": "Success and Failure"}]
        with (
            patch("apotrope.checks.misc.run_powershell",
                  side_effect=["255", "Stopped"]),
            patch("apotrope.checks.misc.run_powershell_json",
                  side_effect=[good_spectre, audit_entries, good_screen]),
        ):
            results = misc.run()
        assert len(results) == 5
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_category_is_hardening(self):
        good_screen = {"Active": "1", "Secure": "1", "Timeout": 600}
        good_spectre = {"Override": None, "Mask": None}
        audit_entries = [{"Subcategory": "Logon", "Inclusion Setting": "Success"}]
        with (
            patch("apotrope.checks.misc.run_powershell",
                  side_effect=["255", "Stopped"]),
            patch("apotrope.checks.misc.run_powershell_json",
                  side_effect=[good_spectre, audit_entries, good_screen]),
        ):
            results = misc.run()
        assert all(r.category == "Hardening" for r in results)


# ---------------------------------------------------------------------------
# Parse fallbacks and list-shaped JSON payloads
# ---------------------------------------------------------------------------

class TestAutoplayParseFallback:
    def test_non_numeric_registry_value_not_treated_as_disabled(self):
        with patch("apotrope.checks.misc.run_powershell",
                   return_value="garbage"):
            r = misc._check_autoplay()[0]
        assert r.status != Status.PASS
        assert r.status != Status.ERROR


class TestSpectreParseFallback:
    def test_non_numeric_override_not_flagged_as_disabled(self):
        payload = {"Override": "garbage", "Mask": "junk"}
        with patch("apotrope.checks.misc.run_powershell_json",
                   return_value=payload):
            r = misc._check_spectre()[0]
        assert r.status != Status.ERROR
        assert r.status != Status.FAIL


class TestScreenLockPayloadShapes:
    def test_json_as_list_unwrapped(self):
        payload = [{"Active": "1", "Secure": "1", "Timeout": "600"}]
        with patch("apotrope.checks.misc.run_powershell_json",
                   return_value=payload):
            r = misc._check_screen_lock()[0]
        assert r.status == Status.PASS

    def test_non_numeric_timeout_warns_as_unset(self):
        payload = {"Active": "1", "Secure": "1", "Timeout": "garbage"}
        with patch("apotrope.checks.misc.run_powershell_json",
                   return_value=payload):
            r = misc._check_screen_lock()[0]
        assert r.status == Status.WARN
        assert "0 or unset" in r.details


class TestMiscFixes:
    def test_autoplay_command_writes_the_value(self):
        # `Set-ItemProperty` cannot create a missing key, and the NOTSET finding
        # fires exactly when the key is absent. reg.exe writes the value and
        # creates the parents in one step.
        with patch("apotrope.checks.misc.run_powershell", return_value="NOTSET"):
            r = misc._check_autoplay()[0]

        assert "reg.exe add" in r.command
        assert "/v NoDriveTypeAutoRun" in r.command
        assert "/t REG_DWORD" in r.command and "/d 255" in r.command

    def test_autoplay_uses_no_form_that_destroys_or_cannot_run(self):
        # Three forms are ruled out, each measured: New-Item -Force replaces the
        # key and deletes the unrelated Explorer policies sharing it (a Test-Path
        # guard does not fix that, since the test and the create are separate);
        # New-Item without -Force cannot create the missing parents; and a .NET
        # method call is refused under Constrained Language Mode, which Apotrope
        # scores as a hardened PASS.
        with patch("apotrope.checks.misc.run_powershell", return_value="NOTSET"):
            r = misc._check_autoplay()[0]

        assert "New-Item" not in r.command
        assert "]::" not in r.command, "a .NET call cannot run under Constrained Language"

    def test_autoplay_command_targets_the_reg_exe_hive_form(self):
        # reg.exe takes "HKLM\..." — the "HKLM:\..." provider form would be read
        # as a key literally named "HKLM:".
        with patch("apotrope.checks.misc.run_powershell", return_value="NOTSET"):
            r = misc._check_autoplay()[0]

        add = next(ln for ln in r.command.splitlines() if "reg.exe add" in ln)
        assert "HKLM:" not in add, f"provider-form path passed to reg.exe: {add}"
        assert f'"HKLM\\{misc._AUTOPLAY_SUBKEY}"' in add

    def test_autoplay_checks_the_exit_code(self):
        # reg.exe reports failure through the exit code, not a PowerShell error,
        # so without this a denied write looks exactly like a successful one.
        with patch("apotrope.checks.misc.run_powershell", return_value="NOTSET"):
            r = misc._check_autoplay()[0]

        assert "$LASTEXITCODE" in r.command and "throw" in r.command

    def test_autoplay_remediation_is_safe_on_every_branch(self):
        # 158 -> "partially disabled" WARN; 0 and an unparseable value -> the
        # AutoPlay-enabled branch. Both read a value back, so the key provably
        # exists — precisely the case a -Force create would wipe.
        for output in ("158", "0", "notanint"):
            with patch("apotrope.checks.misc.run_powershell", return_value=output):
                r = misc._check_autoplay()[0]
            assert "reg.exe add" in r.command, f"no write for output {output!r}"
            assert "New-Item" not in r.command, f"New-Item returned for output {output!r}"
            assert "]::" not in r.command, f"a .NET call returned for output {output!r}"

    def test_machine_inactivity_policy_is_pass(self):
        # A machine-wide inactivity lock counts even without a per-user screensaver.
        with patch("apotrope.checks.misc.run_powershell_json",
                   return_value={"Active": "0", "Secure": "0", "Timeout": 0,
                                 "MachineInactivity": 600}):
            r = misc._check_screen_lock()[0]
        assert r.status == Status.PASS
