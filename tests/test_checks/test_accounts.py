"""Tests for apotrope.checks.accounts (SID-based identification)."""

from __future__ import annotations

from unittest.mock import patch

from apotrope import cis_map
from apotrope.checks import accounts
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


def _user(name: str, enabled: bool, rid: str) -> dict:
    return {"Name": name, "Enabled": enabled, "SID": f"S-1-5-21-1-2-3-{rid}"}


# ---------------------------------------------------------------------------
# _check_guest_account (RID-501, not name)
# ---------------------------------------------------------------------------

class TestCheckGuestAccount:
    def _run(self, users):
        with patch("apotrope.checks.accounts.run_powershell_json", return_value=users):
            return accounts._check_guest_account()

    def test_guest_disabled_is_pass(self):
        r = self._run([_user("Guest", False, "501")])[0]
        assert r.status == Status.PASS
        assert r.severity == Severity.HIGH

    def test_guest_enabled_is_fail(self):
        r = self._run([_user("Guest", True, "501")])[0]
        assert r.status == Status.FAIL
        assert "enabled" in r.details.lower()
        assert "Disable-LocalUser -SID" in r.command

    def test_renamed_enabled_guest_still_fails(self):
        # SID beats name: a renamed-but-enabled guest (e.g. localized) must FAIL,
        # where the old name-based lookup produced a reassuring "not found".
        r = self._run([_user("Visitor", True, "501")])[0]
        assert r.status == Status.FAIL

    def test_no_rid501_is_info(self):
        # Successful enumeration lacking RID-501 → genuinely absent → INFO.
        r = self._run([_user("Administrator", True, "500")])[0]
        assert r.status == Status.INFO
        assert "not present" in r.details.lower()

    def test_query_failure_is_error(self):
        with patch("apotrope.checks.accounts.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            r = accounts._check_guest_account()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_builtin_admin (RID-500; renamed-enabled WARN branch is now live)
# ---------------------------------------------------------------------------

class TestCheckBuiltinAdmin:
    def _run(self, users):
        with patch("apotrope.checks.accounts.run_powershell_json", return_value=users):
            return accounts._check_builtin_admin()

    def test_enabled_default_name_is_fail(self):
        r = self._run([_user("Administrator", True, "500")])[0]
        assert r.status == Status.FAIL
        assert r.severity == Severity.MEDIUM
        assert "Disable-LocalUser -SID" in r.command

    def test_renamed_enabled_is_warn(self):
        r = self._run([_user("CorpAdmin", True, "500")])[0]
        assert r.status == Status.WARN
        assert r.severity == Severity.LOW
        assert "CorpAdmin" in r.details

    def test_disabled_is_pass(self):
        r = self._run([_user("Administrator", False, "500")])[0]
        assert r.status == Status.PASS

    def test_disabled_renamed_is_pass(self):
        r = self._run([_user("CorpAdmin", False, "500")])[0]
        assert r.status == Status.PASS
        assert "CorpAdmin" in r.details

    def test_no_rid500_is_info(self):
        r = self._run([_user("Guest", False, "501")])[0]
        assert r.status == Status.INFO
        assert "not present" in r.details.lower()

    def test_rid1500_not_mistaken_for_500(self):
        # Hyphen-anchored suffix: -1500 must not match -500.
        r = self._run([_user("Weird", True, "1500")])[0]
        assert r.status == Status.INFO

    def test_query_failure_is_error(self):
        with patch("apotrope.checks.accounts.run_powershell_json",
                   side_effect=ApotropeError("access denied")):
            r = accounts._check_builtin_admin()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _check_admin_count (SID-544; empty → ERROR, never a false "0 admins" PASS)
# ---------------------------------------------------------------------------

class TestCheckAdminCount:
    def _run(self, members):
        with patch("apotrope.checks.accounts.run_powershell_json", return_value=members):
            return accounts._check_admin_count()

    def test_one_admin_is_pass(self):
        r = self._run([{"Name": "MACHINE\\Admin"}])[0]
        assert r.status == Status.PASS

    def test_two_admins_is_pass(self):
        r = self._run([{"Name": "MACHINE\\Admin"}, {"Name": "MACHINE\\Domain Admins"}])[0]
        assert r.status == Status.PASS

    def test_three_admins_is_warn(self):
        members = [{"Name": f"MACHINE\\Admin{i}"} for i in range(1, 4)]
        r = self._run(members)[0]
        assert r.status == Status.WARN
        assert "3" in r.details

    def test_domain_prefix_stripped_from_display(self):
        r = self._run([{"Name": "MACHINE\\Alice"}])[0]
        assert "Alice" in r.details
        assert "MACHINE" not in r.details

    def test_single_dict_wrapped(self):
        r = self._run({"Name": "MACHINE\\Admin"})[0]
        assert r.status == Status.PASS

    def test_empty_members_is_error(self):
        # The built-in group always has >=1 member; empty == failed enumeration.
        r = self._run([])[0]
        assert r.status == Status.ERROR

    def test_query_uses_well_known_sid(self):
        assert accounts._ADMINISTRATORS_SID == "S-1-5-32-544"
        assert "S-1-5-32-544" in accounts._PS_ADMINS

    def test_query_failure_is_error(self):
        with patch("apotrope.checks.accounts.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            r = accounts._check_admin_count()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# _parse_secedit_inf helper
# ---------------------------------------------------------------------------

class TestParseSeceditInf:
    _SAMPLE = (
        "[Unicode]\n"
        "Unicode=yes\n"
        "[System Access]\n"
        "MinimumPasswordLength = 14\n"
        "LockoutBadCount = 5\n"
        "PasswordComplexity = 1\n"
        "[Version]\n"
        "signature=\"$CHICAGO$\"\n"
    )

    def test_parses_and_lowercases_keys(self):
        parsed = accounts._parse_secedit_inf(self._SAMPLE)
        assert parsed["minimumpasswordlength"] == "14"
        assert parsed["lockoutbadcount"] == "5"
        assert parsed["passwordcomplexity"] == "1"

    def test_section_headers_ignored(self):
        parsed = accounts._parse_secedit_inf(self._SAMPLE)
        assert "[system access]" not in parsed

    def test_empty_output(self):
        assert accounts._parse_secedit_inf("") == {}


# ---------------------------------------------------------------------------
# _check_password_policy (secedit INF, locale-neutral)
# ---------------------------------------------------------------------------

class TestCheckPasswordPolicy:
    def _inf(self, *, min_len="14", lockout="5", complexity="1"):
        lines = ["[System Access]"]
        if min_len is not None:
            lines.append(f"MinimumPasswordLength = {min_len}")
        if lockout is not None:
            lines.append(f"LockoutBadCount = {lockout}")
        lines.append("LockoutDuration = 30")
        if complexity is not None:
            lines.append(f"PasswordComplexity = {complexity}")
        return "\n".join(lines) + "\n"

    def _run(self, inf_text):
        with patch("apotrope.checks.accounts.run_powershell", return_value=inf_text):
            return accounts._check_password_policy()

    def _by_name(self, results, needle):
        return next(r for r in results if needle in r.check_name)

    def test_all_good_returns_passes(self):
        results = self._run(self._inf())
        assert self._by_name(results, "Length").status == Status.PASS
        assert self._by_name(results, "Lockout").status == Status.PASS
        assert self._by_name(results, "Complexity").status == Status.PASS

    def test_short_password_is_fail(self):
        r = self._by_name(self._run(self._inf(min_len="6")), "Length")
        assert r.status == Status.FAIL
        assert r.severity == Severity.HIGH

    def test_warn_length_is_warn(self):
        r = self._by_name(self._run(self._inf(min_len="10")), "Length")
        assert r.status == Status.WARN

    def test_no_lockout_is_warn(self):
        r = self._by_name(self._run(self._inf(lockout="0")), "Lockout")
        assert r.status == Status.WARN
        assert "net accounts" in r.command

    def test_complexity_disabled_is_fail(self):
        r = self._by_name(self._run(self._inf(complexity="0")), "Complexity")
        assert r.status == Status.FAIL

    def test_missing_min_length_is_error(self):
        r = self._by_name(self._run(self._inf(min_len=None)), "Length")
        assert r.status == Status.ERROR

    def test_missing_lockout_is_error(self):
        r = self._by_name(self._run(self._inf(lockout=None)), "Lockout")
        assert r.status == Status.ERROR

    def test_missing_complexity_is_error(self):
        r = self._by_name(self._run(self._inf(complexity=None)), "Complexity")
        assert r.status == Status.ERROR

    def test_non_integer_min_length_is_error(self):
        r = self._by_name(self._run(self._inf(min_len="lots")), "Length")
        assert r.status == Status.ERROR

    def test_non_integer_lockout_is_error(self):
        r = self._by_name(self._run(self._inf(lockout="lots")), "Lockout")
        assert r.status == Status.ERROR

    def test_success_and_failure_paths_agree_on_names(self):
        # If any path ever disagrees, a --compare diff reads the mismatch as one
        # control vanishing and another appearing.
        with patch("apotrope.checks.accounts.run_powershell",
                   return_value=self._inf()):
            ok = accounts._check_password_policy()
        assert [r.check_name for r in ok] == list(accounts._PW_POLICY_CHECKS)


# ---------------------------------------------------------------------------
# Non-elevated fallback: secedit needs admin, NetUserModalsGet does not
# ---------------------------------------------------------------------------

class TestPasswordPolicyWithoutSecedit:
    """A non-elevated scan must still produce real verdicts, not three ERRORs.

    ``secedit /export`` reads a database ACL'd to SYSTEM and Administrators, so
    the documented default invocation cannot use it. Minimum length and lockout
    come from ``NetUserModalsGet`` instead — unprivileged and locale-neutral.
    """

    _MODALS = {
        "minimumpasswordlength": "0",
        "passwordhistorysize": "0",
        "lockoutbadcount": "10",
        "lockoutduration": "30",
        "resetlockoutcount": "30",
    }

    def _run(self, modals=None, modals_raises=None):
        kw = {"side_effect": modals_raises} if modals_raises else {"return_value": modals}
        with (
            patch("apotrope.checks.accounts.run_powershell",
                  side_effect=ApotropeError("secedit exited 1")),
            patch("apotrope.checks.accounts.read_password_policy", **kw),
        ):
            return accounts._check_password_policy()

    def _by(self, results, needle):
        return next(r for r in results if needle in r.check_name)

    def test_weak_length_is_still_a_fail_without_elevation(self):
        # THE POINT OF THIS CHANGE. MinimumPasswordLength=0 is a HIGH FAIL worth
        # -10. Reporting it as an unscored ERROR inflates the score on exactly
        # the machines that deserve the deduction.
        r = self._by(self._run(self._MODALS), "Minimum Length")
        assert r.status == Status.FAIL
        assert r.severity == Severity.HIGH

    def test_lockout_is_evaluated_without_elevation(self):
        r = self._by(self._run(self._MODALS), "Account Lockout")
        assert r.status == Status.PASS
        assert "10 attempt(s)" in r.details

    def test_complexity_is_reported_unmeasurable_not_guessed(self):
        # Complexity is an LSA setting with no USER_MODALS_INFO field. Inventing
        # a value would be the confidently-wrong verdict this module avoids.
        r = self._by(self._run(self._MODALS), "Complexity")
        assert r.status == Status.ERROR
        assert "Administrator" in r.remediation

    def test_all_three_controls_still_reported_and_cis_mapped(self):
        results = self._run(self._MODALS)
        assert [r.check_name for r in results] == list(accounts._PW_POLICY_CHECKS)
        for r in results:
            assert cis_map.lookup(r.check_name), f"{r.check_name!r} lost its CIS reference"

    def test_strong_policy_passes_without_elevation(self):
        strong = {**self._MODALS, "minimumpasswordlength": "14"}
        r = self._by(self._run(strong), "Minimum Length")
        assert r.status == Status.PASS

    def test_both_sources_failing_degrades_every_control(self):
        # Lack of elevation no longer lands here; reaching it means the machine
        # genuinely is not answering, so both causes are reported.
        results = self._run(modals_raises=ApotropeError("netapi32 status 5"))
        assert [r.check_name for r in results] == list(accounts._PW_POLICY_CHECKS)
        assert all(r.status == Status.ERROR for r in results)
        for r in results:
            assert "secedit exited 1" in r.details
            assert "netapi32 status 5" in r.details

    def test_fallback_is_not_used_when_secedit_works(self):
        # The fallback must never override the richer source.
        inf = (
            "[System Access]\nMinimumPasswordLength = 14\nLockoutBadCount = 5\n"
            "LockoutDuration = 30\nPasswordComplexity = 1\n"
        )
        with (
            patch("apotrope.checks.accounts.run_powershell", return_value=inf),
            patch("apotrope.checks.accounts.read_password_policy") as modals,
        ):
            results = accounts._check_password_policy()
        modals.assert_not_called()
        assert next(r for r in results if "Complexity" in r.check_name).status == Status.PASS


# ---------------------------------------------------------------------------
# run() top-level
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_list_of_check_results(self):
        users = [_user("Administrator", False, "500"), _user("Guest", False, "501")]
        admins = [{"Name": "MACHINE\\Admin"}]
        inf = (
            "[System Access]\n"
            "MinimumPasswordLength = 14\n"
            "LockoutBadCount = 5\n"
            "LockoutDuration = 30\n"
            "PasswordComplexity = 1\n"
        )
        with (
            # guest -> users, admin -> users, admin_count -> admins
            patch("apotrope.checks.accounts.run_powershell_json",
                  side_effect=[users, users, admins]),
            patch("apotrope.checks.accounts.run_powershell", return_value=inf),
        ):
            results = accounts.run()
        assert all(isinstance(r, CheckResult) for r in results)
        assert len(results) >= 6
