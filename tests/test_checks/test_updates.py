"""Tests for apotrope.checks.updates."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import patch


from apotrope.checks import updates
from apotrope.exceptions import ApotropeError
from apotrope.models import Status, Severity

# Fixed reference date
_REF = datetime(2026, 3, 17, tzinfo=timezone.utc)


def _date_str(days_ago: int) -> str:
    return (_REF - timedelta(days=days_ago)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# _check_last_update
# ---------------------------------------------------------------------------

class TestCheckLastUpdate:
    def test_recent_update_returns_pass(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=_date_str(5)), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.PASS
        assert results[0].severity == Severity.CRITICAL

    def test_update_just_at_warn_threshold_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=_date_str(30)), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.WARN
        assert results[0].severity == Severity.HIGH

    def test_update_over_warn_threshold_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=_date_str(45)), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.WARN

    def test_update_at_fail_threshold_returns_fail(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=_date_str(60)), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.FAIL
        assert results[0].severity == Severity.CRITICAL

    def test_very_old_update_returns_critical_fail(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=_date_str(180)), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.FAIL
        assert results[0].severity == Severity.CRITICAL
        assert results[0].remediation != ""

    def test_no_hotfix_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="NONE"):
            results = updates._check_last_update()
        assert results[0].status == Status.WARN

    def test_empty_output_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=""):
            results = updates._check_last_update()
        assert results[0].status == Status.WARN

    def test_malformed_date_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="not-a-date"), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert results[0].status == Status.ERROR

    def test_ps_error_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=ApotropeError("access denied")):
            results = updates._check_last_update()
        assert results[0].status == Status.ERROR

    def test_details_include_date(self):
        date_str = _date_str(10)
        with patch("apotrope.checks.updates.run_powershell", return_value=date_str), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates._check_last_update()
        assert date_str in results[0].details


# ---------------------------------------------------------------------------
# _check_wu_service
# ---------------------------------------------------------------------------

class TestCheckWuService:
    def test_automatic_running_returns_pass(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Automatic|Running"):
            results = updates._check_wu_service()
        assert results[0].status == Status.PASS
        assert results[0].remediation == ""
        assert results[0].command == ""

    def test_automatic_stopped_returns_pass(self):
        # The fix: a normally-idle (Stopped) Automatic service is NOT a finding.
        with patch("apotrope.checks.updates.run_powershell", return_value="Automatic|Stopped"):
            results = updates._check_wu_service()
        assert results[0].status == Status.PASS

    def test_manual_stopped_returns_pass(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Manual|Stopped"):
            results = updates._check_wu_service()
        assert results[0].status == Status.PASS

    def test_disabled_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Disabled|Stopped"):
            results = updates._check_wu_service()
        assert results[0].status == Status.WARN
        assert results[0].severity == Severity.HIGH
        assert results[0].remediation != ""
        assert "Set-Service" in results[0].command

    def test_disabled_case_insensitive(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="disabled|Stopped"):
            results = updates._check_wu_service()
        assert results[0].status == Status.WARN

    def test_empty_output_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=""):
            results = updates._check_wu_service()
        assert results[0].status == Status.ERROR

    def test_ps_error_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=ApotropeError("service not found")):
            results = updates._check_wu_service()
        assert results[0].status == Status.ERROR

    def test_details_include_start_type_and_state(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Automatic|Stopped"):
            results = updates._check_wu_service()
        assert "Stopped" in results[0].details
        assert "Automatic" in results[0].details


# ---------------------------------------------------------------------------
# _check_pending_updates
# ---------------------------------------------------------------------------

class TestCheckPendingUpdates:
    def test_zero_pending_returns_pass(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="0"):
            results = updates._check_pending_updates()
        assert results[0].status == Status.PASS

    def test_pending_updates_returns_fail(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="5"):
            results = updates._check_pending_updates()
        assert results[0].status == Status.FAIL
        assert "5" in results[0].details
        assert results[0].remediation != ""

    def test_one_pending_update_returns_fail(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="1"):
            results = updates._check_pending_updates()
        assert results[0].status == Status.FAIL

    def test_unavailable_returns_info(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="UNAVAILABLE"):
            results = updates._check_pending_updates()
        assert results[0].status == Status.INFO

    def test_unexpected_output_returns_info(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="some-error-text"):
            results = updates._check_pending_updates()
        assert results[0].status == Status.INFO

    def test_ps_error_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=ApotropeError("COM error")):
            results = updates._check_pending_updates()
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# run() — integration
# ---------------------------------------------------------------------------

class TestUpdatesRun:
    def test_returns_three_results(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=[_date_str(5), "Automatic|Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert len(results) == 3

    def test_all_results_have_category_patching(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=[_date_str(5), "Automatic|Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert all(r.category == "Patching" for r in results)

    def test_error_in_one_check_does_not_stop_others(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=[ApotropeError("fail"), "Automatic|Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert len(results) == 3
        assert results[0].status == Status.ERROR
        assert results[1].status == Status.PASS   # Running
        assert results[2].status == Status.PASS   # 0 pending


# ---------------------------------------------------------------------------
# configure() — profile threshold overrides
# ---------------------------------------------------------------------------

class TestConfigure:
    def setup_method(self):
        self._orig = (updates._WARN_DAYS, updates._FAIL_DAYS)

    def teardown_method(self):
        updates._WARN_DAYS, updates._FAIL_DAYS = self._orig

    def test_thresholds_override_module_defaults(self):
        updates.configure({"max_update_age_warn": 45, "max_update_age_fail": 90})
        assert updates._WARN_DAYS == 45
        assert updates._FAIL_DAYS == 90

    def test_partial_thresholds_only_change_named_key(self):
        updates.configure({"max_update_age_warn": 10})
        assert updates._WARN_DAYS == 10
        assert updates._FAIL_DAYS == self._orig[1]

    def test_unknown_keys_ignored(self):
        updates.configure({"unrelated_threshold": 5})
        assert (updates._WARN_DAYS, updates._FAIL_DAYS) == self._orig

    def test_values_coerced_to_int(self):
        updates.configure({"max_update_age_warn": "45"})
        assert updates._WARN_DAYS == 45

    def test_reset_restores_defaults(self):
        updates.configure({"max_update_age_warn": 45, "max_update_age_fail": 90})
        updates.reset()
        assert updates._WARN_DAYS == updates._DEFAULT_WARN_DAYS
        assert updates._FAIL_DAYS == updates._DEFAULT_FAIL_DAYS


class TestNowHelper:
    def test_now_returns_utc_aware_datetime(self):
        now = updates._now()
        assert now.tzinfo is timezone.utc


def test_pending_query_excludes_hidden_updates():
    # Admin-hidden updates must not be counted as pending (false FAIL otherwise).
    assert "IsHidden=0" in updates._PS_PENDING
