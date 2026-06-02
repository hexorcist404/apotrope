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
    def test_running_service_returns_pass(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Running"):
            results = updates._check_wu_service()
        assert results[0].status == Status.PASS

    def test_stopped_service_returns_warn(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Stopped"):
            results = updates._check_wu_service()
        assert results[0].status == Status.WARN
        assert results[0].remediation != ""

    def test_case_insensitive_running(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="running"):
            results = updates._check_wu_service()
        assert results[0].status == Status.PASS

    def test_empty_output_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell", return_value=""):
            results = updates._check_wu_service()
        assert results[0].status == Status.ERROR

    def test_ps_error_returns_error(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=ApotropeError("service not found")):
            results = updates._check_wu_service()
        assert results[0].status == Status.ERROR

    def test_details_include_service_status(self):
        with patch("apotrope.checks.updates.run_powershell", return_value="Stopped"):
            results = updates._check_wu_service()
        assert "Stopped" in results[0].details


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
                   side_effect=[_date_str(5), "Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert len(results) == 3

    def test_all_results_have_category_patching(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=[_date_str(5), "Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert all(r.category == "Patching" for r in results)

    def test_error_in_one_check_does_not_stop_others(self):
        with patch("apotrope.checks.updates.run_powershell",
                   side_effect=[ApotropeError("fail"), "Running", "0"]), \
             patch("apotrope.checks.updates._now", return_value=_REF):
            results = updates.run()
        assert len(results) == 3
        assert results[0].status == Status.ERROR
        assert results[1].status == Status.PASS   # Running
        assert results[2].status == Status.PASS   # 0 pending
