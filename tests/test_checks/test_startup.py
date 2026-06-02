"""Tests for apotrope.checks.startup."""

from __future__ import annotations

from unittest.mock import patch

from apotrope.checks import startup
from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Status, Severity


def _item(name: str = "MyApp", command: str = "C:\\app.exe") -> dict:
    return {"Name": name, "Command": command, "Location": "HKLM\\Run", "User": ""}


# ---------------------------------------------------------------------------
# _check_startup_programs
# ---------------------------------------------------------------------------

class TestCheckStartupPrograms:
    def _run(self, data):
        with patch("apotrope.checks.startup.run_powershell_json", return_value=data):
            return startup._check_startup_programs()

    def test_empty_data_says_no_programs(self):
        r = self._run([])[0]
        assert r.status == Status.INFO
        assert "No startup" in r.details

    def test_single_item_reported(self):
        r = self._run([_item("OneDrive")])[0]
        assert "1" in r.details
        assert "OneDrive" in r.details

    def test_multiple_items_counted(self):
        items = [_item(f"App{i}") for i in range(5)]
        r = self._run(items)[0]
        assert "5" in r.details

    def test_more_than_20_truncated(self):
        items = [_item(f"App{i}") for i in range(25)]
        r = self._run(items)[0]
        assert "+5 more" in r.details

    def test_single_dict_wrapped(self):
        r = self._run(_item("SingularApp"))[0]
        assert "SingularApp" in r.details

    def test_status_always_info(self):
        r = self._run([_item()])[0]
        assert r.status == Status.INFO
        assert r.severity == Severity.LOW

    def test_error_returns_error(self):
        with patch("apotrope.checks.startup.run_powershell_json",
                   side_effect=ApotropeError("denied")):
            r = startup._check_startup_programs()[0]
        assert r.status == Status.ERROR

    def test_check_name(self):
        r = self._run([])[0]
        assert r.check_name == "Startup Programs"

    def test_category_is_persistence(self):
        r = self._run([])[0]
        assert r.category == "Persistence"


# ---------------------------------------------------------------------------
# _check_scheduled_tasks
# ---------------------------------------------------------------------------

class TestCheckScheduledTasks:
    def _task(self, name: str = "MyTask") -> dict:
        return {"TaskName": name, "TaskPath": "\\Custom\\", "RunAs": "SYSTEM", "State": "Ready"}

    def _run(self, data):
        with patch("apotrope.checks.startup.run_powershell_json", return_value=data):
            return startup._check_scheduled_tasks()

    def test_empty_data_says_no_tasks(self):
        r = self._run([])[0]
        assert "No non-Microsoft" in r.details

    def test_tasks_reported(self):
        r = self._run([self._task("BackupJob"), self._task("Updater")])[0]
        assert "2" in r.details
        assert "BackupJob" in r.details

    def test_more_than_20_truncated(self):
        tasks = [self._task(f"Task{i}") for i in range(25)]
        r = self._run(tasks)[0]
        assert "+5 more" in r.details

    def test_status_always_info(self):
        r = self._run([self._task()])[0]
        assert r.status == Status.INFO

    def test_error_returns_error(self):
        with patch("apotrope.checks.startup.run_powershell_json",
                   side_effect=ApotropeError("boom")):
            r = startup._check_scheduled_tasks()[0]
        assert r.status == Status.ERROR


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_two_results(self):
        empty = []
        with patch("apotrope.checks.startup.run_powershell_json", return_value=empty):
            results = startup.run()
        assert len(results) == 2
        assert all(isinstance(r, CheckResult) for r in results)

    def test_run_check_names(self):
        with patch("apotrope.checks.startup.run_powershell_json", return_value=[]):
            results = startup.run()
        names = {r.check_name for r in results}
        assert "Startup Programs" in names
        assert "Scheduled Tasks" in names
