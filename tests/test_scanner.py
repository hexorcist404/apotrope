"""Tests for apotrope.scanner — admin detection, REQUIRES_ADMIN skipping, timing."""

from __future__ import annotations

from types import ModuleType
from unittest.mock import patch


from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.scanner import Scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_module(
    name: str = "test_mod",
    category: str = "Test",
    results: list[CheckResult] | None = None,
    requires_admin: bool = False,
    run_raises: Exception | None = None,
) -> ModuleType:
    """Return a minimal fake check module."""
    mod = ModuleType(name)
    mod.CATEGORY = category
    if requires_admin:
        mod.REQUIRES_ADMIN = True

    if run_raises is not None:
        def _run():
            raise run_raises
        mod.run = _run
    else:
        _results = results or [CheckResult(
            category=category,
            check_name="Dummy Check",
            status=Status.PASS,
            severity=Severity.LOW,
            description="desc",
            details="ok",
        )]
        mod.run = lambda: _results

    return mod


def _pass_result(category: str = "Test") -> CheckResult:
    return CheckResult(
        category=category, check_name="x", status=Status.PASS,
        severity=Severity.LOW, description="d", details="ok",
    )


# ---------------------------------------------------------------------------
# Basic construction
# ---------------------------------------------------------------------------

class TestScannerInit:
    def test_defaults(self):
        s = Scanner()
        assert s.categories is None
        assert s.is_admin is False

    def test_categories_stored(self):
        s = Scanner(categories=["firewall"])
        assert s.categories == ["firewall"]

    def test_is_admin_stored(self):
        s = Scanner(is_admin=True)
        assert s.is_admin is True


# ---------------------------------------------------------------------------
# REQUIRES_ADMIN skipping
# ---------------------------------------------------------------------------

class TestRequiresAdminSkipping:
    def test_admin_module_skipped_when_not_admin(self):
        scanner = Scanner(is_admin=False)
        mod = _make_module(category="Encryption", requires_admin=True)
        results = scanner._run_module(mod)
        assert len(results) == 1
        assert results[0].status == Status.INFO
        assert "administrator" in results[0].details.lower()

    def test_admin_module_runs_when_admin(self):
        scanner = Scanner(is_admin=True)
        expected = [_pass_result("Encryption")]
        mod = _make_module(category="Encryption", results=expected, requires_admin=True)
        results = scanner._run_module(mod)
        assert results == expected

    def test_non_admin_module_always_runs(self):
        scanner = Scanner(is_admin=False)
        expected = [_pass_result()]
        mod = _make_module(results=expected)
        results = scanner._run_module(mod)
        assert results == expected

    def test_skipped_result_category_matches_module(self):
        scanner = Scanner(is_admin=False)
        mod = _make_module(category="File Sharing", requires_admin=True)
        results = scanner._run_module(mod)
        assert results[0].category == "File Sharing"

    def test_no_requires_admin_attribute_runs(self):
        """Module without REQUIRES_ADMIN attribute should always run."""
        scanner = Scanner(is_admin=False)
        mod = _make_module()
        # Ensure the attribute is absent
        assert not hasattr(mod, "REQUIRES_ADMIN")
        results = scanner._run_module(mod)
        assert results[0].status == Status.PASS


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestModuleErrorHandling:
    def test_exception_returns_error_status(self):
        scanner = Scanner()
        mod = _make_module(run_raises=RuntimeError("boom"))
        results = scanner._run_module(mod)
        assert len(results) == 1
        assert results[0].status == Status.ERROR
        assert "boom" in results[0].details

    def test_exception_category_from_module(self):
        scanner = Scanner()
        mod = _make_module(category="Firewall", run_raises=ValueError("oops"))
        results = scanner._run_module(mod)
        assert results[0].category == "Firewall"

    def test_wrong_return_type_becomes_error(self):
        scanner = Scanner()
        mod = ModuleType("bad_mod")
        mod.CATEGORY = "Test"
        mod.run = lambda: "not a list"
        results = scanner._run_module(mod)
        assert results[0].status == Status.ERROR


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

class TestCheckTiming:
    def test_check_duration_set_on_results(self):
        scanner = Scanner()
        mod = _make_module(results=[_pass_result(), _pass_result()])
        results = scanner._run_module(mod)
        assert all(r.check_duration >= 0.0 for r in results)

    def test_check_duration_non_negative(self):
        scanner = Scanner()
        mod = _make_module()
        results = scanner._run_module(mod)
        assert results[0].check_duration >= 0.0

    def test_skipped_module_duration_zero(self):
        scanner = Scanner(is_admin=False)
        mod = _make_module(requires_admin=True)
        results = scanner._run_module(mod)
        # Skipped modules get no timing
        assert results[0].check_duration == 0.0


# ---------------------------------------------------------------------------
# report.is_admin reflects scanner.is_admin
# ---------------------------------------------------------------------------

class TestReportAdminFlag:
    def _run_with_mocks(self, is_admin: bool) -> AuditReport:
        scanner = Scanner(is_admin=is_admin)
        mod = _make_module()
        with patch.object(scanner, "_discover_modules", return_value=[mod]):
            return scanner.run()

    def test_report_is_admin_true(self):
        report = self._run_with_mocks(is_admin=True)
        assert report.is_admin is True

    def test_report_is_admin_false(self):
        report = self._run_with_mocks(is_admin=False)
        assert report.is_admin is False


# ---------------------------------------------------------------------------
# error_count property
# ---------------------------------------------------------------------------

class TestErrorCount:
    def test_error_count_in_report(self):
        scanner = Scanner()
        mod = _make_module(run_raises=RuntimeError("fail"))
        with patch.object(scanner, "_discover_modules", return_value=[mod]):
            report = scanner.run()
        assert report.error_count == 1

    def test_error_count_zero_when_clean(self):
        scanner = Scanner()
        mod = _make_module()
        with patch.object(scanner, "_discover_modules", return_value=[mod]):
            report = scanner.run()
        assert report.error_count == 0


# ---------------------------------------------------------------------------
# on_module_start callback
# ---------------------------------------------------------------------------

class TestOnModuleStart:
    def test_callback_called_for_each_module(self):
        scanner = Scanner()
        mods = [_make_module(f"mod_{i}", f"Cat{i}") for i in range(3)]
        called = []

        def _cb(m):
            called.append(m.__name__)

        with patch.object(scanner, "_discover_modules", return_value=mods):
            scanner.run(on_module_start=_cb)

        assert called == [m.__name__ for m in mods]

    def test_callback_exception_does_not_abort_scan(self):
        scanner = Scanner()
        mod = _make_module()

        def _bad_cb(m):
            raise RuntimeError("callback exploded")

        with patch.object(scanner, "_discover_modules", return_value=[mod]):
            report = scanner.run(on_module_start=_bad_cb)

        assert len(report.results) == 1
