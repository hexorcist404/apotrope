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
    # setattr (not mod.attr =) so mypy accepts dynamic attributes on ModuleType.
    mod = ModuleType(name)
    setattr(mod, "CATEGORY", category)
    if requires_admin:
        setattr(mod, "REQUIRES_ADMIN", True)

    if run_raises is not None:
        def _run():
            raise run_raises
        setattr(mod, "run", _run)
    else:
        _results = results or [CheckResult(
            category=category,
            check_name="Dummy Check",
            status=Status.PASS,
            severity=Severity.LOW,
            description="desc",
            details="ok",
        )]
        setattr(mod, "run", lambda: _results)

    return mod


def _pass_result(category: str = "Test") -> CheckResult:
    return CheckResult(
        category=category, check_name="x", status=Status.PASS,
        severity=Severity.LOW, description="d", details="ok",
    )


# ---------------------------------------------------------------------------
# Profile threshold configuration must not leak across runs (finding #2)
# ---------------------------------------------------------------------------

class TestThresholdConfigureReset:
    def _configurable_module(self, calls: list) -> ModuleType:
        """A fake module that records its configure/run/reset call order."""
        mod = ModuleType("configurable_mod")
        setattr(mod, "CATEGORY", "Configurable")

        def _configure(thresholds):
            calls.append(("configure", dict(thresholds)))

        def _reset():
            calls.append(("reset", None))

        def _run():
            calls.append(("run", None))
            return []

        setattr(mod, "configure", _configure)
        setattr(mod, "reset", _reset)
        setattr(mod, "run", _run)
        return mod

    def test_configure_then_run_then_reset_in_order(self):
        from apotrope.profile import Profile
        calls: list = []
        module = self._configurable_module(calls)
        scanner = Scanner(profile=Profile(thresholds={"max_update_age_fail": 90}))
        scanner._run_module(module)
        assert [c[0] for c in calls] == ["configure", "run", "reset"]

    def test_no_profile_means_no_configure_or_reset(self):
        calls: list = []
        module = self._configurable_module(calls)
        scanner = Scanner(profile=None)
        scanner._run_module(module)
        assert [c[0] for c in calls] == ["run"]

    def test_reset_failure_is_swallowed(self):
        """A module whose reset() raises must not break the scan."""
        from apotrope.profile import Profile
        calls: list = []
        module = self._configurable_module(calls)

        def _bad_reset():
            raise RuntimeError("boom")

        setattr(module, "reset", _bad_reset)
        scanner = Scanner(profile=Profile(thresholds={"max_update_age_fail": 90}))
        results = scanner._run_module(module)  # must not raise
        assert isinstance(results, list)
        assert [c[0] for c in calls] == ["configure", "run"]

    def test_real_updates_thresholds_do_not_leak_after_run(self):
        """The real updates module's profile thresholds must be reset after it runs, so a
        later scan in the same process is not silently using the previous profile's values."""
        from apotrope.checks import updates
        from apotrope.profile import Profile
        default_fail, default_warn = updates._DEFAULT_FAIL_DAYS, updates._DEFAULT_WARN_DAYS
        scanner = Scanner(profile=Profile(thresholds={
            "max_update_age_fail": default_fail + 30,
            "max_update_age_warn": default_warn + 30,
        }))
        try:
            with patch("apotrope.checks.updates.run_powershell", return_value="NONE"):
                scanner._run_module(updates)
            assert updates._FAIL_DAYS == default_fail
            assert updates._WARN_DAYS == default_warn
        finally:
            updates.reset()


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


# ---------------------------------------------------------------------------
# Module discovery (_discover_modules / discover_modules / dry_run)
# ---------------------------------------------------------------------------

class TestDiscoverModules:
    def test_discovers_all_check_modules(self):
        mods = Scanner()._discover_modules()
        short_names = {m.__name__.rsplit(".", 1)[-1] for m in mods}
        assert {"firewall", "smb", "updates", "uac"} <= short_names
        assert len(mods) >= 14
        assert all(callable(m.run) for m in mods)

    def test_public_wrapper_matches_dry_run(self):
        scanner = Scanner()
        assert [m.__name__ for m in scanner.discover_modules()] == scanner.dry_run()

    def test_dry_run_returns_full_module_names(self):
        names = Scanner().dry_run()
        assert "apotrope.checks.firewall" in names
        assert all(isinstance(n, str) for n in names)

    def test_category_filter_selects_matching_module(self):
        mods = Scanner(categories=["firewall"])._discover_modules()
        assert [m.__name__ for m in mods] == ["apotrope.checks.firewall"]

    def test_category_filter_matches_category_attribute_not_filename(self):
        # updates.py declares CATEGORY = "Patching"
        mods = Scanner(categories=["patching"])._discover_modules()
        assert [m.__name__ for m in mods] == ["apotrope.checks.updates"]

    def test_category_filter_no_match_returns_empty(self):
        assert Scanner(categories=["nonexistent"])._discover_modules() == []

    def test_module_without_run_is_skipped(self):
        from types import SimpleNamespace

        bad = ModuleType("apotrope.checks.badmod")
        bad.CATEGORY = "Bad"
        with (
            patch("apotrope.scanner.pkgutil.iter_modules",
                  return_value=[SimpleNamespace(name="badmod")]),
            patch("apotrope.scanner.importlib.import_module", return_value=bad),
        ):
            assert Scanner()._discover_modules() == []

    def test_private_modules_ignored(self):
        from types import SimpleNamespace

        with patch("apotrope.scanner.pkgutil.iter_modules",
                   return_value=[SimpleNamespace(name="_private")]):
            assert Scanner()._discover_modules() == []

    def test_import_failure_skips_module(self):
        from types import SimpleNamespace

        with (
            patch("apotrope.scanner.pkgutil.iter_modules",
                  return_value=[SimpleNamespace(name="broken")]),
            patch("apotrope.scanner.importlib.import_module",
                  side_effect=ImportError("nope")),
        ):
            assert Scanner()._discover_modules() == []

    def test_frozen_bundle_uses_module_registry(self):
        """PyInstaller path: discovery reads checks.MODULES, not pkgutil."""
        import sys

        good = _make_module("apotrope.checks.frozen_mod", "Frozen")
        with (
            patch.object(sys, "frozen", True, create=True),
            patch("apotrope.checks.MODULES", ["frozen_mod"]),
            patch("apotrope.scanner.importlib.import_module",
                  return_value=good) as imp,
        ):
            mods = Scanner()._discover_modules()
        assert mods == [good]
        imp.assert_called_once_with("apotrope.checks.frozen_mod")


# ---------------------------------------------------------------------------
# Profile integration (_apply_profile, configure() thresholds)
# ---------------------------------------------------------------------------

def _named_result(name: str, severity: Severity = Severity.HIGH) -> CheckResult:
    return CheckResult(
        category="Test", check_name=name, status=Status.FAIL,
        severity=severity, description="d", details="found", remediation="fix",
    )


class TestApplyProfile:
    def _run_with_profile(self, profile, results) -> AuditReport:
        from apotrope.profile import Profile  # noqa: F401 — type for clarity

        scanner = Scanner(profile=profile)
        mod = _make_module(results=results)
        with patch.object(scanner, "_discover_modules", return_value=[mod]):
            return scanner.run()

    def test_disabled_checks_removed_from_report(self):
        from apotrope.profile import Profile

        report = self._run_with_profile(
            Profile(disabled_checks=["Noisy Check"]),
            [_named_result("Noisy Check"), _named_result("Kept Check")],
        )
        names = [r.check_name for r in report.results]
        assert "Noisy Check" not in names
        assert "Kept Check" in names

    def test_severity_override_applied_case_insensitively(self):
        from apotrope.profile import Profile

        report = self._run_with_profile(
            Profile(severity_overrides={"Kept Check": "low"}),
            [_named_result("Kept Check", Severity.HIGH)],
        )
        assert report.results[0].severity == Severity.LOW

    def test_invalid_severity_override_ignored(self):
        from apotrope.profile import Profile

        report = self._run_with_profile(
            Profile(severity_overrides={"Kept Check": "BOGUS"}),
            [_named_result("Kept Check", Severity.HIGH)],
        )
        assert report.results[0].severity == Severity.HIGH

    def test_checks_without_override_untouched(self):
        from apotrope.profile import Profile

        report = self._run_with_profile(
            Profile(severity_overrides={"Other Check": "LOW"}),
            [_named_result("Kept Check", Severity.CRITICAL)],
        )
        assert report.results[0].severity == Severity.CRITICAL

    def test_score_reflects_filtered_results(self):
        from apotrope.profile import Profile

        # A CRITICAL FAIL (-15) that is disabled must not affect the score.
        report = self._run_with_profile(
            Profile(disabled_checks=["Noisy Check"]),
            [_named_result("Noisy Check", Severity.CRITICAL)],
        )
        assert report.score == 100


class TestProfileThresholds:
    def _profile(self, thresholds):
        from apotrope.profile import Profile

        return Profile(thresholds=thresholds)

    def test_configure_called_with_thresholds(self):
        from unittest.mock import MagicMock

        mod = _make_module()
        mod.configure = MagicMock()
        scanner = Scanner(profile=self._profile({"max_update_age_warn": 45}))
        scanner._run_module(mod)
        mod.configure.assert_called_once_with({"max_update_age_warn": 45})

    def test_configure_failure_does_not_abort_module(self):
        from unittest.mock import MagicMock

        mod = _make_module()
        mod.configure = MagicMock(side_effect=RuntimeError("bad config"))
        scanner = Scanner(profile=self._profile({"k": 1}))
        results = scanner._run_module(mod)
        assert results[0].status == Status.PASS

    def test_module_without_configure_runs_normally(self):
        mod = _make_module()
        assert not hasattr(mod, "configure")
        scanner = Scanner(profile=self._profile({"k": 1}))
        results = scanner._run_module(mod)
        assert results[0].status == Status.PASS

    def test_empty_thresholds_skip_configure(self):
        from unittest.mock import MagicMock

        mod = _make_module()
        mod.configure = MagicMock()
        scanner = Scanner(profile=self._profile({}))
        scanner._run_module(mod)
        mod.configure.assert_not_called()


# ---------------------------------------------------------------------------
# run() with pre-discovered modules; CIS references preserved
# ---------------------------------------------------------------------------

class TestRunWithExplicitModules:
    def test_pre_discovered_modules_skip_discovery(self):
        scanner = Scanner()
        mod = _make_module()
        with patch.object(scanner, "_discover_modules") as discover:
            report = scanner.run(modules=[mod])
        discover.assert_not_called()
        assert len(report.results) == 1


class TestApplyCisReferences:
    def test_existing_reference_not_overwritten(self):
        result = _pass_result()
        result.cis_reference = "CIS 1.2.3"
        Scanner._apply_cis_references([result])
        assert result.cis_reference == "CIS 1.2.3"
