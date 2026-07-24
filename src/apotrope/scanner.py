"""Audit scanner — discovers and runs all check modules.

Uses importlib to dynamically load every module inside the checks/ package.
Each module must expose a ``run() -> list[CheckResult]`` function.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import platform
import socket
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from apotrope import checks as checks_pkg
from apotrope.models import AuditReport, CheckResult, Status, Severity
from apotrope.scoring import calculate_score
from apotrope.utils import get_wmi_object

if TYPE_CHECKING:
    from apotrope import cis_map
    from apotrope.profile import Profile

log = logging.getLogger(__name__)


def known_categories() -> set[str]:
    """Return the lowercased ``CATEGORY`` of every check module.

    These are exactly the tokens ``--category`` accepts. Derived from the
    modules themselves (not hardcoded) so a new module's category is honoured
    automatically, and mirrors the discovery logic in
    :meth:`Scanner._discover_modules` (``pkgutil`` from source, the explicit
    ``checks.MODULES`` registry when frozen). Importing a module does not run
    its checks, so this is OS-independent and needs no elevation.
    """
    import sys

    if getattr(sys, "frozen", False):
        names: list[str] = list(checks_pkg.MODULES)
    else:
        names = [
            m.name for m in pkgutil.iter_modules(checks_pkg.__path__)
            if not m.name.startswith("_")
        ]

    categories: set[str] = set()
    for name in names:
        try:
            module = importlib.import_module(f"apotrope.checks.{name}")
        except Exception as exc:
            log.error("Failed to import apotrope.checks.%s: %s", name, exc)
            continue
        categories.add(getattr(module, "CATEGORY", name).lower())
    return categories


class Scanner:
    """Discovers check modules and orchestrates an audit run.

    Args:
        categories: If provided, only modules whose ``CATEGORY`` attribute
                    matches one of these strings (case-insensitive) are run.
                    Pass ``None`` (default) to run all modules.
        is_admin:   Whether the current process has administrator privileges.
                    Modules with ``REQUIRES_ADMIN = True`` are skipped when
                    this is ``False``, producing an INFO result instead.
        profile:    Optional :class:`~apotrope.profile.Profile` loaded from
                    a ``apotrope.toml`` file.  Applies disabled checks,
                    severity overrides, and threshold configuration.
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        is_admin: bool = False,
        profile: "Profile | None" = None,
    ) -> None:
        self.categories = categories
        self.is_admin = is_admin
        self.profile = profile

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_modules(self) -> list:
        """Return the list of check modules that would be run (respects category filter)."""
        return self._discover_modules()

    def dry_run(self) -> list[str]:
        """Return the names of modules that would run without executing them.

        Returns:
            List of module names (e.g. ``"apotrope.checks.firewall"``).
        """
        return [m.__name__ for m in self._discover_modules()]

    def run(
        self,
        modules: list | None = None,
        on_module_start=None,
    ) -> AuditReport:
        """Discover check modules, run them, and return an AuditReport.

        Args:
            modules:         Pre-discovered module list; if None, auto-discovered.
            on_module_start: Optional callable(module) called before each module runs.

        Returns:
            A fully-populated AuditReport including score and CIS references.
        """
        if modules is None:
            modules = self._discover_modules()
        log.info("Discovered %d check module(s): %s", len(modules), [m.__name__ for m in modules])

        start = time.monotonic()
        results: list[CheckResult] = []

        for module in modules:
            if on_module_start is not None:
                try:
                    on_module_start(module)
                except Exception:
                    pass
            module_results = self._run_module(module)
            results.extend(module_results)

        # Apply CIS references from the central map, keyed on OS family.
        try:
            build = int(platform.version().split(".")[-1])
        except (ValueError, IndexError):
            build = 0
        from apotrope import cis_map
        family = cis_map.family_for_build(build, self._detect_product_type())
        self._apply_cis_references(results, family=family)

        cis_version = cis_map.benchmark_version(family)
        cis_caveat = cis_map.benchmark_caveat(family)

        # Apply profile transforms (disabled checks, severity overrides)
        if self.profile:
            results = self._apply_profile(results)

        duration = time.monotonic() - start
        score = calculate_score(results)

        error_count = sum(1 for r in results if r.status == Status.ERROR)
        if error_count:
            hint = (
                "run with --log-level DEBUG to see why"
                if self.is_admin
                else "rerun as Administrator for full results"
            )
            log.warning("%d check(s) could not complete — %s.", error_count, hint)

        report = AuditReport(
            hostname=socket.gethostname(),
            os_version=platform.version(),
            scan_timestamp=datetime.now(tz=timezone.utc),
            scan_duration=round(duration, 2),
            results=results,
            score=score,
            is_admin=self.is_admin,
            cis_version=cis_version,
            cis_caveat=cis_caveat,
        )
        log.info(
            "Scan complete: %d results, score=%d, duration=%.2fs",
            len(results),
            score,
            duration,
        )
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_modules(self) -> list:
        """Return a list of check module objects matching the category filter.

        Uses ``pkgutil.iter_modules`` when running from source, and falls back
        to the explicit ``checks.MODULES`` registry when running inside a
        PyInstaller ``--onefile`` bundle (where the archive is not traversable).
        """
        import sys

        discovered = []

        if getattr(sys, "frozen", False):
            # PyInstaller bundle: use the explicit module registry
            check_names: list[str] = list(checks_pkg.MODULES)
        else:
            check_names = [
                m.name for m in pkgutil.iter_modules(checks_pkg.__path__)
                if not m.name.startswith("_")
            ]

        for name in check_names:

            full_name = f"apotrope.checks.{name}"
            try:
                module = importlib.import_module(full_name)
            except Exception as exc:
                log.error("Failed to import %s: %s", full_name, exc)
                continue

            # Category filter
            if self.categories is not None:
                module_category = getattr(module, "CATEGORY", name).lower()
                if module_category not in self.categories:
                    log.debug("Skipping %s (category %r not in filter)", full_name, module_category)
                    continue

            # Must expose a run() callable
            if not callable(getattr(module, "run", None)):
                log.warning("%s has no run() function — skipping", full_name)
                continue

            discovered.append(module)

        return discovered

    def _run_module(self, module) -> list[CheckResult]:
        """Run a single check module and return its results.

        Handles three cases:
        - Module requires admin but we are not elevated → returns INFO result.
        - Module runs successfully → returns its results with timing set.
        - Module raises an unhandled exception → returns a synthetic ERROR result.
        """
        cat = getattr(module, "CATEGORY", module.__name__)

        # Skip modules that require elevation when running without admin
        if getattr(module, "REQUIRES_ADMIN", False) and not self.is_admin:
            log.info(
                "Skipping %s — requires administrator privileges", module.__name__
            )
            return [CheckResult(
                category=cat,
                check_name=f"{cat} — requires administrator",
                status=Status.INFO,
                severity=Severity.INFO,
                description="This check module requires administrator privileges.",
                details="Run Apotrope as Administrator to include these checks.",
                remediation="",
            )]

        # Pass profile thresholds to modules that declare configure(). Track whether we
        # applied an override so we can undo it after run() via reset() — otherwise a
        # profile's thresholds would leak into a later scan in the same process, since
        # Scanner is reusable library code, not only a one-shot CLI.
        configured = False
        if (
            self.profile
            and self.profile.thresholds
            and callable(getattr(module, "configure", None))
        ):
            try:
                module.configure(self.profile.thresholds)
                configured = True
            except Exception as exc:
                log.warning("configure() on %s failed: %s", module.__name__, exc)

        log.debug("Running %s", module.__name__)
        t_start = time.monotonic()
        try:
            results = module.run()
            if not isinstance(results, list):
                raise TypeError(
                    f"run() must return list[CheckResult], got {type(results)}"
                )
        except Exception as exc:
            log.error("Error in %s.run(): %s", module.__name__, exc, exc_info=True)
            results = [CheckResult(
                category=cat,
                check_name=f"{cat} — module error",
                status=Status.ERROR,
                severity=Severity.INFO,
                description="The check module raised an unhandled exception.",
                details=str(exc),
                remediation="Run with --log-level DEBUG for more detail.",
            )]
        finally:
            # Undo any per-scan threshold override so it cannot leak into a later scan.
            if configured and callable(getattr(module, "reset", None)):
                try:
                    module.reset()
                except Exception as exc:
                    log.warning("reset() on %s failed: %s", module.__name__, exc)

        # A module must return at least one CheckResult (CLAUDE.md contract). An
        # empty list or a non-CheckResult element would otherwise flow silently
        # into the report and, being neither FAIL nor WARN, leave the score at
        # 100 — a false "clean" result. Turn it into a synthetic ERROR instead.
        if not results or not all(isinstance(r, CheckResult) for r in results):
            log.error(
                "%s.run() returned no valid CheckResult objects (%r)",
                module.__name__, results,
            )
            results = [CheckResult(
                category=cat,
                check_name=f"{cat} — module error",
                status=Status.ERROR,
                severity=Severity.INFO,
                description="The check module returned no valid results.",
                details=(
                    "run() returned an empty list."
                    if not results
                    else "run() returned a non-CheckResult element."
                ),
                remediation="Run with --log-level DEBUG for more detail.",
            )]

        duration = time.monotonic() - t_start
        for r in results:
            r.check_duration = duration
        log.debug("%s finished in %.2fs", module.__name__, duration)
        return results

    @staticmethod
    def _detect_product_type() -> int | None:
        """Return ``Win32_OperatingSystem.ProductType``, or ``None`` if unreadable.

        ProductType (1 = Workstation, 2 = Domain Controller, 3 = Server) is what
        distinguishes a server SKU from client Windows on the build numbers they
        share (17763 = Win10 1809 / Server 2019; 14393 = Win10 1607 / Server
        2016). Returns ``None`` when WMI yields nothing — non-Windows, access
        denied, or a missing/non-integer value — so ``family_for_build`` falls
        back to build-only classification.
        """
        rows = get_wmi_object("Win32_OperatingSystem", properties=["ProductType"])
        if not rows:
            return None
        product_type = rows[0].get("ProductType")
        return product_type if isinstance(product_type, int) else None

    @staticmethod
    def _apply_cis_references(
        results: list[CheckResult], family: "cis_map.OSFamily | None" = None
    ) -> None:
        """Populate the cis_reference field on results that don't already have one."""
        from apotrope import cis_map
        fam = family or cis_map.OSFamily.WIN11
        for r in results:
            if not r.cis_reference:
                r.cis_reference = cis_map.lookup(r.check_name, fam)

    def _apply_profile(self, results: list[CheckResult]) -> list[CheckResult]:
        """Apply profile transforms: disabled_checks filter and severity_overrides."""
        profile = self.profile
        assert profile is not None

        disabled = set(profile.disabled_checks)
        filtered = [r for r in results if r.check_name not in disabled]

        if disabled:
            removed = len(results) - len(filtered)
            log.info("Profile disabled %d check result(s)", removed)

        for r in filtered:
            override = profile.severity_overrides.get(r.check_name)
            if override:
                try:
                    r.severity = Severity(override.upper())
                except ValueError:
                    log.warning(
                        "Profile severity_override %r for %r is invalid — ignoring",
                        override, r.check_name,
                    )

        return filtered
