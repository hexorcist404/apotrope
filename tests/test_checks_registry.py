"""Guard: the frozen-mode MODULES registry matches the check modules on disk.

PyInstaller bundles cannot traverse the package with ``pkgutil``, so
``apotrope.checks.MODULES`` lists the check modules explicitly. If a new check
module is added but not registered, it silently vanishes from the shipped exe;
this test catches that drift.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

import apotrope.checks as checks_pkg


def _on_disk() -> set[str]:
    return {
        p.stem for p in Path(checks_pkg.__path__[0]).glob("*.py")
        if not p.stem.startswith("_")
    }


def test_modules_registry_matches_disk():
    # Count BEFORE comparing as sets. set() discards cardinality, so a
    # duplicated entry compares equal to a clean registry — while the frozen
    # scanner would import that name twice and emit its results twice.
    duplicates = {name: n for name, n in Counter(checks_pkg.MODULES).items() if n > 1}
    assert not duplicates, (
        f"duplicate entries in apotrope.checks.MODULES: {duplicates}. "
        "The frozen scanner walks the registry in order, so a duplicate runs "
        "that check twice and double-deducts its FAIL/WARN score."
    )

    on_disk = _on_disk()
    registered = set(checks_pkg.MODULES)
    assert registered == on_disk, (
        f"MODULES registry drift — symmetric difference: {registered ^ on_disk}. "
        "Update apotrope/checks/__init__.py MODULES when adding/removing a check module."
    )


def test_modules_registry_is_sorted():
    """Canonical order keeps the diff — and the exe's run order — stable."""
    assert checks_pkg.MODULES == sorted(checks_pkg.MODULES), (
        f"apotrope.checks.MODULES must stay alphabetically sorted: {checks_pkg.MODULES}"
    )


def test_duplicate_detection_actually_fires(monkeypatch: pytest.MonkeyPatch):
    """Meta-test: the guard above must fail on a duplicate.

    The previous set()-only version passed in this scenario, which is exactly
    why the Counter check exists.
    """
    monkeypatch.setattr(checks_pkg, "MODULES", [*checks_pkg.MODULES, "rdp"])
    with pytest.raises(AssertionError, match="duplicate entries"):
        test_modules_registry_matches_disk()
