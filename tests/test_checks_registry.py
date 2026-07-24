"""Guard: the frozen-mode MODULES registry matches the check modules on disk.

PyInstaller bundles cannot traverse the package with ``pkgutil``, so
``apotrope.checks.MODULES`` lists the check modules explicitly. If a new check
module is added but not registered, it silently vanishes from the shipped exe;
this test catches that drift.
"""

from __future__ import annotations

from pathlib import Path

import apotrope.checks as checks_pkg


def test_modules_registry_matches_disk():
    on_disk = {
        p.stem for p in Path(checks_pkg.__path__[0]).glob("*.py")
        if not p.stem.startswith("_")
    }
    registered = set(checks_pkg.MODULES)
    assert registered == on_disk, (
        f"MODULES registry drift — symmetric difference: {registered ^ on_disk}. "
        "Update apotrope/checks/__init__.py MODULES when adding/removing a check module."
    )
