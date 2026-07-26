"""Guard: the package version is single-sourced.

``pyproject.toml`` ``[project].version`` and ``apotrope.__version__`` are
maintained by hand; this test fails if they drift, so the wheel's metadata
version can never disagree with the version the CLI reports.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import apotrope


def test_pyproject_version_matches_dunder():
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == apotrope.__version__


def test_license_is_spdx_expression():
    # PEP 639: license is an SPDX string, and the deprecated classifier is gone.
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["license"] == "MIT"
    assert not any(
        c.startswith("License ::") for c in data["project"].get("classifiers", [])
    )
