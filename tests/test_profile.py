"""Tests for apotrope.profile — TOML profile loading and parsing."""

from __future__ import annotations

import os
import tempfile

import pytest

from apotrope.profile import Profile, load_profile


# ---------------------------------------------------------------------------
# Profile defaults
# ---------------------------------------------------------------------------

class TestProfileDefaults:
    def test_default_profile_name(self):
        p = Profile()
        assert p.name == "default"

    def test_default_disabled_empty(self):
        assert Profile().disabled_checks == []

    def test_default_overrides_empty(self):
        assert Profile().severity_overrides == {}

    def test_default_thresholds_empty(self):
        assert Profile().thresholds == {}


# ---------------------------------------------------------------------------
# load_profile — no file
# ---------------------------------------------------------------------------

class TestLoadProfileNoFile:
    def test_returns_default_when_no_file(self, tmp_path, monkeypatch):
        """No apotrope.toml in cwd → default profile."""
        monkeypatch.chdir(tmp_path)
        profile = load_profile()
        assert isinstance(profile, Profile)

    def test_explicit_missing_raises(self):
        """An explicitly requested path that doesn't exist fails closed."""
        from apotrope.exceptions import ProfileError
        with pytest.raises(ProfileError):
            load_profile("/nonexistent/apotrope.toml")


# ---------------------------------------------------------------------------
# load_profile — from TOML file
# ---------------------------------------------------------------------------

def _write_toml(content: str) -> str:
    """Write TOML content to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(suffix=".toml", delete=False, mode="w", encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


class TestLoadProfileFromToml:
    def test_profile_name_parsed(self):
        path = _write_toml('[profile]\nname = "MyProfile"\n')
        try:
            p = load_profile(path)
            assert p.name == "MyProfile"
        finally:
            os.unlink(path)

    def test_disabled_checks_parsed(self):
        toml = '[disabled_checks]\nchecks = ["SMBv1 Disabled", "Guest Account"]\n'
        path = _write_toml(toml)
        try:
            p = load_profile(path)
            assert "SMBv1 Disabled" in p.disabled_checks
            assert "Guest Account" in p.disabled_checks
        finally:
            os.unlink(path)

    def test_severity_overrides_parsed(self):
        toml = '[severity_overrides]\n"Last Windows Update" = "LOW"\n'
        path = _write_toml(toml)
        try:
            p = load_profile(path)
            assert p.severity_overrides.get("Last Windows Update") == "LOW"
        finally:
            os.unlink(path)

    def test_thresholds_parsed(self):
        toml = "[thresholds]\nmax_update_age_warn = 45\nmax_update_age_fail = 90\n"
        path = _write_toml(toml)
        try:
            p = load_profile(path)
            assert p.thresholds["max_update_age_warn"] == 45
            assert p.thresholds["max_update_age_fail"] == 90
        finally:
            os.unlink(path)

    def test_empty_toml_returns_custom_profile(self):
        path = _write_toml("")
        try:
            p = load_profile(path)
            assert isinstance(p, Profile)
        finally:
            os.unlink(path)

    def test_explicit_invalid_toml_raises(self):
        from apotrope.exceptions import ProfileError
        path = _write_toml("this is {{{{ not valid toml")
        try:
            with pytest.raises(ProfileError):
                load_profile(path)
        finally:
            os.unlink(path)

    def test_autodetected_invalid_toml_returns_default(self, tmp_path, monkeypatch):
        # An auto-discovered (not explicitly requested) apotrope.toml that fails
        # to parse still falls back to defaults rather than failing the scan.
        monkeypatch.chdir(tmp_path)
        (tmp_path / "apotrope.toml").write_text("{{{ not valid", encoding="utf-8")
        p = load_profile()
        assert isinstance(p, Profile)
        assert p.name == "default"

    def test_invalid_threshold_value_ignored(self):
        toml = '[thresholds]\nmax_update_age_warn = "not_a_number"\n'
        path = _write_toml(toml)
        try:
            p = load_profile(path)
            assert "max_update_age_warn" not in p.thresholds
        finally:
            os.unlink(path)

    def test_auto_detect_from_cwd(self, tmp_path, monkeypatch):
        """apotrope.toml in cwd is auto-detected."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "apotrope.toml").write_text(
            '[profile]\nname = "AutoDetected"\n', encoding="utf-8"
        )
        p = load_profile()
        assert p.name == "AutoDetected"


# ---------------------------------------------------------------------------
# TOML library fallback (tomllib → tomli)
# ---------------------------------------------------------------------------

class TestTomlLibraryFallback:
    def _write_toml(self, tmp_path):
        path = tmp_path / "apotrope-profile.toml"
        path.write_text('[profile]\nname = "fallback"\n', encoding="utf-8")
        return path

    def test_tomli_used_when_tomllib_missing(self, tmp_path):
        import sys
        import tomllib
        from types import ModuleType
        from unittest.mock import patch

        from apotrope.profile import _parse_toml

        fake_tomli = ModuleType("tomli")
        fake_tomli.load = tomllib.load
        path = self._write_toml(tmp_path)
        with patch.dict(sys.modules, {"tomllib": None, "tomli": fake_tomli}):
            profile = _parse_toml(path)
        assert profile.name == "fallback"

    def test_import_error_when_no_toml_library(self, tmp_path):
        import sys
        from unittest.mock import patch

        import pytest

        from apotrope.profile import _parse_toml

        path = self._write_toml(tmp_path)
        with patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            with pytest.raises(ImportError, match="tomli"):
                _parse_toml(path)

    def test_autodetected_profile_falls_back_to_defaults_without_toml_library(
        self, tmp_path, monkeypatch
    ):
        import sys
        from unittest.mock import patch

        # An auto-discovered profile with no TOML library available degrades to
        # the default profile (an explicitly requested one would fail closed).
        (tmp_path / "apotrope.toml").write_text('[profile]\nname = "fb"\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        with patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            profile = load_profile()
        assert profile.name == "default"
