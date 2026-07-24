"""Custom check profiles loaded from an apotrope.toml configuration file.

Profile files allow MSP teams and advanced users to customise Apotrope's
behaviour without touching source code.

Example ``apotrope.toml``:

.. code-block:: toml

    [profile]
    name = "MSP-Baseline"

    [disabled_checks]
    # Skip checks that are not relevant to this client
    checks = [
        "SMBv1 Disabled",
        "Firewall — Public Default Inbound Action",
    ]

    [severity_overrides]
    # Downgrade noisy checks
    "Last Windows Update" = "LOW"
    "Defender Tamper Protection" = "LOW"

    [thresholds]
    # Days before Last Windows Update is flagged (default: warn=30, fail=60)
    max_update_age_warn = 45
    max_update_age_fail = 90

Profiles are searched in this order:
    1. Path supplied by ``--profile`` CLI flag
    2. ``apotrope.toml`` in the current working directory
    3. ``~/.apotrope.toml`` in the user's home directory
"""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

from apotrope.exceptions import ProfileError

log = logging.getLogger(__name__)

_SEARCH_PATHS = [
    Path("apotrope.toml"),
    Path.home() / ".apotrope.toml",
]


@dataclasses.dataclass
class Profile:
    """Resolved check profile configuration.

    Attributes:
        name:               Human-readable profile name.
        disabled_checks:    Exact check_name values to skip entirely.
        severity_overrides: Map of check_name → new Severity string.
        thresholds:         Numeric threshold overrides (module-specific).
    """

    name: str = "default"
    disabled_checks: list[str] = dataclasses.field(default_factory=list)
    severity_overrides: dict[str, str] = dataclasses.field(default_factory=dict)
    thresholds: dict[str, int] = dataclasses.field(default_factory=dict)


def load_profile(path: str | None = None) -> Profile:
    """Load a :class:`Profile` from a TOML file.

    If *path* is ``None`` the default search paths are tried in order.
    If no file is found a default (empty) Profile is returned.

    Args:
        path: Explicit path to a TOML file, or ``None`` to auto-discover.

    Returns:
        A :class:`Profile` instance.

    Raises:
        ProfileError: If an *explicitly* requested *path* is missing or cannot be
            parsed. An auto-discovered ``apotrope.toml`` never raises — a parse
            error there is logged and a default Profile is returned.
    """
    if path is not None:
        resolved = Path(path)
        if not resolved.exists():
            raise ProfileError(f"Profile file not found: {path}")
        try:
            return _parse_toml(resolved)
        except ProfileError:
            raise
        except Exception as exc:
            raise ProfileError(f"Could not parse profile {path}: {exc}") from exc

    resolved = None
    for candidate in _SEARCH_PATHS:
        if candidate.exists():
            resolved = candidate
            break

    if resolved is None:
        log.debug("No apotrope.toml found — using default profile")
        return Profile()

    try:
        return _parse_toml(resolved)
    except Exception as exc:
        log.warning("Could not parse profile %s: %s — using defaults", resolved, exc)
        return Profile()


def _parse_toml(path: Path) -> Profile:
    """Parse *path* as TOML and return a Profile.

    Uses ``tomllib`` (Python 3.11+) or ``tomli`` as a fallback.

    Raises:
        ImportError: If neither tomllib nor tomli is available.
        Any TOML parse error from the underlying library.
    """
    try:
        import tomllib  # type: ignore[import]  # stdlib in 3.11+
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except ImportError:
        try:
            import tomli  # type: ignore[import]
            with path.open("rb") as fh:
                data = tomli.load(fh)
        except ImportError as exc:
            raise ImportError(
                "Python < 3.11 requires the 'tomli' package to read .toml files: "
                "pip install tomli"
            ) from exc

    profile_section = data.get("profile", {})
    name = str(profile_section.get("name", "custom"))

    disabled = list(data.get("disabled_checks", {}).get("checks", []))

    severity_raw = data.get("severity_overrides", {})
    severity_overrides = {str(k): str(v) for k, v in severity_raw.items()}

    thresholds_raw = data.get("thresholds", {})
    thresholds: dict[str, int] = {}
    for k, v in thresholds_raw.items():
        try:
            thresholds[str(k)] = int(v)
        except (TypeError, ValueError):
            log.warning("Profile threshold %r = %r is not an integer — ignoring", k, v)

    profile = Profile(
        name=name,
        disabled_checks=disabled,
        severity_overrides=severity_overrides,
        thresholds=thresholds,
    )
    log.info(
        "Loaded profile %r from %s (%d disabled, %d overrides, %d thresholds)",
        name, path, len(disabled), len(severity_overrides), len(thresholds),
    )
    return profile
