"""Custom exceptions for Apotrope."""

from __future__ import annotations


class ApotropeError(Exception):
    """Raised when an Apotrope utility operation fails in an expected way.

    Examples: PowerShell non-zero exit, timeout, JSON parse failure,
    access-denied registry read, or running on a non-Windows platform.
    """


class PowerShellUnavailableError(ApotropeError):
    """Raised when a trusted ``powershell.exe`` cannot be resolved at all.

    Distinct from a plain :class:`ApotropeError` because the two mean different
    things to a caller. A plain one is *this query* failed, and helpers such as
    ``read_registry`` / ``get_wmi_object`` legitimately degrade to ``None`` /
    ``[]``. This one means *no query can succeed*, so degrading would turn a
    total execution failure into confident PASS/FAIL verdicts derived from no
    data. Helpers re-raise it instead.
    """


class ProfileError(ApotropeError):
    """Raised when an explicitly requested ``--profile`` is missing or unparseable.

    An auto-discovered ``apotrope.toml`` falls back to defaults, but a profile the
    user asked for by name must fail closed rather than silently scan with the
    default profile (which could change which checks run).
    """
