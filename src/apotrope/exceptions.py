"""Custom exceptions for Apotrope."""

from __future__ import annotations


class ApotropeError(Exception):
    """Raised when a Apotrope utility operation fails in an expected way.

    Examples: PowerShell non-zero exit, timeout, JSON parse failure,
    access-denied registry read, or running on a non-Windows platform.
    """
