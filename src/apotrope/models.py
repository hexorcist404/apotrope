"""Core data models for Apotrope audit results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    """Result status for an individual check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Risk severity for a check finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    """The result of a single security audit check.

    Attributes:
        category:    Logical grouping, e.g. "Firewall" or "Encryption".
        check_name:  Human-readable name, e.g. "Windows Firewall - Domain Profile".
        status:      Outcome of the check (PASS/FAIL/WARN/INFO/ERROR).
        severity:    Risk level if the check fails (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        description: What this check verifies.
        details:     What was actually found on the system.
        remediation: Plain-English fix guidance (the *what & why*); no command
                     text. Empty string when status is PASS/INFO.
        command:     Verbatim, ready-to-paste PowerShell a user can run in an
                     elevated prompt. May be multi-line (one statement per line);
                     empty string when there is nothing to run (PASS/INFO).
    """

    category: str
    check_name: str
    status: Status
    severity: Severity
    description: str
    details: str
    remediation: str = ""
    command: str = ""            # ready-to-paste PowerShell; "" when PASS/INFO
    check_duration: float = 0.0  # seconds the parent module took to run
    cis_reference: str = ""      # CIS Benchmark control ID, e.g. "CIS 9.1.1"


@dataclass
class AuditReport:
    """A complete Apotrope audit report.

    Attributes:
        hostname:       Name of the audited machine.
        os_version:     Windows version string.
        scan_timestamp: When the scan started (UTC).
        scan_duration:  How long the scan took in seconds.
        results:        All CheckResult objects collected during the scan.
        score:          Aggregate security score 0–100.
    """

    hostname: str
    os_version: str
    scan_timestamp: datetime
    scan_duration: float
    results: list[CheckResult] = field(default_factory=list)
    score: int = 0
    is_admin: bool = False
    cis_version: str = ""  # CIS Benchmark edition used (e.g. "v5.0.0" / "v4.0.0")
    cis_caveat: str = ""   # Best-effort note when the edition is an approximation
                           # (e.g. Server 2022 mapped onto the Win10 v4.0.0 baseline)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def by_status(self, status: Status) -> list[CheckResult]:
        """Return all results matching *status*."""
        return [r for r in self.results if r.status == status]

    def by_category(self, category: str) -> list[CheckResult]:
        """Return all results for *category* (case-insensitive)."""
        return [r for r in self.results if r.category.lower() == category.lower()]

    @property
    def fail_count(self) -> int:
        """Number of FAIL results."""
        return len(self.by_status(Status.FAIL))

    @property
    def warn_count(self) -> int:
        """Number of WARN results."""
        return len(self.by_status(Status.WARN))

    @property
    def pass_count(self) -> int:
        """Number of PASS results."""
        return len(self.by_status(Status.PASS))

    @property
    def error_count(self) -> int:
        """Number of ERROR results."""
        return len(self.by_status(Status.ERROR))
