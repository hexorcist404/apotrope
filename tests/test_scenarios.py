"""Integration-style scenario tests — mock full scan environments and verify scores."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.scoring import calculate_score, score_grade


# ---------------------------------------------------------------------------
# Scenario builder helpers
# ---------------------------------------------------------------------------

def _r(
    category: str,
    name: str,
    status: Status,
    severity: Severity,
    details: str = "",
    remediation: str = "",
) -> CheckResult:
    return CheckResult(
        category=category,
        check_name=name,
        status=status,
        severity=severity,
        description=f"Check: {name}",
        details=details or status.value,
        remediation=remediation,
    )


def _report(results: list[CheckResult], is_admin: bool = True) -> AuditReport:
    score = calculate_score(results)
    return AuditReport(
        hostname="SCENARIO-PC",
        os_version="Windows 11 Pro 10.0.22621",
        scan_timestamp=datetime.now(tz=timezone.utc),
        scan_duration=5.0,
        results=results,
        score=score,
        is_admin=is_admin,
    )


# ---------------------------------------------------------------------------
# Scenario 1: Clean Windows 11 Pro domain-joined machine
# ---------------------------------------------------------------------------

def _clean_win11_pro_results() -> list[CheckResult]:
    """Simulate a well-configured Windows 11 Pro workstation."""
    return [
        # Firewall — all three profiles enabled
        _r("Firewall", "Domain Profile",  Status.PASS, Severity.HIGH),
        _r("Firewall", "Private Profile", Status.PASS, Severity.HIGH),
        _r("Firewall", "Public Profile",  Status.PASS, Severity.HIGH),
        # Antivirus — Defender active, definitions current
        _r("Antivirus", "Windows Defender Status",   Status.PASS, Severity.CRITICAL),
        _r("Antivirus", "Definition Age",             Status.PASS, Severity.HIGH),
        _r("Antivirus", "Third-party AV",             Status.INFO, Severity.INFO),
        # Encryption — BitLocker on OS drive
        _r("Encryption", "BitLocker — C:", Status.PASS, Severity.HIGH),
        # Updates — current
        _r("Patching", "Last Windows Update",    Status.PASS, Severity.CRITICAL),
        _r("Patching", "WU Service",              Status.PASS, Severity.MEDIUM),
        _r("Patching", "Pending Updates",         Status.PASS, Severity.HIGH),
        # Accounts — minimal admins, guest disabled
        _r("Accounts", "Guest Account",           Status.PASS, Severity.HIGH),
        _r("Accounts", "Built-in Administrator",  Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Local Administrators",    Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Password Length",         Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Account Lockout",         Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Password Complexity",     Status.PASS, Severity.MEDIUM),
        # UAC — maximum setting
        _r("UAC", "UAC Enabled",        Status.PASS, Severity.CRITICAL),
        _r("UAC", "UAC Consent Level",  Status.PASS, Severity.HIGH),
        # SMB — v1 disabled, signing required
        _r("File Sharing", "SMBv1 Disabled",      Status.PASS, Severity.CRITICAL),
        _r("File Sharing", "SMB Signing",          Status.PASS, Severity.HIGH),
        _r("File Sharing", "SMB Encryption",       Status.INFO, Severity.LOW),
        # RDP — disabled or NLA enforced
        _r("RDP", "RDP Enabled",  Status.INFO, Severity.HIGH),
        _r("RDP", "NLA Required", Status.PASS, Severity.HIGH),
        # PowerShell — logging enabled
        _r("PowerShell", "Execution Policy",    Status.PASS, Severity.HIGH),
        _r("PowerShell", "Script Block Logging",Status.PASS, Severity.MEDIUM),
        _r("PowerShell", "Module Logging",      Status.PASS, Severity.MEDIUM),
        _r("PowerShell", "PSv2 Installed",      Status.PASS, Severity.MEDIUM),
        # Network — LLMNR disabled, no risky ports
        _r("Network", "LLMNR Disabled",  Status.PASS, Severity.MEDIUM),
        _r("Network", "NetBIOS",         Status.PASS, Severity.MEDIUM),
        # Services — no risky services
        _r("Services", "Risky Services",    Status.PASS, Severity.MEDIUM),
        _r("Services", "Unquoted Paths",    Status.PASS, Severity.HIGH),
        # Hardening
        _r("Hardening", "AutoPlay Disabled",  Status.PASS, Severity.MEDIUM),
        _r("Hardening", "WinRM",              Status.PASS, Severity.MEDIUM),
        _r("Hardening", "Audit Policy",       Status.PASS, Severity.MEDIUM),
        _r("Hardening", "Screen Lock",        Status.PASS, Severity.MEDIUM),
    ]


class TestCleanWin11ProDomainMachine:
    def test_score_is_grade_a(self):
        results = _clean_win11_pro_results()
        score = calculate_score(results)
        letter, _ = score_grade(score)
        assert letter == "A", f"Expected A grade but got {letter} (score={score})"

    def test_score_at_least_90(self):
        score = calculate_score(_clean_win11_pro_results())
        assert score >= 90, f"Expected score >= 90, got {score}"

    def test_no_failures(self):
        report = _report(_clean_win11_pro_results())
        assert report.fail_count == 0

    def test_no_errors(self):
        report = _report(_clean_win11_pro_results())
        assert report.error_count == 0

    def test_is_admin_flag(self):
        report = _report(_clean_win11_pro_results(), is_admin=True)
        assert report.is_admin is True


# ---------------------------------------------------------------------------
# Scenario 2: Neglected Windows 10 Home workgroup machine
# ---------------------------------------------------------------------------

def _neglected_win10_home_results() -> list[CheckResult]:
    """Simulate a poorly configured Windows 10 Home workstation."""
    return [
        # Firewall — public profile off
        _r("Firewall", "Domain Profile",  Status.INFO, Severity.HIGH, "Not domain-joined"),
        _r("Firewall", "Private Profile", Status.PASS, Severity.HIGH),
        _r("Firewall", "Public Profile",  Status.FAIL, Severity.CRITICAL, "Disabled", "Enable firewall"),
        # Antivirus — Defender disabled
        _r("Antivirus", "Windows Defender Status",  Status.FAIL, Severity.CRITICAL, "Disabled", "Enable Defender"),
        _r("Antivirus", "Definition Age",            Status.FAIL, Severity.HIGH, "90 days old", "Update defs"),
        # Encryption — no BitLocker (Home edition)
        _r("Encryption", "BitLocker — C:", Status.WARN, Severity.HIGH, "Unavailable on Home", "Upgrade to Pro"),
        # Updates — very stale
        _r("Patching", "Last Windows Update", Status.FAIL, Severity.CRITICAL, "120 days ago", "Run Windows Update"),
        _r("Patching", "WU Service",          Status.WARN, Severity.MEDIUM, "Stopped", "Start service"),
        _r("Patching", "Pending Updates",     Status.FAIL, Severity.HIGH, "15 updates", "Install updates"),
        # Accounts — guest enabled, many admins
        _r("Accounts", "Guest Account",          Status.FAIL, Severity.HIGH, "Enabled", "Disable guest"),
        _r("Accounts", "Built-in Administrator", Status.FAIL, Severity.MEDIUM,
           "Enabled, default name", "Rename/disable"),
        _r("Accounts", "Local Administrators",   Status.WARN, Severity.MEDIUM, "5 admins", "Reduce admins"),
        _r("Accounts", "Password Length",        Status.FAIL, Severity.HIGH, "6 chars min", "Increase length"),
        _r("Accounts", "Account Lockout",        Status.WARN, Severity.MEDIUM, "Disabled", "Enable lockout"),
        _r("Accounts", "Password Complexity",    Status.FAIL, Severity.MEDIUM, "Disabled", "Enable complexity"),
        # UAC — disabled
        _r("UAC", "UAC Enabled",       Status.FAIL, Severity.CRITICAL, "Disabled", "Enable UAC"),
        _r("UAC", "UAC Consent Level", Status.FAIL, Severity.HIGH, "No prompt", "Set to prompt"),
        # SMB — v1 enabled
        _r("File Sharing", "SMBv1 Disabled", Status.FAIL, Severity.CRITICAL, "SMBv1 enabled", "Disable SMBv1"),
        _r("File Sharing", "SMB Signing",    Status.FAIL, Severity.HIGH, "Not required", "Enable signing"),
        # RDP — enabled without NLA
        _r("RDP", "RDP Enabled",  Status.WARN, Severity.HIGH, "Enabled", "Disable or restrict"),
        _r("RDP", "NLA Required", Status.FAIL, Severity.HIGH, "NLA disabled", "Enable NLA"),
        # PowerShell
        _r("PowerShell", "Execution Policy", Status.WARN, Severity.HIGH, "Unrestricted", "Restrict policy"),
        # Hardening
        _r("Hardening", "AutoPlay Disabled", Status.WARN, Severity.MEDIUM, "Not set", "Disable AutoPlay"),
        _r("Hardening", "Audit Policy",      Status.WARN, Severity.MEDIUM, "Not configured", "Configure"),
    ]


class TestNeglectedWin10HomeMachine:
    def test_score_is_grade_f(self):
        results = _neglected_win10_home_results()
        score = calculate_score(results)
        letter, _ = score_grade(score)
        assert letter == "F", f"Expected F grade but got {letter} (score={score})"

    def test_score_below_60(self):
        score = calculate_score(_neglected_win10_home_results())
        assert score < 60, f"Expected score < 60, got {score}"

    def test_has_multiple_critical_failures(self):
        report = _report(_neglected_win10_home_results())
        critical_fails = sum(
            1 for r in report.results
            if r.status == Status.FAIL and r.severity == Severity.CRITICAL
        )
        assert critical_fails >= 3

    def test_has_failures(self):
        report = _report(_neglected_win10_home_results())
        assert report.fail_count > 0

    def test_score_much_lower_than_clean(self):
        clean_score  = calculate_score(_clean_win11_pro_results())
        bad_score    = calculate_score(_neglected_win10_home_results())
        assert clean_score - bad_score >= 30, (
            f"Clean ({clean_score}) vs neglected ({bad_score}) gap too small"
        )


# ---------------------------------------------------------------------------
# Scenario 3: Windows Server 2022 with baseline hardening
# ---------------------------------------------------------------------------

def _server_2022_hardened_results() -> list[CheckResult]:
    """Simulate a reasonably hardened Windows Server 2022."""
    return [
        # Firewall
        _r("Firewall", "Domain Profile",  Status.PASS, Severity.HIGH),
        _r("Firewall", "Private Profile", Status.PASS, Severity.HIGH),
        _r("Firewall", "Public Profile",  Status.PASS, Severity.HIGH),
        # Antivirus — Defender running
        _r("Antivirus", "Windows Defender Status", Status.PASS, Severity.CRITICAL),
        _r("Antivirus", "Definition Age",           Status.PASS, Severity.HIGH),
        # Encryption — BitLocker on C:
        _r("Encryption", "BitLocker — C:", Status.PASS, Severity.HIGH),
        # Updates — within 30 days
        _r("Patching", "Last Windows Update", Status.PASS, Severity.CRITICAL),
        _r("Patching", "WU Service",          Status.PASS, Severity.MEDIUM),
        _r("Patching", "Pending Updates",     Status.PASS, Severity.HIGH),
        # Accounts — standard setup
        _r("Accounts", "Guest Account",          Status.PASS, Severity.HIGH),
        _r("Accounts", "Local Administrators",   Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Password Length",        Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Account Lockout",        Status.PASS, Severity.MEDIUM),
        _r("Accounts", "Password Complexity",    Status.PASS, Severity.MEDIUM),
        # UAC — enabled
        _r("UAC", "UAC Enabled",       Status.PASS, Severity.CRITICAL),
        _r("UAC", "UAC Consent Level", Status.PASS, Severity.HIGH),
        # SMB — v1 disabled, signing required
        _r("File Sharing", "SMBv1 Disabled", Status.PASS, Severity.CRITICAL),
        _r("File Sharing", "SMB Signing",    Status.PASS, Severity.HIGH),
        _r("File Sharing", "SMB Encryption", Status.PASS, Severity.LOW),
        # RDP — NLA enforced
        _r("RDP", "NLA Required", Status.PASS, Severity.HIGH),
        # PowerShell
        _r("PowerShell", "Execution Policy",     Status.PASS, Severity.HIGH),
        _r("PowerShell", "Script Block Logging", Status.PASS, Severity.MEDIUM),
        _r("PowerShell", "Module Logging",       Status.PASS, Severity.MEDIUM),
        _r("PowerShell", "PSv2 Installed",       Status.PASS, Severity.MEDIUM),
        # Services — one warn (Print Spooler)
        _r("Services", "Risky Services",  Status.WARN, Severity.MEDIUM, "Spooler running", "Disable if unused"),
        _r("Services", "Unquoted Paths",  Status.PASS, Severity.HIGH),
        # Network
        _r("Network", "LLMNR Disabled", Status.PASS, Severity.MEDIUM),
        # Hardening
        _r("Hardening", "Audit Policy",   Status.PASS, Severity.MEDIUM),
        _r("Hardening", "Screen Lock",    Status.PASS, Severity.MEDIUM),
    ]


class TestServer2022Hardened:
    def test_score_grade_b_or_better(self):
        results = _server_2022_hardened_results()
        score = calculate_score(results)
        letter, _ = score_grade(score)
        assert letter in ("A", "B"), f"Expected A or B grade, got {letter} (score={score})"

    def test_score_at_least_80(self):
        score = calculate_score(_server_2022_hardened_results())
        assert score >= 80, f"Expected score >= 80, got {score}"

    def test_no_failures(self):
        report = _report(_server_2022_hardened_results())
        assert report.fail_count == 0


# ---------------------------------------------------------------------------
# Scenario 4: Non-admin scan — admin-required checks skipped gracefully
# ---------------------------------------------------------------------------

def _non_admin_results() -> list[CheckResult]:
    """Simulate results when scan runs without elevation."""
    return [
        # Checks that run without admin
        _r("Firewall", "Domain Profile",  Status.PASS, Severity.HIGH),
        _r("Firewall", "Public Profile",  Status.PASS, Severity.HIGH),
        _r("Antivirus", "Defender",       Status.PASS, Severity.CRITICAL),
        _r("UAC", "UAC Enabled",          Status.PASS, Severity.CRITICAL),
        # Admin-required checks skipped (returned as INFO by scanner)
        _r("Encryption", "Encryption — requires administrator", Status.INFO, Severity.INFO,
           "Run as Administrator"),
        _r("File Sharing", "File Sharing — requires administrator", Status.INFO, Severity.INFO,
           "Run as Administrator"),
    ]


class TestNonAdminScan:
    def test_score_not_penalised_for_skipped_checks(self):
        """INFO results must not deduct from score."""
        results = _non_admin_results()
        score = calculate_score(results)
        # All non-INFO results are PASS, so score should stay high
        assert score == 100, f"Skipped (INFO) checks should not deduct points, got {score}"

    def test_report_is_admin_false(self):
        report = _report(_non_admin_results(), is_admin=False)
        assert report.is_admin is False

    def test_no_errors_in_non_admin_scan(self):
        report = _report(_non_admin_results(), is_admin=False)
        assert report.error_count == 0


# ---------------------------------------------------------------------------
# Scenario 5: HTML and JSON round-trip
# ---------------------------------------------------------------------------

class TestReportRoundTrip:
    def test_html_report_contains_all_categories(self):
        from apotrope.reporter import Reporter

        results = _clean_win11_pro_results()
        report = _report(results)
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            html_path = f.name
        try:
            reporter.generate_html_report(report, html_path)
            content = open(html_path, encoding="utf-8").read()
        finally:
            os.unlink(html_path)

        categories = {r.category for r in results}
        for cat in categories:
            assert cat in content, f"Category '{cat}' not found in HTML report"

    def test_json_report_preserves_all_results(self):
        from apotrope.reporter import Reporter

        results = _clean_win11_pro_results()
        report = _report(results)
        reporter = Reporter()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            reporter.generate_json_report(report, json_path)
            data = json.loads(open(json_path, encoding="utf-8").read())
        finally:
            os.unlink(json_path)

        assert len(data["results"]) == len(results)
        assert data["score"] == report.score
        assert data["hostname"] == "SCENARIO-PC"
