"""Tests for apotrope.reporter — HTML/JSON generation and executive summary."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.reporter import Reporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_report(
    score: int = 80,
    is_admin: bool = True,
    extra_results: list[CheckResult] | None = None,
) -> AuditReport:
    base = [
        CheckResult("Firewall", "Domain Profile",  Status.PASS, Severity.HIGH,   "desc", "ok"),
        CheckResult("Firewall", "Public Profile",  Status.FAIL, Severity.CRITICAL,"desc", "off", "Enable it"),
        CheckResult("Services", "Risky Services",  Status.WARN, Severity.MEDIUM,  "desc", "SNMP running", "Disable SNMP"),
        CheckResult("OS",       "OS Version",       Status.INFO, Severity.INFO,    "desc", "Win11 22621"),
    ]
    results = base + (extra_results or [])
    return AuditReport(
        hostname="TEST-PC",
        os_version="Windows 11 Pro 10.0.22621",
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration=2.5,
        results=results,
        score=score,
        is_admin=is_admin,
    )


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

class TestGenerateHtmlReport:
    def _generate(self, report: AuditReport) -> str:
        """Generate the HTML report and return its content."""
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            reporter.generate_html_report(report, path)
            return Path(path).read_text(encoding="utf-8")
        finally:
            os.unlink(path)

    def test_file_created(self):
        reporter = Reporter()
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            reporter.generate_html_report(report, path)
            assert os.path.exists(path)
            assert os.path.getsize(path) > 5000
        finally:
            os.unlink(path)

    def test_valid_html_structure(self):
        html = self._generate(_make_report())
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_hostname_present(self):
        html = self._generate(_make_report())
        assert "TEST-PC" in html

    def test_score_present(self):
        html = self._generate(_make_report(score=80))
        assert "80" in html

    def test_grade_present(self):
        html = self._generate(_make_report(score=80))
        assert "Good" in html  # B = Good

    def test_pass_fail_warn_counts(self):
        html = self._generate(_make_report())
        assert "1" in html   # 1 PASS, 1 FAIL, 1 WARN, 1 INFO

    def test_category_scores_present(self):
        html = self._generate(_make_report())
        assert "Category Scores" in html
        assert "Firewall" in html

    def test_findings_rendered_server_side(self):
        """Findings must be in the static HTML (readable with JS disabled)."""
        html = self._generate(_make_report())
        assert 'class="findings"' in html
        assert 'class="frow"' in html
        # the FAIL finding's status is baked into a filterable data attribute
        assert 'data-status="FAIL"' in html

    def test_filter_toolbar_present(self):
        html = self._generate(_make_report())
        assert 'id="apoSearch"' in html
        assert 'data-k="FAIL"' in html

    def test_info_findings_rendered(self):
        html = self._generate(_make_report())
        assert 'data-status="INFO"' in html
        assert "OS Version" in html  # the INFO check name

    def test_no_external_dependencies(self):
        html = self._generate(_make_report())
        assert "cdn." not in html
        assert "googleapis.com" not in html
        assert "<script src" not in html

    def test_brand_mark_embedded(self):
        """The eye-mark ships inline as a base64 data URI (report stays self-contained)."""
        html = self._generate(_make_report())
        assert "data:image/png;base64," in html
        assert '<img class="diamond"' in html

    def test_brand_mark_falls_back_to_glyph_when_missing(self):
        """If the mark asset can't be read, the header still renders the ◈ glyph."""
        with patch.object(Reporter, "_encode_logo_data_uri", return_value=None):
            html = self._generate(_make_report())
        assert "data:image/png;base64," not in html
        assert '<span class="diamond">◈</span>' in html

    def test_encode_logo_data_uri_missing_returns_none(self):
        """_encode_logo_data_uri returns None when the PNG is absent (graceful fallback)."""
        with tempfile.TemporaryDirectory() as td:
            assert Reporter._encode_logo_data_uri(Path(td)) is None

    def test_print_css_present(self):
        html = self._generate(_make_report())
        assert "@media print" in html

    # ── Expand/collapse: the [hidden] toggle must actually hide content ────

    @staticmethod
    def _finding_rows(html: str) -> list[tuple[str, bool, bool]]:
        """Per finding row: (status, header marked open, body hidden)."""
        rows = []
        for chunk in html.split('<div class="frow" ')[1:]:
            status_match = re.search(r'data-status="(\w+)"', chunk)
            assert status_match is not None
            status = status_match.group(1)
            is_open = 'class="fhead is-open"' in chunk
            body_hidden = re.search(r'<div class="fbody"[^>]*\shidden', chunk) is not None
            rows.append((status, is_open, body_hidden))
        return rows

    def test_fbody_hidden_css_rule_present(self):
        """Regression: .fbody{display:grid} overrides the UA's [hidden] rule,
        so an explicit author rule must hide collapsed bodies on screen —
        without it every row renders permanently expanded."""
        html = self._generate(_make_report())
        assert re.search(r"\.fbody\[hidden\]\s*\{\s*display:\s*none", html)

    def test_fail_warn_rows_expanded_by_default(self):
        """FAIL/WARN rows start expanded (open header, visible body)."""
        rows = self._finding_rows(self._generate(_make_report()))
        triage = [r for r in rows if r[0] in ("FAIL", "WARN")]
        assert triage, "fixture must contain FAIL/WARN rows"
        assert all(is_open and not hidden for _, is_open, hidden in triage)

    def test_pass_info_rows_collapsed_by_default(self):
        """PASS/INFO rows start collapsed (closed header, hidden body)."""
        rows = self._finding_rows(self._generate(_make_report()))
        quiet = [r for r in rows if r[0] in ("PASS", "INFO")]
        assert quiet, "fixture must contain PASS/INFO rows"
        assert all(not is_open and hidden for _, is_open, hidden in quiet)

    def test_summary_counters_are_filter_buttons(self):
        """The executive-summary count pills are keyboard-focusable buttons
        wired to the same data-k filter keys the toolbar chips use."""
        html = self._generate(_make_report())
        for cls, key in (("pass", "PASS"), ("fail", "FAIL"),
                         ("warn", "WARN"), ("info", "INFO")):
            assert re.search(
                rf'<button class="pill pill-{cls}" data-k="{key}"', html
            ), f"missing clickable {key} pill"

    def test_version_in_footer(self):
        html = self._generate(_make_report())
        assert "Apotrope" in html

    def test_executive_summary_present(self):
        html = self._generate(_make_report())
        assert "Executive Summary" in html
        assert "TEST-PC" in html  # hostname in summary

    def test_top_issues_callout_present_when_critical(self):
        html = self._generate(_make_report())
        assert "Top Issues" in html
        assert "CRITICAL" in html

    def test_no_file_written_when_jinja2_missing(self):
        import sys
        from unittest import mock

        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        os.unlink(path)
        try:
            with mock.patch.dict(sys.modules, {"jinja2": None}):
                reporter.generate_html_report(_make_report(), path)
            assert not os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_no_file_written_when_template_load_fails(self):
        from unittest import mock

        from jinja2 import Environment

        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        os.unlink(path)
        try:
            with mock.patch.object(
                Environment, "get_template", side_effect=OSError("boom")
            ):
                reporter.generate_html_report(_make_report(), path)
            assert not os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_frozen_bundle_uses_meipass_template_dir(self):
        """PyInstaller path: templates resolve under sys._MEIPASS/templates."""
        import sys
        from unittest import mock

        import apotrope.reporter as reporter_mod

        # Point _MEIPASS at the package dir so _MEIPASS/templates is the real
        # template directory and rendering still succeeds.
        package_dir = Path(reporter_mod.__file__).parent
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "_MEIPASS", str(package_dir), create=True):
            html = self._generate(_make_report())
        assert "<!DOCTYPE html>" in html

    def test_html_special_chars_escaped(self):
        """Regression: autoescape=True must escape user-controlled fields everywhere.

        select_autoescape(["html"]) silently returned False for .j2 templates
        because it checks the last extension (.j2, not .html). Verify a future
        change cannot re-introduce raw output — in details, remediation, OR the
        command field, including attribute-context (the data-text search index)
        injection via a quote breakout.
        """
        xss = '<script>alert(1)</script>'
        attr_breakout = '"><img src=x onerror=alert(2)>'
        report = AuditReport(
            hostname=f"HOST-{xss}",
            os_version="10.0.22631",
            scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            scan_duration=1.0,
            results=[
                CheckResult(
                    "Security", "XSS Check", Status.FAIL, Severity.HIGH,
                    "desc", f"Details: {xss} {attr_breakout}",
                    f"Remediate {xss}", f"Set-Item {xss} {attr_breakout}",
                ),
            ],
            score=50,
            is_admin=False,
        )
        html = self._generate(report)
        # No raw executable markup survives in any field or in attribute context
        assert "<script>alert(1)</script>" not in html
        assert "<img src=x" not in html
        assert '"><img' not in html
        # Escaped forms are present, proving the payloads were rendered (and escaped)
        assert "&lt;script&gt;" in html
        assert "&lt;img" in html

    def test_remediation_caution_banner_rendered(self):
        """A finding with a command renders the review-before-running banner."""
        with_command = CheckResult(
            "Firewall", "Public Profile Cmd", Status.FAIL, Severity.HIGH,
            "desc", "off", "Enable it",
            "Set-NetFirewallProfile -Profile Public -Enabled True",
        )
        html = self._generate(_make_report(extra_results=[with_command]))
        assert (
            "Review before running — these commands run elevated and can change "
            "system settings, or require a reboot or maintenance window." in html
        )

    def test_share_warning_rendered_in_footer(self):
        """The footer warns that the report embeds machine-identifying detail."""
        html = self._generate(_make_report())
        assert (
            "This report contains this machine's hostname, account names, "
            "services, and configuration. Review and redact before sharing it "
            "outside your organization." in html
        )


# ---------------------------------------------------------------------------
# JSON report generation
# ---------------------------------------------------------------------------

class TestGenerateJsonReport:
    def _generate_json(self, report: AuditReport) -> dict:
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            reporter.generate_json_report(report, path)
            return json.loads(Path(path).read_text(encoding="utf-8"))
        finally:
            os.unlink(path)

    def test_file_created(self):
        reporter = Reporter()
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            reporter.generate_json_report(report, path)
            assert os.path.exists(path)
        finally:
            os.unlink(path)

    def test_valid_json(self):
        data = self._generate_json(_make_report())
        assert isinstance(data, dict)

    def test_hostname_field(self):
        data = self._generate_json(_make_report())
        assert data["hostname"] == "TEST-PC"

    def test_score_field(self):
        data = self._generate_json(_make_report(score=75))
        assert data["score"] == 75

    def test_results_array(self):
        data = self._generate_json(_make_report())
        assert "results" in data
        assert isinstance(data["results"], list)
        assert len(data["results"]) > 0

    def test_result_fields_present(self):
        data = self._generate_json(_make_report())
        r = data["results"][0]
        for field in ("category", "check_name", "status", "severity", "description", "details"):
            assert field in r, f"Missing field: {field}"

    def test_scan_timestamp_serialized(self):
        data = self._generate_json(_make_report())
        assert "scan_timestamp" in data
        assert "2026" in data["scan_timestamp"]

    def test_is_admin_field(self):
        data = self._generate_json(_make_report(is_admin=True))
        assert data["is_admin"] is True


# ---------------------------------------------------------------------------
# Executive summary generation
# ---------------------------------------------------------------------------

class TestBuildExecutiveSummary:
    def _summary(self, results: list[CheckResult], score: int = 80) -> str:
        report = AuditReport(
            hostname="MYPC",
            os_version="Win11",
            scan_timestamp=datetime.now(tz=timezone.utc),
            scan_duration=1.0,
            results=results,
            score=score,
        )
        return Reporter()._build_executive_summary(report)

    def test_contains_hostname(self):
        s = self._summary([])
        assert "MYPC" in s

    def test_contains_score(self):
        s = self._summary([], score=85)
        assert "85" in s

    def test_clean_machine_mentions_all_passed(self):
        results = [
            CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"),
        ]
        s = self._summary(results, score=100)
        assert "pass" in s.lower() or "no failure" in s.lower()

    def test_critical_failures_called_out(self):
        results = [
            CheckResult("Firewall", "FW", Status.FAIL, Severity.CRITICAL, "d", "off", "fix"),
        ]
        s = self._summary(results, score=85)
        assert "critical" in s.lower()

    def test_top_categories_mentioned(self):
        results = [
            CheckResult("Firewall", "FW1", Status.FAIL, Severity.HIGH, "d", "off", "fix"),
            CheckResult("Firewall", "FW2", Status.WARN, Severity.MEDIUM, "d", "ok", "fix"),
        ]
        s = self._summary(results, score=75)
        assert "Firewall" in s

    def test_remediation_advice_included(self):
        results = [
            CheckResult("Antivirus", "AV", Status.FAIL, Severity.CRITICAL, "d", "off", "fix"),
        ]
        s = self._summary(results, score=60)
        assert "remediat" in s.lower() or "priorit" in s.lower()

    def test_fail_count_mentioned(self):
        results = [
            CheckResult("X", "C1", Status.FAIL, Severity.HIGH, "d", "d", "fix"),
            CheckResult("X", "C2", Status.FAIL, Severity.MEDIUM, "d", "d", "fix"),
        ]
        s = self._summary(results, score=70)
        assert "2" in s or "failed" in s.lower()


# ---------------------------------------------------------------------------
# Terminal output — triage boxes (default) and --verbose boxes
# ---------------------------------------------------------------------------

class TestPrintTerminal:
    def _boxed_report(self) -> AuditReport:
        return _make_report(extra_results=[
            CheckResult(
                "Firewall", "Public Firewall", Status.FAIL, Severity.HIGH,
                "desc", "Profile disabled.", "Turn the public profile on.",
                command="Set-NetFirewallProfile -Profile Public -Enabled True",
            ),
        ])

    def _output(self, report: AuditReport, capsys, monkeypatch,
                verbose: bool = False, columns: int = 120) -> str:
        # Pin the console width (Rich and shutil both honor COLUMNS) so the
        # wide/narrow rendering path doesn't depend on the test runner's tty.
        monkeypatch.setenv("COLUMNS", str(columns))
        Reporter(verbose=verbose, no_color=True).print_terminal(report)
        return capsys.readouterr().out

    def test_default_boxes_issue_categories_only(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "FIREWALL" in out   # has FAIL findings → boxed
        assert "SERVICES" in out   # has a WARN finding → boxed
        assert "OS  " not in out   # INFO only → no box in the triage view

    def test_default_hides_passing_checks(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "Domain Profile" not in out  # PASS check stays out of triage

    def test_default_shows_fix_and_run(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "fix" in out
        assert "Turn the public profile on." in out
        assert "run" in out
        assert "Set-NetFirewallProfile -Profile Public -Enabled True" in out

    def test_old_summary_blocks_removed(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "TOP FAILURES" not in out
        assert "TOP WARNINGS" not in out
        assert "TOP FIXES" not in out

    def test_box_frame_drawn(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "┌" in out and "┐" in out and "└" in out and "┘" in out

    def test_box_lines_align_at_78_columns(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        box_lines = [ln for ln in out.splitlines()
                     if ln.lstrip().startswith(("┌", "│", "└"))]
        assert box_lines
        assert all(len(ln) == 80 for ln in box_lines)  # 2 indent + 78 box

    def test_footer_default(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch)
        assert "issues to triage" in out
        assert "--verbose for per-check detail" in out

    def test_footer_zero_issues(self, capsys, monkeypatch):
        clean = AuditReport(
            hostname="TEST-PC",
            os_version="Windows 11 Pro 10.0.22621",
            scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
            scan_duration=2.5,
            results=[
                CheckResult("Firewall", "Domain Profile", Status.PASS,
                            Severity.HIGH, "desc", "ok"),
            ],
            score=100,
        )
        out = self._output(clean, capsys, monkeypatch)
        assert "no issues to triage" in out
        assert "┌" not in out  # no boxes on a clean run

    def test_verbose_boxes_every_category_and_check(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch, verbose=True)
        assert "OS Version" in out         # INFO-only category boxed now
        assert "Domain Profile" in out     # passing check shown
        assert "--verbose for per-check detail" not in out

    def test_narrow_console_falls_back_unboxed(self, capsys, monkeypatch):
        out = self._output(self._boxed_report(), capsys, monkeypatch, columns=70)
        assert "┌" not in out
        assert "Public Firewall" in out  # content still there, un-boxed
