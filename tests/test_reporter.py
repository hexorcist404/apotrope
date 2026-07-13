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
        # each row carries a status class (frow is-fail / is-pass / …)
        assert re.search(r'class="frow is-\w+"', html)
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
        for chunk in html.split('<div class="frow ')[1:]:
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

    def test_command_block_copy_source_is_clean(self):
        """The command block renders a non-selectable ``PS>`` prompt (and a muted
        ``#`` comment line) for readability, but the copy source ``data-cmd`` must
        hold the RAW command — no prompt, no markup — so a paste runs verbatim."""
        cmd = ("# comment line\n"
               "Set-NetFirewallProfile -Profile Public -Enabled True")
        with_command = CheckResult(
            "Firewall", "Public Profile Cmd", Status.FAIL, Severity.HIGH,
            "desc", "off", "Enable it", cmd,
        )
        html = self._generate(_make_report(extra_results=[with_command]))
        # readability: rendered command carries the prompt + a muted comment line
        assert '<span class="ps">PS&gt;</span>' in html
        assert 'class="cl-c"' in html
        # copy-correctness: every data-cmd value is free of the prompt and markup
        raw_cmds = re.findall(r'data-cmd="(.*?)"', html, re.DOTALL)
        assert raw_cmds, "expected a command block with a data-cmd attribute"
        for raw in raw_cmds:
            assert "PS&gt;" not in raw
            assert "<span" not in raw

    def test_share_warning_rendered_in_footer(self):
        """The footer warns that the report embeds machine-identifying detail."""
        html = self._generate(_make_report())
        assert (
            "This report contains this machine's hostname, account names, "
            "services, and configuration. Review and redact before sharing it "
            "outside your organization." in html
        )

    def test_footer_uses_canonical_privacy_copy(self) -> None:
        html = self._generate(_make_report())
        assert "No data leaves this machine" in html
        assert "No data left this machine" not in html

    def test_pass_and_info_are_deemphasized_but_error_is_not(self) -> None:
        html = self._generate(_make_report())
        assert ".frow.is-pass, .frow.is-info { opacity:0.62; }" in html
        assert ".frow.is-pass, .frow.is-error { opacity:0.62; }" not in html

    def test_top_remainder_is_not_called_lower_severity(self) -> None:
        extras = [
            CheckResult(
                "Firewall",
                f"Critical {index}",
                Status.FAIL,
                Severity.CRITICAL,
                "d",
                "off",
                "fix",
            )
            for index in range(9)
        ]
        html = self._generate(_make_report(extra_results=extras))
        assert "additional open findings not shown here" in html
        assert "more lower-severity" not in html

    def test_top_issue_command_toggle_has_aria_contract(self) -> None:
        command = CheckResult(
            "Firewall",
            "Command Finding",
            Status.FAIL,
            Severity.HIGH,
            "d",
            "off",
            "fix",
            "Set-NetFirewallProfile -Enabled True",
        )
        html = self._generate(_make_report(extra_results=[command]))

        match = re.search(
            r'<button class="ti-cmd-toggle"[^>]*aria-expanded="false"'
            r'[^>]*aria-controls="([^"]+)"[^>]*>',
            html,
        )
        assert match is not None
        assert f'id="{match.group(1)}"' in html
        assert "btn.setAttribute('aria-expanded', String(opening));" in html

    def test_exec_link_rendered_when_href_given(self):
        """Header links to a co-generated executive report via exec_href."""
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            reporter.generate_html_report(
                _make_report(), path, exec_href="brief%20v1.html")
            html = Path(path).read_text(encoding="utf-8")
        finally:
            os.unlink(path)
        assert 'class="exec-link"' in html
        assert 'href="brief%20v1.html"' in html
        assert "Executive Report" in html

    def test_no_exec_link_by_default(self):
        """Without exec_href, no dead 'Executive Report' link is rendered."""
        html = self._generate(_make_report())
        assert 'class="exec-link"' not in html
        assert "Executive Report" not in html


# ---------------------------------------------------------------------------
# Executive report (Security Posture Assessment) generation
# ---------------------------------------------------------------------------

class TestGenerateExecutiveReport:
    def _generate(self, report: AuditReport) -> str:
        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            reporter.generate_executive_report(report, path)
            return Path(path).read_text(encoding="utf-8")
        finally:
            os.unlink(path)

    @staticmethod
    def _section(html: str, start_id: str, end_id: str | None = None) -> str:
        """Slice the document between two section ids."""
        part = html.split(f'id="{start_id}"', 1)[1]
        return part.split(f'id="{end_id}"', 1)[0] if end_id else part

    def test_valid_html_document(self):
        html = self._generate(_make_report())
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "Security Posture Assessment" in html

    def test_error_only_report_renders_incomplete_not_all_clear(self) -> None:
        results = [
            CheckResult(
                "Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"
            ),
            CheckResult(
                "Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"
            ),
        ]
        html = self._generate(
            AuditReport(
                hostname="TEST-PC",
                os_version="Windows 11",
                scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                scan_duration=1.0,
                results=results,
                score=100,
                is_admin=True,
            )
        )

        cover = html.split('id="summary"', 1)[0]
        deck = cover.split('<p class="deck">', 1)[1].split("</p>", 1)[0]
        summary = self._section(html, "summary", "glance")

        assert "assessment is incomplete" in deck.lower()
        assert "all evaluated controls passed" not in deck.lower()
        assert 'class="note-box assessment-incomplete"' in summary
        assert 'class="note-box all-clear"' not in summary
        assert "Assessment incomplete" in html
        assert "All clear" not in html

    def test_self_contained_and_script_free(self):
        """Offline and print-first: no network references and no JS at all."""
        html = self._generate(_make_report())
        assert "cdn." not in html
        assert "googleapis.com" not in html
        assert "<script" not in html

    def test_cover_meta_admin(self):
        html = self._generate(_make_report(is_admin=True))
        assert "TEST-PC" in html
        assert "Windows 11 Pro 10.0.22621" in html
        assert "Read-only · non-invasive" in html
        assert "Administrator" in html
        assert "Apotrope v" in html

    def test_cover_meta_standard_user(self):
        html = self._generate(_make_report(is_admin=False))
        assert "Standard user" in html

    def test_gradebox_and_verdict(self):
        # Fixture: 1 CRITICAL FAIL + 1 MEDIUM WARN open → 1 P1, 1 remainder.
        html = self._generate(_make_report(score=80))
        assert 'class="letter">B<' in html
        assert (
            "1 high-priority finding should be addressed this week; "
            "1 further item can be scheduled into routine maintenance." in html
        )

    def test_stat_tiles_and_distribution(self):
        html = self._generate(_make_report())
        assert "Controls passed" in html
        assert "Open findings" in html
        assert "flex-grow:" in html
        assert "Priority-1 item" in html

    def test_tier_assignment_and_order(self):
        low = CheckResult("Hardening", "Low Hygiene Item", Status.FAIL,
                          Severity.LOW, "desc", "found", "Tidy it up")
        html = self._generate(_make_report(extra_results=[low]))
        roadmap = self._section(html, "roadmap", "findings")
        # P1 (CRITICAL fail) before P2 (MEDIUM warn) before P3 (LOW fail).
        i_p1 = roadmap.index("Public Profile")
        i_p2 = roadmap.index("Risky Services")
        i_p3 = roadmap.index("Low Hygiene Item")
        assert i_p1 < i_p2 < i_p3
        assert "No items in this tier." not in roadmap.split("Low Hygiene")[0]

    def test_severity_chip_classes(self):
        extras = [
            CheckResult("Hardening", "Low Sev Item", Status.FAIL,
                        Severity.LOW, "d", "f", "fix"),
            CheckResult("Network", "Info Sev Item", Status.WARN,
                        Severity.INFO, "d", "f", "fix"),
        ]
        html = self._generate(_make_report(extra_results=extras))
        assert 'sev low"' in html
        assert 'sev info"' in html

    def test_cis_ref_shown_when_present(self):
        extra = CheckResult("Firewall", "CIS Tagged Check", Status.FAIL,
                            Severity.HIGH, "d", "f", "fix",
                            cis_reference="CIS 9.9.9")
        html = self._generate(_make_report(extra_results=[extra]))
        assert "CIS 9.9.9" in html

    def test_findings_cards_open_only(self):
        html = self._generate(_make_report())
        findings = self._section(html, "findings", "appendix-a")
        assert "Public Profile" in findings   # FAIL — has a card
        assert "Risky Services" in findings   # WARN — has a card
        assert "Domain Profile" not in findings  # PASS — attestation only
        assert "OS Version" not in findings      # INFO — not open

    def test_impact_copy_known_category_and_fallback(self):
        from markupsafe import escape

        from apotrope.reporter import _EXEC_IMPACT, _EXEC_IMPACT_FALLBACK
        unknown = CheckResult("CustomCat", "Odd Check", Status.FAIL,
                              Severity.HIGH, "d", "f", "fix")
        html = self._generate(_make_report(extra_results=[unknown]))
        # Compare the autoescaped forms (the copy contains apostrophes).
        assert str(escape(_EXEC_IMPACT["Firewall"])) in html
        assert str(escape(_EXEC_IMPACT_FALLBACK)) in html

    def test_attestation_pass_only(self):
        html = self._generate(_make_report())
        attest = self._section(html, "appendix-a", "appendix-b")
        assert "Domain Profile" in attest      # the PASS control
        assert "Public Profile" not in attest  # the FAIL control
        assert "OS Version" not in attest      # INFO is not attested

    def test_commands_ordered_numbered_comment_styled(self):
        extras = [
            CheckResult("Hardening", "Low Cmd Item", Status.FAIL, Severity.LOW,
                        "d", "f", "fix", "Set-Low -Value 1"),
            CheckResult("Firewall", "Crit Cmd Item", Status.FAIL,
                        Severity.CRITICAL, "d", "f", "fix",
                        "# review first\nSet-Crit -Value 1"),
        ]
        html = self._generate(_make_report(extra_results=extras))
        appendix = self._section(html, "appendix-b")
        # P1 command is numbered 01 and appears before the P3 command.
        assert appendix.index("Crit Cmd Item") < appendix.index("Low Cmd Item")
        assert ">01<" in appendix
        assert '<div class="cmt"># review first</div>' in appendix
        assert "PS&gt;" not in appendix  # paper copies must retype clean

    def test_commands_empty_note(self):
        # Base fixture has open findings but none carry a command.
        html = self._generate(_make_report())
        assert "No scripted remediation applies" in html

    def test_clean_report_all_clear(self):
        results = [
            CheckResult("Firewall", "Domain Profile", Status.PASS,
                        Severity.HIGH, "desc", "ok"),
            CheckResult("Accounts", "Guest Account", Status.PASS,
                        Severity.HIGH, "desc", "ok"),
        ]
        report = AuditReport(
            hostname="TEST-PC", os_version="Windows 11",
            scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            scan_duration=1.0, results=results, score=100, is_admin=True,
        )
        html = self._generate(report)
        assert ("All 2 evaluated controls passed; no corrective action is "
                "required at this time." in html)
        assert "No corrective action is required." in html
        assert "no remediation actions to prioritize" in html
        assert "no failed or warning findings" in html

    def test_error_results_excluded_and_noted(self):
        err = CheckResult("Network", "Broken Check", Status.ERROR,
                          Severity.INFO, "d", "probe failed")
        html = self._generate(_make_report(extra_results=[err]))
        findings = self._section(html, "findings", "appendix-a")
        attest = self._section(html, "appendix-a", "appendix-b")
        assert "Broken Check" not in findings
        assert "Broken Check" not in attest
        assert "could not" in html  # caveat sentence in the narrative

    def test_html_special_chars_escaped(self):
        """Autoescape must cover every scan-derived field in this template too."""
        xss = "<script>alert(1)</script>"
        report = AuditReport(
            hostname=f"HOST-{xss}",
            os_version="10.0.22631",
            scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            scan_duration=1.0,
            results=[
                CheckResult(
                    "Security", "XSS Check", Status.FAIL, Severity.HIGH,
                    "desc", f"Details: {xss}", f"Remediate {xss}",
                    f"Set-Item {xss}",
                ),
            ],
            score=50,
            is_admin=False,
        )
        html = self._generate(report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_print_css_present(self):
        html = self._generate(_make_report())
        assert "@page" in html
        assert "size: letter" in html
        assert "break-before: page" in html

    def test_footer_line(self):
        html = self._generate(_make_report())
        foot = html.split('class="doc-foot"')[1]
        assert "Security Posture Assessment" in foot
        assert "TEST-PC" in foot
        assert "Confidential" in foot

    def test_no_file_written_when_jinja2_missing(self):
        import sys
        from unittest import mock

        reporter = Reporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        os.unlink(path)
        try:
            with mock.patch.dict(sys.modules, {"jinja2": None}):
                reporter.generate_executive_report(_make_report(), path)
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
                reporter.generate_executive_report(_make_report(), path)
            assert not os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_frozen_bundle_uses_meipass_template_dir(self):
        """PyInstaller path: templates resolve under sys._MEIPASS/templates."""
        import sys
        from unittest import mock

        import apotrope.reporter as reporter_mod

        package_dir = Path(reporter_mod.__file__).parent
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "_MEIPASS", str(package_dir), create=True):
            html = self._generate(_make_report())
        assert "<!DOCTYPE html>" in html


# ---------------------------------------------------------------------------
# Executive report narrative builders
# ---------------------------------------------------------------------------

class TestExecNarrative:
    @staticmethod
    def _report(results, score=80, is_admin=True):
        return AuditReport(
            hostname="TEST-PC", os_version="Windows 11 Pro 10.0.22621",
            scan_timestamp=datetime(2026, 3, 15, 12, 0, tzinfo=timezone.utc),
            scan_duration=2.0, results=results, score=score, is_admin=is_admin,
        )

    def test_verdict_no_controls(self):
        verdict = Reporter()._build_exec_verdict(self._report([]))
        assert verdict == "No controls could be evaluated in this assessment."

    def test_verdict_clean(self):
        results = [CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH,
                               "d", "ok")]
        verdict = Reporter()._build_exec_verdict(self._report(results, 100))
        assert "All 1 evaluated controls passed" in verdict

    def test_verdict_clean_with_errors(self):
        results = [
            CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"),
            CheckResult("Network", "NB", Status.ERROR, Severity.INFO, "d", "x"),
        ]
        verdict = Reporter()._build_exec_verdict(self._report(results, 100))
        assert "1 control could not be evaluated" in verdict

    def test_verdict_p1(self):
        results = [CheckResult("Firewall", "FW", Status.FAIL,
                               Severity.CRITICAL, "d", "off", "fix")]
        verdict = Reporter()._build_exec_verdict(self._report(results, 85))
        assert "1 high-priority finding should be addressed this week." == verdict

    def test_verdict_score_bands_without_p1(self):
        med = [CheckResult("Services", "Svc", Status.WARN, Severity.MEDIUM,
                           "d", "warn", "fix")]
        r = Reporter()
        assert "strong" in r._build_exec_verdict(self._report(med, 92))
        assert "good" in r._build_exec_verdict(self._report(med, 85))
        assert "fair" in r._build_exec_verdict(self._report(med, 75))
        assert "below standard" in r._build_exec_verdict(self._report(med, 65))
        assert "prompt attention" in r._build_exec_verdict(self._report(med, 40))

    def test_bottom_line_branches(self):
        r = Reporter()
        clean = [CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH,
                             "d", "ok")]
        assert "No corrective action" in str(
            r._build_exec_bottom_line(self._report(clean, 100)))
        p1 = [CheckResult("Firewall", "FW", Status.FAIL, Severity.HIGH,
                          "d", "off", "fix"),
              CheckResult("Services", "Svc", Status.WARN, Severity.MEDIUM,
                          "d", "warn", "fix")]
        line = str(r._build_exec_bottom_line(self._report(p1, 70)))
        assert "Address the 1 Priority 1 item within the week" in line
        assert "remaining 1 item" in line
        med_only = [CheckResult("Services", "Svc", Status.WARN,
                                Severity.MEDIUM, "d", "warn", "fix")]
        assert "routine maintenance" in str(
            r._build_exec_bottom_line(self._report(med_only, 85)))

    def test_bottom_line_does_not_call_error_only_report_clean(self) -> None:
        results = [
            CheckResult(
                "Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"
            ),
            CheckResult(
                "Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"
            ),
        ]

        line = str(Reporter()._build_exec_bottom_line(self._report(results, 100)))

        assert "could not be evaluated" in line
        assert "No corrective action is required" not in line

    def test_paragraphs_scope_and_findings(self):
        results = [
            CheckResult("Firewall", "FW Check", Status.FAIL, Severity.HIGH,
                        "d", "off", "fix"),
            CheckResult("Accounts", "Guest", Status.PASS, Severity.HIGH,
                        "d", "ok"),
        ]
        paras = Reporter()._build_exec_paragraphs(self._report(results, 70))
        joined = " ".join(str(p) for p in paras)
        assert len(paras) >= 2
        assert "15 March 2026" in joined
        assert "with administrator privileges" in joined
        assert "1 check failed" in joined
        assert "FW Check" in joined
        assert "The primary area of concern is <b>Firewall</b>." in joined
        # Accounts has no open findings → named as a clean category.
        assert "Accounts" in joined

    def test_error_category_is_not_claimed_as_fully_passed(self) -> None:
        results = [
            CheckResult(
                "Firewall", "FW", Status.FAIL, Severity.HIGH, "d", "off", "fix"
            ),
            CheckResult(
                "Network", "Known Good", Status.PASS, Severity.INFO, "d", "ok"
            ),
            CheckResult(
                "Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"
            ),
        ]

        paragraphs = Reporter()._build_exec_paragraphs(self._report(results, 90))
        rendered = " ".join(str(paragraph) for paragraph in paragraphs)

        assert "Network category passed all of its checks" not in rendered

    def test_error_only_paragraphs_describe_incomplete_assessment(self) -> None:
        results = [
            CheckResult(
                "Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"
            ),
            CheckResult(
                "Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"
            ),
        ]

        paragraphs = Reporter()._build_exec_paragraphs(self._report(results, 100))
        rendered = " ".join(str(paragraph) for paragraph in paragraphs)

        assert "assessment is incomplete" in rendered
        assert "could not be evaluated" in rendered
        assert "Every evaluated control passed" not in rendered
        assert "system's configuration is in line" not in rendered

    def test_paragraphs_non_admin_clause(self):
        results = [CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH,
                               "d", "ok")]
        paras = Reporter()._build_exec_paragraphs(
            self._report(results, 100, is_admin=False))
        joined = " ".join(str(p) for p in paras)
        assert "without administrator privileges" in joined

    def test_paragraphs_clean_report(self):
        results = [CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH,
                               "d", "ok")]
        paras = Reporter()._build_exec_paragraphs(self._report(results, 100))
        joined = " ".join(str(p) for p in paras)
        assert "Every evaluated control passed" in joined


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
