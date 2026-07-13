"""Tests for apotrope.reporter — Rich terminal rendering paths.

Covers the terminal output surface that test_reporter.py (HTML/JSON) does not:
the score panel, the default triage boxes (per-category FAIL/WARN findings with
fix + run), the --verbose all-category boxes, footer variants, comparison view,
progress runner, glyph/ASCII fallbacks, the narrow-console un-boxed fallback,
and the plain-text fallback used when Rich is not installed.

All tests render to an in-memory console (StringIO file, colors stripped) so
assertions run against plain text on any OS.
"""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from apotrope.compare import ScanDiff
from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.reporter import (
    Reporter,
    _console_is_unicode,
    _glyphs,
    _grade_hex,
    _truncate,
    _u,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _AsciiStringIO(io.StringIO):
    """A StringIO that reports a non-Unicode encoding (forces ASCII glyphs)."""

    encoding = "cp437"


def _make_console(ascii_console: bool = False, width: int = 200):
    """Build a Rich console that records plain text into a StringIO."""
    from rich.console import Console

    file = _AsciiStringIO() if ascii_console else io.StringIO()
    return Console(
        file=file, force_terminal=False, width=width,
        no_color=True, highlight=False,
    )


def _result(
    category: str = "Firewall",
    name: str = "Check",
    status: Status = Status.PASS,
    severity: Severity = Severity.HIGH,
    details: str = "found",
    remediation: str = "",
    command: str = "",
    cis: str = "",
) -> CheckResult:
    return CheckResult(
        category=category,
        check_name=name,
        status=status,
        severity=severity,
        description="desc",
        details=details,
        remediation=remediation,
        command=command,
        cis_reference=cis,
    )


def _report(
    results: list[CheckResult],
    score: int = 70,
    is_admin: bool = True,
) -> AuditReport:
    return AuditReport(
        hostname="TEST-PC",
        os_version="10.0.22621",
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration=1.5,
        results=results,
        score=score,
        is_admin=is_admin,
    )


def _render(
    reporter: Reporter,
    method: str,
    *args,
    ascii_console: bool = False,
    **kwargs,
) -> str:
    """Call *method* on *reporter* with a captive console; return its text."""
    console = _make_console(ascii_console=ascii_console)
    with mock.patch.object(Reporter, "_make_console", return_value=console):
        getattr(reporter, method)(*args, **kwargs)
    return console.file.getvalue()


def _default_results() -> list[CheckResult]:
    return [
        _result("Firewall", "Domain Profile", Status.PASS),
        _result("Antivirus", "Defender Status", Status.FAIL, Severity.CRITICAL,
                remediation="Enable Defender", command="Set-MpPreference X"),
        _result("RDP", "RDP Enabled", Status.WARN, Severity.MEDIUM,
                remediation="Disable RDP", command="Stop-Service TermService"),
        _result("System", "OS Version", Status.INFO, Severity.INFO),
    ]


# ---------------------------------------------------------------------------
# Score panel (default print_terminal view)
# ---------------------------------------------------------------------------

class TestScorePanel:
    def test_score_and_grade_shown(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results(), score=70))
        assert "70 / 100" in out
        assert "C" in out  # grade letter

    def test_hostname_and_os_version_shown(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "TEST-PC" in out
        assert "10.0.22621" in out

    def test_status_distribution_counts(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "1 pass" in out
        assert "1 fail" in out
        assert "1 warn" in out
        assert "1 info" in out

    def test_total_checks_evaluated(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "4 checks evaluated" in out

    def test_error_count_in_distribution(self):
        results = _default_results() + [
            _result("SMB", "SMB Signing", Status.ERROR, Severity.INFO),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert "1 error" in out

    def test_no_error_segment_when_clean(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "error" not in out.split("checks evaluated")[0]


# ---------------------------------------------------------------------------
# Default triage view (per-category issue boxes)
# ---------------------------------------------------------------------------

class TestTriageBoxes:
    def test_issue_categories_boxed_no_top_lists(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "TOP FAILURES" not in out
        assert "TOP WARNINGS" not in out
        assert "ANTIVIRUS" in out   # has a FAIL → boxed
        assert "RDP" in out         # has a WARN → boxed
        assert "FIREWALL" not in out  # PASS only → not in the triage view

    def test_no_boxes_when_clean(self):
        results = [_result(name="Only Pass", status=Status.PASS)]
        out = _render(Reporter(), "print_terminal", _report(results, score=100))
        assert "┌" not in out
        assert "Only Pass" not in out

    def test_failures_sorted_by_severity(self):
        results = [
            _result(name="Low Severity Fail", status=Status.FAIL, severity=Severity.LOW),
            _result(name="Critical Severity Fail", status=Status.FAIL,
                    severity=Severity.CRITICAL),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert out.index("Critical Severity Fail") < out.index("Low Severity Fail")

    def test_worst_category_boxed_first(self):
        results = [
            _result("Mild", "Mild Warn", Status.WARN, Severity.LOW),
            _result("Grave", "Grave Fail", Status.FAIL, Severity.CRITICAL),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert out.index("GRAVE") < out.index("MILD")

    def test_uncapped_all_findings_shown(self):
        results = [
            _result(name=f"Failure Number {i}", status=Status.FAIL, severity=Severity.HIGH)
            for i in range(1, 8)
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        for i in range(1, 8):
            assert f"Failure Number {i}" in out

    def test_long_check_name_truncated_to_box_width(self):
        long_name = "A" * 70
        results = [_result(name=long_name, status=Status.FAIL)]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert long_name not in out
        assert "A" * 65 + "~" in out

    def test_details_fix_and_run_inside_box(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "fix" in out
        assert "Enable Defender" in out
        assert "run" in out
        assert "Set-MpPreference X" in out

    def test_cis_reference_shown_in_narrow_fallback(self):
        # Boxes omit CIS tags (per the redesign spec); the un-boxed fallback
        # for narrow consoles keeps them.
        results = [_result(name="Tagged Fail", status=Status.FAIL, cis="CIS 9.2.1")]
        console = _make_console(width=70)
        with mock.patch.object(Reporter, "_make_console", return_value=console):
            Reporter().print_terminal(_report(results))
        out = console.file.getvalue()
        assert "┌" not in out          # too narrow for boxes
        assert "CIS 9.2.1" in out

    def test_severity_abbreviations_used(self):
        results = [
            _result(name="Crit Fail", status=Status.FAIL, severity=Severity.CRITICAL),
            _result(name="Med Warn", status=Status.WARN, severity=Severity.MEDIUM),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert "CRIT" in out
        assert "MED" in out


# ---------------------------------------------------------------------------
# Fixes in boxes (--fix retired; commands print by default)
# ---------------------------------------------------------------------------

class TestFixesInBoxes:
    def test_no_top_fixes_block(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "TOP FIXES" not in out
        assert "elevated PowerShell" not in out

    def test_commands_printed_by_default(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "Set-MpPreference X" in out
        assert "Stop-Service TermService" in out

    def test_fix_param_is_noop(self):
        report = _report(_default_results())
        assert (_render(Reporter(fix=True), "print_terminal", report)
                == _render(Reporter(), "print_terminal", report))

    def test_multiline_command_all_lines_present(self):
        results = [_result(
            name="Multi Step Fix", status=Status.FAIL,
            command="First-Command -A 1\nSecond-Command -B 2",
        )]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert "First-Command -A 1" in out
        assert "Second-Command -B 2" in out

    def test_finding_without_command_still_boxed(self):
        results = [
            _result(name="Fixable Fail", status=Status.FAIL, command="Do-Fix"),
            _result(name="Unfixable Fail", status=Status.FAIL, command=""),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert "Fixable Fail" in out
        assert "Do-Fix" in out
        assert "Unfixable Fail" in out  # shown, just without a run line

    def test_pass_results_never_included(self):
        results = [_result(name="Passing Check", status=Status.PASS, command="Noop")]
        out = _render(Reporter(), "print_terminal", _report(results, score=100))
        assert "Passing Check" not in out
        assert "Noop" not in out

    def test_fail_ordered_before_warn_within_severity(self):
        results = [
            _result(name="Warn Finding", status=Status.WARN,
                    severity=Severity.CRITICAL, command="Fix-Warn"),
            _result(name="Fail Finding", status=Status.FAIL,
                    severity=Severity.CRITICAL, command="Fix-Fail"),
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert out.index("Fail Finding") < out.index("Warn Finding")

    def test_all_fixes_shown_uncapped(self):
        results = [
            _result(name=f"Fix {i}", status=Status.FAIL, command=f"Cmd-{i}")
            for i in range(7)
        ]
        out = _render(Reporter(), "print_terminal", _report(results))
        for i in range(7):
            assert f"Cmd-{i}" in out
        assert "fixes shown" not in out  # old overflow counter is gone


# ---------------------------------------------------------------------------
# --verbose: every category boxed, every check shown
# ---------------------------------------------------------------------------

class TestVerboseBoxes:
    def test_category_headers_with_score_badge(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert "ANTIVIRUS" in out
        assert "FIREWALL" in out  # PASS-only category boxed under --verbose
        assert "/100" in out

    def test_categories_sorted_alphabetically(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert out.index("ANTIVIRUS") < out.index("FIREWALL") < out.index("RDP")

    def test_label_columns_dropped_fix_kept(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert "severity" not in out   # old per-check label column is gone
        assert "details" not in out
        assert "fix" in out
        assert "CRIT" in out           # abbreviated, right-aligned severity
        assert "Enable Defender" in out

    def test_command_printed_with_run_label(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert "run" in out
        assert "Set-MpPreference X" in out

    def test_multiline_command_kept_verbatim(self):
        results = [_result(
            name="Multi", status=Status.FAIL,
            command="Step-One -Very -Long\nStep-Two",
        )]
        out = _render(Reporter(verbose=True), "print_terminal", _report(results))
        assert "Step-One -Very -Long" in out
        assert "Step-Two" in out

    def test_long_details_wrapped(self):
        results = [_result(name="Wordy", status=Status.FAIL,
                           details="word " * 40)]
        out = _render(Reporter(verbose=True), "print_terminal", _report(results))
        detail_lines = [ln for ln in out.splitlines() if "word" in ln]
        assert len(detail_lines) >= 2

    def test_no_top_findings_in_verbose_mode(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert "TOP FAILURES" not in out

    def test_passing_check_has_no_fix_or_run(self):
        results = [_result(name="Healthy Check", status=Status.PASS,
                           remediation="Should not print", command="Should-Not-Run")]
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(results, score=100))
        assert "Healthy Check" in out
        assert "Should not print" not in out
        assert "Should-Not-Run" not in out

    def test_cis_reference_shown_in_narrow_fallback(self):
        results = [_result(name="Tagged Check", status=Status.FAIL, cis="CIS 2.3.1")]
        console = _make_console(width=70)
        with mock.patch.object(Reporter, "_make_console", return_value=console):
            Reporter(verbose=True).print_terminal(_report(results))
        out = console.file.getvalue()
        assert "CIS 2.3.1" in out


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

class TestFooter:
    def test_html_path_with_issues(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()),
                      html_path="report.html")
        assert "report.html written" in out
        assert "open to triage all 2 issues" in out

    def test_html_path_clean(self):
        results = [_result(status=Status.PASS)]
        out = _render(Reporter(), "print_terminal", _report(results, score=100),
                      html_path="report.html")
        assert "clean — no issues to triage" in out

    def test_issues_without_html_suggests_html_flag(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "2 issues to triage" in out
        assert "--html report.html" in out

    def test_singular_issue_pluralization(self):
        results = [_result(name="Solo Fail", status=Status.FAIL)]
        out = _render(Reporter(), "print_terminal", _report(results))
        assert "1 issue to triage" in out

    def test_clean_without_html(self):
        results = [_result(status=Status.PASS)]
        out = _render(Reporter(), "print_terminal", _report(results, score=100))
        assert "no issues to triage" in out
        assert "--html report.html for the full report" in out

    def test_json_path_mentioned(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()),
                      json_path="report.json")
        assert "report.json written" in out

    def test_exec_path_mentioned(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()),
                      exec_path="brief.html")
        assert "brief.html written" in out
        assert "executive summary for decision makers" in out

    def test_no_exec_hint_by_default(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "executive summary" not in out

    def test_error_caveat_admin_points_to_debug(self):
        results = [_result(name="Broken", status=Status.ERROR, severity=Severity.INFO)]
        out = _render(Reporter(), "print_terminal", _report(results, score=100))
        assert "1 check could not complete" in out
        assert "--log-level DEBUG" in out
        assert "run as Administrator" not in out

    def test_error_caveat_non_admin_suggests_elevation(self):
        results = [_result(name="Broken", status=Status.ERROR, severity=Severity.INFO)]
        out = _render(Reporter(), "print_terminal",
                      _report(results, score=100, is_admin=False))
        assert "1 check could not complete" in out
        assert "run as Administrator" in out

    def test_error_caveat_pluralized(self):
        results = [
            _result(name=f"Broken {i}", status=Status.ERROR, severity=Severity.INFO)
            for i in range(2)
        ]
        out = _render(Reporter(), "print_terminal", _report(results, score=100))
        assert "2 checks could not complete" in out

    def test_non_admin_note(self):
        out = _render(Reporter(), "print_terminal",
                      _report(_default_results(), is_admin=False))
        assert "some checks skipped" in out

    def test_no_non_admin_note_when_admin(self):
        out = _render(Reporter(), "print_terminal",
                      _report(_default_results(), is_admin=True))
        assert "some checks skipped" not in out

    def test_default_hint_mentions_verbose_but_not_fix(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()))
        assert "--verbose for per-check detail" in out
        assert "--fix" not in out  # retired flag is never advertised

    def test_verbose_footer_drops_verbose_hint(self):
        out = _render(Reporter(verbose=True), "print_terminal",
                      _report(_default_results()))
        assert "issues to triage" in out
        assert "--verbose for per-check detail" not in out


# ---------------------------------------------------------------------------
# print_comparison
# ---------------------------------------------------------------------------

def _diff(
    baseline_score: int = 60,
    current_score: int = 75,
    new: list[CheckResult] | None = None,
    resolved: list[CheckResult] | None = None,
    worsened: list[CheckResult] | None = None,
    unchanged_bad: list[CheckResult] | None = None,
    unchanged_count: int = 0,
    score_delta_reliable: bool = True,
) -> ScanDiff:
    return ScanDiff(
        baseline_score=baseline_score,
        current_score=current_score,
        score_delta=current_score - baseline_score,
        new_findings=new or [],
        resolved_findings=resolved or [],
        worsened_findings=worsened or [],
        unchanged_bad=unchanged_bad or [],
        unchanged_count=unchanged_count,
        score_delta_reliable=score_delta_reliable,
    )


class TestPrintComparison:
    def test_unreliable_positive_delta_is_yellow_not_green_markup(self) -> None:
        diff = _diff(90, 100, score_delta_reliable=False)
        console = mock.Mock()
        console.encoding = "utf-8"

        with mock.patch.object(Reporter, "_make_console", return_value=console):
            Reporter().print_comparison(diff)

        comparison_markup = console.print.call_args_list[1].args[0]
        assert "[yellow]+10 raw · indeterminate[/yellow]" in comparison_markup
        assert "[green]+10 raw · indeterminate[/green]" not in comparison_markup

    def test_score_transition_with_positive_delta(self):
        out = _render(Reporter(), "print_comparison", _diff(60, 75))
        assert "60" in out
        assert "75" in out
        assert "+15" in out

    def test_negative_delta_has_no_plus_sign(self):
        out = _render(Reporter(), "print_comparison", _diff(80, 65))
        assert "-15" in out
        assert "+-15" not in out

    def test_sections_rendered_with_findings(self):
        resolved = [_result(name="Fixed Check", status=Status.PASS)]
        new = [_result(name="Fresh Fail", status=Status.FAIL)]
        worsened = [_result(name="Regressed Check", status=Status.WARN)]
        ongoing = [_result(name="Still Bad", status=Status.FAIL)]
        out = _render(Reporter(), "print_comparison",
                      _diff(resolved=resolved, new=new, worsened=worsened,
                            unchanged_bad=ongoing))
        for label in ("Resolved", "New", "Worsened", "Ongoing"):
            assert label in out
        for name in ("Fixed Check", "Fresh Fail", "Regressed Check", "Still Bad"):
            assert name in out

    def test_no_changes_message(self):
        out = _render(Reporter(), "print_comparison", _diff(70, 70, unchanged_count=4))
        assert "No changes detected" in out

    def test_summary_counts_line(self):
        out = _render(Reporter(), "print_comparison",
                      _diff(new=[_result(name="N", status=Status.FAIL)],
                            unchanged_count=3))
        assert "Resolved: 0" in out
        assert "New: 1" in out
        assert "Unchanged: 3" in out


# ---------------------------------------------------------------------------
# run_with_progress
# ---------------------------------------------------------------------------

class _StubScanner:
    """Scanner stand-in: fixed module list, canned report, records callbacks."""

    def __init__(self, report: AuditReport, is_admin: bool = True) -> None:
        self._report = report
        self.is_admin = is_admin
        self.started: list[object] = []
        self.run_called_with_modules: object = "unset"

    def discover_modules(self) -> list:
        return [SimpleNamespace(__name__="mod_a"), SimpleNamespace(__name__="mod_b")]

    def run(self, modules=None, on_module_start=None) -> AuditReport:
        self.run_called_with_modules = modules
        if on_module_start is not None:
            for m in modules or []:
                on_module_start(m)
                self.started.append(m)
        return self._report


class TestRunWithProgress:
    def test_returns_report_and_prints_banner(self):
        scanner = _StubScanner(_report(_default_results()))
        console = _make_console()
        with mock.patch.object(Reporter, "_make_console", return_value=console):
            report = Reporter().run_with_progress(scanner)
        out = console.file.getvalue()
        assert report is scanner._report
        assert "APOTROPE" in out
        assert "Windows Security Posture Auditor" in out

    def test_completion_line_shows_count_and_duration(self):
        scanner = _StubScanner(_report(_default_results()))
        out = _render(Reporter(), "run_with_progress", scanner)
        assert "scanning 4 controls" in out
        assert "done" in out
        assert "1.5s" in out

    def test_passes_discovered_modules_to_run(self):
        scanner = _StubScanner(_report(_default_results()))
        _render(Reporter(), "run_with_progress", scanner)
        assert scanner.run_called_with_modules != "unset"
        assert len(scanner.run_called_with_modules) == 2
        assert len(scanner.started) == 2

    def test_non_admin_warning_shown(self):
        scanner = _StubScanner(_report(_default_results()), is_admin=False)
        out = _render(Reporter(), "run_with_progress", scanner)
        assert "running without administrator privileges" in out
        assert "run elevated for a full audit" in out

    def test_no_warning_when_admin(self):
        scanner = _StubScanner(_report(_default_results()), is_admin=True)
        out = _render(Reporter(), "run_with_progress", scanner)
        assert "running without administrator privileges" not in out

    def test_falls_back_to_plain_run_without_rich_progress(self):
        scanner = _StubScanner(_report(_default_results()))
        with mock.patch.dict(sys.modules, {"rich.progress": None}):
            report = Reporter().run_with_progress(scanner)
        assert report is scanner._report
        # Fallback path calls scanner.run() with default (None) modules.
        assert scanner.run_called_with_modules is None


# ---------------------------------------------------------------------------
# Plain-text fallback (Rich unavailable)
# ---------------------------------------------------------------------------

class TestPlainFallback:
    def test_print_terminal_falls_back_without_rich(self, capsys):
        report = _report(_default_results())
        with mock.patch.dict(sys.modules, {"rich.console": None}):
            Reporter().print_terminal(report)
        out = capsys.readouterr().out
        assert "TEST-PC" in out
        assert "Score: 70/100" in out

    def test_plain_lists_every_result_with_icon(self, capsys):
        Reporter()._print_plain(_report(_default_results()))
        out = capsys.readouterr().out
        assert "PASS: 1  FAIL: 1  WARN: 1" in out
        assert "[✓]" in out
        assert "[✗]" in out
        assert "[!]" in out
        assert "Antivirus: Defender Status" in out

    def test_plain_verbose_shows_details_fix_and_command(self, capsys):
        Reporter(verbose=True)._print_plain(_report(_default_results()))
        out = capsys.readouterr().out
        assert "RealTimeProtectionEnabled" not in out  # not in our fixture details
        assert "found" in out
        assert "Fix: Enable Defender" in out
        assert "Set-MpPreference X" in out

    def test_plain_non_verbose_shows_fixes_hides_pass_detail(self, capsys):
        """Fixes print by default for FAIL/WARN; PASS detail needs --verbose."""
        results = [
            _result(name="Quiet Pass", status=Status.PASS,
                    details="pass-only-detail"),
            _result(name="Loud Fail", status=Status.FAIL,
                    remediation="Enable Defender", command="Set-MpPreference X"),
        ]
        Reporter()._print_plain(_report(results))
        out = capsys.readouterr().out
        assert "Fix: Enable Defender" in out
        assert "Set-MpPreference X" in out
        assert "pass-only-detail" not in out


# ---------------------------------------------------------------------------
# ASCII fallback rendering (non-Unicode console)
# ---------------------------------------------------------------------------

class TestAsciiFallback:
    def test_print_terminal_uses_ascii_glyphs(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()),
                      ascii_console=True)
        assert "[+]" in out   # pass glyph
        assert "[x]" in out   # fail glyph
        assert "#" in out     # score bar fill
        assert "✓" not in out
        assert "█" not in out

    def test_footer_arrow_is_ascii(self):
        out = _render(Reporter(), "print_terminal", _report(_default_results()),
                      ascii_console=True)
        assert "->" in out
        assert "→" not in out


# ---------------------------------------------------------------------------
# Executive summary branches not covered by the HTML-focused tests
# ---------------------------------------------------------------------------

class TestExecutiveSummaryBranches:
    def _results_multi_cat_with_error(self) -> list[CheckResult]:
        return [
            _result("Firewall", "FW Fail", Status.FAIL, Severity.HIGH,
                    remediation="fix"),
            _result("RDP", "RDP Warn", Status.WARN, Severity.MEDIUM,
                    remediation="fix"),
            _result("SMB", "SMB Error", Status.ERROR, Severity.INFO),
        ]

    def test_plain_summary_joins_multiple_categories(self):
        s = Reporter()._build_executive_summary(
            _report(self._results_multi_cat_with_error()))
        assert "primary areas of concern" in s
        assert "Firewall" in s and "RDP" in s
        assert " and " in s

    def test_plain_summary_notes_incomplete_checks(self):
        s = Reporter()._build_executive_summary(
            _report(self._results_multi_cat_with_error()))
        assert "1 check could not complete" in s

    def test_html_summary_joins_multiple_categories(self):
        s = str(Reporter()._build_executive_summary_html(
            _report(self._results_multi_cat_with_error())))
        assert "primary areas of concern" in s
        assert "<b>Firewall</b>" in s and "<b>RDP</b>" in s

    def test_html_summary_notes_incomplete_checks(self):
        s = str(Reporter()._build_executive_summary_html(
            _report(self._results_multi_cat_with_error())))
        assert "1 check could not complete" in s


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

class TestMakeConsole:
    def test_returns_console_honouring_no_color(self):
        from rich.console import Console

        console = Reporter(no_color=True)._make_console()
        assert isinstance(console, Console)
        assert console.no_color is True

    def test_color_enabled_by_default(self):
        assert Reporter()._make_console().no_color is False


class TestMakeConsoleModern:
    def test_truecolor_forced_on_real_terminal(self):
        with mock.patch("rich.console.Console.is_terminal",
                        new_callable=mock.PropertyMock, return_value=True), \
             mock.patch("apotrope.reporter._modernize_windows_console") as modernize:
            console = Reporter(no_color=False)._make_console()
            assert console.color_system == "truecolor"
            assert console.legacy_windows is False
        modernize.assert_called_once()

    def test_not_a_terminal_skips_truecolor_and_modernize(self):
        with mock.patch("rich.console.Console.is_terminal",
                        new_callable=mock.PropertyMock, return_value=False), \
             mock.patch("apotrope.reporter._modernize_windows_console") as modernize:
            console = Reporter(no_color=False)._make_console()
        assert console.no_color is False
        modernize.assert_not_called()

    def test_no_color_skips_truecolor_and_modernize(self):
        with mock.patch("rich.console.Console.is_terminal",
                        new_callable=mock.PropertyMock, return_value=True), \
             mock.patch("apotrope.reporter._modernize_windows_console") as modernize:
            console = Reporter(no_color=True)._make_console()
        assert console.no_color is True
        modernize.assert_not_called()


class TestModernizeWindowsConsole:
    def test_noop_on_non_windows(self):
        from apotrope.reporter import _modernize_windows_console
        with mock.patch.object(sys, "platform", "linux"):
            _modernize_windows_console()  # no windll on Linux → must not raise

    def test_enables_vt_and_utf8_on_windows(self):
        from apotrope import reporter
        k32 = mock.MagicMock()
        k32.GetConsoleMode.return_value = 1   # a console is attached
        windll = mock.MagicMock(kernel32=k32)
        with mock.patch.object(sys, "platform", "win32"), \
             mock.patch("ctypes.windll", windll, create=True):
            reporter._modernize_windows_console()
        k32.SetConsoleMode.assert_called_once()
        k32.SetConsoleOutputCP.assert_called_once_with(65001)

    def test_bails_when_stdout_redirected(self):
        from apotrope import reporter
        k32 = mock.MagicMock()
        k32.GetConsoleMode.return_value = 0   # no console handle
        windll = mock.MagicMock(kernel32=k32)
        with mock.patch.object(sys, "platform", "win32"), \
             mock.patch("ctypes.windll", windll, create=True):
            reporter._modernize_windows_console()
        k32.SetConsoleMode.assert_not_called()
        k32.SetConsoleOutputCP.assert_not_called()

    def test_swallows_api_exception(self):
        from apotrope import reporter
        windll = mock.MagicMock()
        windll.kernel32.GetStdHandle.side_effect = OSError("boom")
        with mock.patch.object(sys, "platform", "win32"), \
             mock.patch("ctypes.windll", windll, create=True):
            reporter._modernize_windows_console()  # must not raise


class TestGlyphHelpers:
    def test_console_is_unicode_for_utf8(self):
        assert _console_is_unicode(SimpleNamespace(encoding="utf-8")) is True

    def test_console_is_unicode_for_utf_16(self):
        assert _console_is_unicode(SimpleNamespace(encoding="UTF-16")) is True

    def test_console_not_unicode_for_codepage(self):
        assert _console_is_unicode(SimpleNamespace(encoding="cp1252")) is False

    def test_missing_encoding_defaults_to_unicode(self):
        assert _console_is_unicode(SimpleNamespace()) is True

    def test_u_picks_unicode_or_ascii(self):
        utf = SimpleNamespace(encoding="utf-8")
        cp = SimpleNamespace(encoding="cp850")
        assert _u(utf, "→", "->") == "→"
        assert _u(cp, "→", "->") == "->"

    def test_glyph_sets_differ(self):
        utf = _glyphs(SimpleNamespace(encoding="utf-8"))
        asc = _glyphs(SimpleNamespace(encoding="ascii"))
        assert utf["pass"] == "✓"
        assert asc["pass"] == "[+]"
        assert asc["flag"] == ""  # no ASCII flag glyph

    def test_truncate_short_string_unchanged(self):
        assert _truncate("short", 10) == "short"

    def test_truncate_exact_length_unchanged(self):
        assert _truncate("x" * 10, 10) == "x" * 10

    def test_truncate_long_string_marked(self):
        out = _truncate("a" * 20, 10)
        assert out == "a" * 9 + "~"
        assert len(out) == 10

    def test_grade_hex_bands(self):
        assert _grade_hex(100) == _grade_hex(80)   # green band
        assert _grade_hex(79) == _grade_hex(60)    # amber band
        assert _grade_hex(59) == _grade_hex(0)     # red band
        assert _grade_hex(80) != _grade_hex(79)
        assert _grade_hex(60) != _grade_hex(59)
