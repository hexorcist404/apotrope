"""Output formatting for Apotrope audit reports.

Supports:
  - Rich-formatted terminal output with progress, panels, and color
  - HTML report via Jinja2 template
  - JSON export
"""

from __future__ import annotations

import dataclasses
import json
import logging
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apotrope.scanner import Scanner

from apotrope import __version__
from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.scoring import calculate_category_scores, score_grade

log = logging.getLogger(__name__)

# ── Status display config ─────────────────────────────────────────────────────

_STATUS_COLOR: dict[Status, str] = {
    Status.PASS:  "green",
    Status.FAIL:  "red",
    Status.WARN:  "yellow",
    Status.INFO:  "cyan",
    Status.ERROR: "dim",
}

_STATUS_ICON: dict[Status, str] = {
    Status.PASS:  "✓",
    Status.FAIL:  "✗",
    Status.WARN:  "!",
    Status.INFO:  "i",
    Status.ERROR: "?",
}

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "blue",
    Severity.INFO:     "dim",
}

# Letter grade → Rich color
_GRADE_COLOR: dict[str, str] = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "bold red",
}

# Severity sort key for top-issues ranking
_SEV_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

_TOP_ISSUES_COUNT  = 5
_SCORE_BAR_WIDTH   = 34
_DETAIL_INLINE_MAX = 60
_REM_WRAP_WIDTH    = 72


# ── Helpers ───────────────────────────────────────────────────────────────────

def _console_is_unicode(console) -> bool:
    """Return True if the console encoding can represent Unicode characters."""
    enc = (getattr(console, "encoding", None) or "utf-8").lower().replace("-", "")
    return "utf" in enc


def _u(console, unicode_char: str, ascii_char: str) -> str:
    """Return *unicode_char* when the console supports it, else *ascii_char*."""
    return unicode_char if _console_is_unicode(console) else ascii_char


def _score_bar(score: int, filled_char: str = "=", empty_char: str = "-") -> str:
    """Return a filled/empty progress bar string for *score* (0–100)."""
    filled = round(score / 100 * _SCORE_BAR_WIDTH)
    return filled_char * filled + empty_char * (_SCORE_BAR_WIDTH - filled)


def _truncate(text: str, maxlen: int) -> str:
    return text if len(text) <= maxlen else text[:maxlen - 1] + "~"


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:
    """Formats and outputs Apotrope audit reports.

    Args:
        verbose:  Show details and remediation for every check result.
        no_color: Disable Rich color markup (produces plain, no-ANSI output).
    """

    def __init__(self, verbose: bool = False, no_color: bool = False) -> None:
        self.verbose = verbose
        self.no_color = no_color

    # ── Public API ────────────────────────────────────────────────────────────

    def run_with_progress(self, scanner: "Scanner") -> AuditReport:
        """Run *scanner* while showing a Rich progress bar.

        Prints the Apotrope banner above the progress bar, then runs each
        check module in turn updating the bar.  The caller should then call
        :meth:`print_terminal` to display the results.

        Args:
            scanner: Configured :class:`~apotrope.scanner.Scanner` instance.

        Returns:
            Completed :class:`~apotrope.models.AuditReport`.
        """
        try:
            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )
        except ImportError:
            return scanner.run()

        console = self._make_console()
        modules = scanner.discover_modules()
        total   = len(modules)

        console.print()
        self._print_banner(console)
        if not scanner.is_admin:
            self._print_non_admin_warning(console)
        console.print()

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description:<24}[/cyan]"),
            BarColumn(bar_width=28, style="dim blue", complete_style="cyan"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Initializing…", total=total)

            def _on_module(module) -> None:
                cat = getattr(module, "CATEGORY", module.__name__)
                progress.update(task, description=cat, advance=1)

            report = scanner.run(modules=modules, on_module_start=_on_module)
            progress.update(task, description="Scan complete")

        console.print()
        return report

    def print_terminal(
        self,
        report: AuditReport,
        html_path: str | None = None,
        json_path: str | None = None,
    ) -> None:
        """Print the completed audit report to the terminal.

        Args:
            report:    Completed :class:`~apotrope.models.AuditReport`.
            html_path: If set, shown in footer as the saved HTML path.
            json_path: If set, shown in footer as the saved JSON path.
        """
        try:
            from rich.console import Console  # noqa: F401 – ensure Rich is present
        except ImportError:
            log.warning("Rich not installed — falling back to plain text output")
            self._print_plain(report)
            return

        console = self._make_console()
        self._print_score_panel(console, report)
        self._print_category_panels(console, report)
        self._print_top_issues(console, report)
        self._print_footer(console, report, html_path, json_path)

    def generate_html_report(self, report: AuditReport, path: str) -> None:
        """Render and save a self-contained HTML report via the Jinja2 template.

        Args:
            report: Completed :class:`~apotrope.models.AuditReport`.
            path:   Destination file path for the HTML file.
        """
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            log.error("Jinja2 not installed — cannot generate HTML report")
            return

        import sys
        if getattr(sys, "frozen", False):
            # Running inside a PyInstaller one-file bundle; templates were
            # added with --add-data "...;templates" so they extract to
            # sys._MEIPASS/templates/
            template_dir = Path(sys._MEIPASS) / "templates"  # type: ignore[attr-defined]
        else:
            # Templates ship as package data inside apotrope/templates/, so the
            # directory sits next to this module for both editable and installed
            # (pip / PyPI) installs.
            template_dir = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,  # Always escape — the template is always HTML.
            # Note: select_autoescape(["html"]) would NOT autoescape "report.html.j2"
            # because it checks the last extension (".j2"), not the full name.
        )
        try:
            template = env.get_template("report.html.j2")
        except Exception as exc:
            log.error("Could not load HTML template: %s", exc)
            return

        html = template.render(**self._build_template_context(report))
        Path(path).write_text(html, encoding="utf-8")
        log.info("HTML report saved to %s", path)

    def generate_json_report(self, report: AuditReport, path: str) -> None:
        """Serialize the AuditReport to a JSON file.

        Args:
            report: Completed :class:`~apotrope.models.AuditReport`.
            path:   Destination file path for the JSON file.
        """

        def _default(obj):
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            if isinstance(obj, (Status, Severity)):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        Path(path).write_text(
            json.dumps(dataclasses.asdict(report), indent=2, default=_default),
            encoding="utf-8",
        )
        log.info("JSON report saved to %s", path)

    def print_comparison(self, diff: object) -> None:
        """Print a scan comparison diff table to the terminal.

        Args:
            diff: A :class:`~apotrope.compare.ScanDiff` from
                  :func:`~apotrope.compare.compare_reports`.
        """
        from apotrope.compare import ScanDiff

        assert isinstance(diff, ScanDiff)
        console = self._make_console()
        sep = _u(console, "─", "-")
        delta_sign = "+" if diff.score_delta >= 0 else ""
        delta_col = "green" if diff.score_delta >= 0 else "red"

        console.print()
        console.print(
            f"  [bold]Comparison vs baseline[/bold]  "
            f"Score: [dim]{diff.baseline_score}[/dim] \u2192 "
            f"[bold]{diff.current_score}[/bold]  "
            f"([{delta_col}]{delta_sign}{diff.score_delta}[/{delta_col}])"
        )
        console.print(f"  {sep * 65}")

        sections: list[tuple[str, str, list]] = [
            ("green",  "Resolved", diff.resolved_findings),
            ("red",    "New",      diff.new_findings),
            ("yellow", "Worsened", diff.worsened_findings),
            ("yellow", "Ongoing",  diff.unchanged_bad),
        ]

        any_printed = False
        for colour, label, findings in sections:
            if not findings:
                continue
            any_printed = True
            console.print(f"\n  [{colour} bold]{label}[/{colour} bold]  ({len(findings)})")
            for r in findings:
                console.print(
                    f"    [{colour}]{r.status.value:5}[/{colour}]  "
                    f"[dim]{r.severity.value:8}[/dim]  "
                    f"{r.category} / {r.check_name}"
                )

        if not any_printed:
            console.print(
                "  [green]No changes detected — scan results match baseline.[/green]"
            )

        console.print(f"  {sep * 65}")
        console.print(
            f"  Resolved: {len(diff.resolved_findings)}  |  "
            f"New: {len(diff.new_findings)}  |  "
            f"Worsened: {len(diff.worsened_findings)}  |  "
            f"Unchanged: {diff.unchanged_count}"
        )
        console.print()

    # ── Internal rendering helpers ────────────────────────────────────────────

    def _build_template_context(self, report: AuditReport) -> dict:
        """Build the full Jinja2 template variable dict for the HTML report."""
        from collections import defaultdict

        letter, label = score_grade(report.score)
        cat_scores = calculate_category_scores(report.results)

        _sev_ord: dict[Severity, int] = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2,   Severity.LOW: 3, Severity.INFO: 4,
        }
        _sta_ord: dict[Status, int] = {
            Status.FAIL: 0, Status.WARN: 1, Status.ERROR: 2,
            Status.PASS: 3, Status.INFO: 4,
        }

        def _sort_key(r: CheckResult) -> tuple[int, int]:
            return (_sta_ord.get(r.status, 5), _sev_ord.get(r.severity, 5))

        # Per-category data (sorted by category name, results by status/severity)
        by_cat: dict[str, list[CheckResult]] = defaultdict(list)
        for r in report.results:
            by_cat[r.category].append(r)

        category_data = []
        for cat_name in sorted(by_cat):
            cat_results = sorted(by_cat[cat_name], key=_sort_key)
            cs = cat_scores.get(cat_name, 100)
            cl, clbl = score_grade(cs)
            category_data.append({
                "name":        cat_name,
                "score":       cs,
                "grade":       cl,
                "grade_label": clbl,
                "results":     cat_results,
                "fail_count":  sum(1 for r in cat_results if r.status == Status.FAIL),
                "warn_count":  sum(1 for r in cat_results if r.status == Status.WARN),
                "pass_count":  sum(1 for r in cat_results if r.status == Status.PASS),
                "error_count": sum(1 for r in cat_results if r.status == Status.ERROR),
            })

        # Top findings: CRITICAL+HIGH FAIL/WARN, up to 5
        issues = [r for r in report.results if r.status in (Status.FAIL, Status.WARN)]
        issues.sort(key=lambda r: (_sev_ord.get(r.severity, 5),
                                   0 if r.status == Status.FAIL else 1))
        top_findings = [
            r for r in issues
            if r.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]

        # All FAIL+WARN for detailed findings section
        fail_warn_results = sorted(
            [r for r in report.results if r.status in (Status.FAIL, Status.WARN)],
            key=_sort_key,
        )

        # INFO results for appendix
        info_results = [r for r in report.results if r.status == Status.INFO]

        ts = report.scan_timestamp
        generated_at = (
            ts.strftime("%Y-%m-%d %H:%M UTC") if ts.tzinfo
            else ts.strftime("%Y-%m-%d %H:%M")
        )

        return {
            "report":            report,
            "version":           __version__,
            "score_grade":       letter,
            "score_label":       label,
            "executive_summary": self._build_executive_summary(report),
            "category_data":     category_data,
            "top_findings":      top_findings,
            "fail_warn_results": fail_warn_results,
            "info_results":      info_results,
            "generated_at":      generated_at,
        }

    def _build_executive_summary(self, report: AuditReport) -> str:
        """Auto-generate a one-paragraph executive summary from report findings."""
        from collections import Counter

        letter, label = score_grade(report.score)
        total = len(report.results)

        critical_fails = sum(
            1 for r in report.results
            if r.status == Status.FAIL and r.severity == Severity.CRITICAL
        )
        high_fails = sum(
            1 for r in report.results
            if r.status == Status.FAIL and r.severity == Severity.HIGH
        )

        # Categories with the most issues (FAIL or WARN)
        issue_cats = Counter(
            r.category for r in report.results
            if r.status in (Status.FAIL, Status.WARN)
        )

        parts: list[str] = []

        # Opening — always present
        parts.append(
            f"The security posture of {report.hostname} has been assessed as "
            f"{label} with an overall score of {report.score}/100 ({letter}) "
            f"across {total} security checks."
        )

        if report.fail_count == 0 and report.warn_count == 0:
            parts.append(
                "All checks passed with no failures or warnings detected. "
                "The system appears to be well-configured according to "
                "Windows security best practices."
            )
            return "  ".join(parts)

        # Severity callout
        if critical_fails > 0:
            noun = "finding" if critical_fails == 1 else "findings"
            verb = "requires" if critical_fails == 1 else "require"
            parts.append(
                f"{critical_fails} critical {noun} {verb} immediate remediation."
            )
        elif high_fails > 0:
            noun = "finding" if high_fails == 1 else "findings"
            parts.append(
                f"{high_fails} high-severity {noun} should be addressed promptly."
            )

        # Fail/warn summary
        detail_parts: list[str] = []
        if report.fail_count > 0:
            n = report.fail_count
            detail_parts.append(f"{n} check{'s' if n != 1 else ''} failed")
        if report.warn_count > 0:
            n = report.warn_count
            detail_parts.append(f"{n} check{'s' if n != 1 else ''} issued warnings")
        if detail_parts:
            parts.append(f"Of the checks performed, {' and '.join(detail_parts)}.")

        # Top affected categories
        if issue_cats:
            top_cats = [cat for cat, _ in issue_cats.most_common(3)]
            if len(top_cats) == 1:
                parts.append(f"The primary area of concern is {top_cats[0]}.")
            else:
                joined = ", ".join(top_cats[:-1]) + f" and {top_cats[-1]}"
                parts.append(f"The primary areas of concern are {joined}.")

        parts.append(
            "Remediation should be prioritized by severity, "
            "addressing critical and high severity findings first."
        )

        if report.error_count:
            n = report.error_count
            parts.append(
                f"Note: {n} check{'s' if n != 1 else ''} could not complete "
                "(run as Administrator for full results)."
            )

        return "  ".join(parts)

    def _make_console(self):
        from rich.console import Console
        return Console(no_color=self.no_color, highlight=False)

    def _print_non_admin_warning(self, console) -> None:
        """Print a warning panel when the scan is running without elevation."""
        from rich.panel import Panel
        warn = _u(console, "⚠  ", "! ")
        console.print(Panel(
            f"  {warn}[yellow bold]Running without administrator privileges.[/yellow bold]\n"
            "  Some checks (BitLocker, SMB configuration) will be skipped.\n"
            "  For a complete audit, right-click and [bold]Run as Administrator[/bold].",
            border_style="yellow",
            padding=(0, 1),
        ))

    def _print_banner(self, console) -> None:
        """Print the Apotrope logo panel."""
        from rich.align import Align
        from rich.panel import Panel
        from rich.text import Text

        diamond = _u(console, "◈", "*")
        logo = Text(f"{diamond}  A P O T R O P E  {diamond}", style="bold blue")
        sub  = Text(f"Windows Security Posture Auditor  {_u(console, '·', '-')}  v{__version__}", style="dim")
        # Build two-line content; Text.append returns self so we can chain
        content = logo.copy()
        content.append("\n")
        content.append(sub)
        console.print(Align.center(Panel(
            Align.center(content),
            border_style="blue",
            padding=(1, 6),
        )))

    def _print_score_panel(self, console, report: AuditReport) -> None:
        """Print the prominent security-score panel."""
        from rich.panel import Panel

        letter, label = score_grade(report.score)
        gc  = _GRADE_COLOR.get(letter, "white")
        bar = _score_bar(
            report.score,
            filled_char=_u(console, "█", "="),
            empty_char=_u(console, "░", "-"),
        )

        ts     = report.scan_timestamp
        ts_str = ts.strftime("%Y-%m-%d %H:%M UTC") if ts.tzinfo else ts.strftime("%Y-%m-%d %H:%M")
        total  = len(report.results)
        errors = sum(1 for r in report.results if r.status == Status.ERROR)

        meta = (
            f"  [dim]Host:[/dim]  [bold]{report.hostname}[/bold]"
            f"   [dim]OS:[/dim] {report.os_version}\n"
            f"  [dim]Scan:[/dim] {ts_str}"
            f"   [dim]Duration:[/dim] {report.scan_duration:.1f}s"
            f"   [dim]Total checks:[/dim] {total}"
        )

        score_line = f"\n  [{gc}]{report.score:>3} / 100    {letter}  {label}[/{gc}]\n"
        bar_line   = f"  [{gc}]{bar}[/{gc}]\n"

        ck = _u(console, "✓", "+")
        xk = _u(console, "✗", "x")
        counts = (
            f"  [green]{ck}  {report.pass_count:>3} passed[/green]"
            f"   [red]{xk}  {report.fail_count:>3} failed[/red]"
            f"   [yellow]!  {report.warn_count:>3} warnings[/yellow]"
        )
        if errors:
            counts += f"   [dim]?  {errors} error(s)[/dim]"

        console.print(Panel(
            meta + score_line + bar_line + counts,
            title="[bold]Security Score[/bold]",
            border_style=gc.replace("bold ", ""),
            padding=(0, 1),
        ))
        console.print()

    def _print_category_panels(self, console, report: AuditReport) -> None:
        """Print one Rich Panel per check category."""
        from rich.panel import Panel

        cat_scores = calculate_category_scores(report.results)
        categories = sorted({r.category for r in report.results})

        for category in categories:
            results    = [r for r in report.results if r.category == category]
            cat_score  = cat_scores.get(category, 100)
            letter, _  = score_grade(cat_score)
            score_color = _GRADE_COLOR.get(letter, "white")

            _icon: dict[Status, str] = {
                Status.PASS:  _u(console, "✓", "+"),
                Status.FAIL:  _u(console, "✗", "x"),
                Status.WARN:  "!",
                Status.INFO:  "i",
                Status.ERROR: "?",
            }
            lines: list[str] = []
            for result in results:
                sc   = _STATUS_COLOR[result.status]
                icon = _icon[result.status]

                # Bold red icon for CRITICAL failures
                if result.status == Status.FAIL and result.severity == Severity.CRITICAL:
                    icon_markup = f"[bold red]{icon}[/bold red]"
                else:
                    icon_markup = f"[{sc}]{icon}[/{sc}]"

                name_markup = f"[{sc}]{result.check_name}[/{sc}]"

                # One-line detail snippet for FAIL/WARN in normal mode
                inline = ""
                if not self.verbose and result.details and result.status in (
                    Status.FAIL, Status.WARN
                ):
                    snippet = result.details.split("\n")[0]
                    for sep in (".", ";", " - ", " -- "):
                        if sep in snippet:
                            snippet = snippet.split(sep)[0]
                            break
                    inline = f"  [dim]{_truncate(snippet, _DETAIL_INLINE_MAX)}[/dim]"

                lines.append(f"  {icon_markup}  {name_markup}{inline}")

                if self.verbose:
                    sev_c = _SEVERITY_COLOR.get(result.severity, "white")
                    lines.append(
                        f"     [dim]Severity:[/dim]  [{sev_c}]{result.severity.value}[/{sev_c}]"
                    )
                    if result.details:
                        wrapped = textwrap.wrap(result.details, 72)
                        lines.append(f"     [dim]Details:[/dim]   {wrapped[0]}")
                        for cont in wrapped[1:]:
                            lines.append(f"               {cont}")
                    if result.remediation:
                        wrapped = textwrap.wrap(result.remediation, 72)
                        lines.append(
                            f"     [dim]Fix:[/dim]       [italic]{wrapped[0]}[/italic]"
                        )
                        for cont in wrapped[1:]:
                            lines.append(f"               [italic]{cont}[/italic]")
                    lines.append("")

            title = (
                f"[bold]{category}[/bold]"
                f"   [{score_color}]{cat_score}/100  {letter}[/{score_color}]"
            )
            console.print(Panel(
                "\n".join(lines),
                title=title,
                border_style="blue",
                padding=(0, 1),
            ))
            console.print()

    def _print_top_issues(self, console, report: AuditReport) -> None:
        """Print the top-N highest-severity findings with remediation guidance."""
        from rich.panel import Panel

        issues = [
            r for r in report.results
            if r.status in (Status.FAIL, Status.WARN) and r.remediation
        ]
        issues.sort(key=lambda r: (
            _SEV_ORDER.get(r.severity, 5),
            0 if r.status == Status.FAIL else 1,
        ))
        top = issues[:_TOP_ISSUES_COUNT]

        if not top:
            return

        lines: list[str] = []
        for i, result in enumerate(top, 1):
            sc  = _STATUS_COLOR[result.status]
            svc = _SEVERITY_COLOR.get(result.severity, "white")

            lines.append(
                f"  [bold]{i}.[/bold]  "
                f"[{sc}]{result.status.value}[/{sc}]"
                f" / [{svc}]{result.severity.value}[/{svc}]"
                f"   [bold]{result.check_name}[/bold]"
            )
            for rline in textwrap.wrap(result.remediation, _REM_WRAP_WIDTH):
                lines.append(f"       [italic dim]{rline}[/italic dim]")

            if i < len(top):
                lines.append("")

        flag = _u(console, "⚑  ", "")
        console.print(Panel(
            "\n".join(lines),
            title=f"[bold red]{flag}Top Issues[/bold red]",
            border_style="red",
            padding=(1, 1),
        ))
        console.print()

    def _print_footer(
        self,
        console,
        report: AuditReport,
        html_path: str | None,
        json_path: str | None,
    ) -> None:
        """Print the scan summary footer."""
        if _console_is_unicode(console):
            from rich.rule import Rule
            console.print(Rule(style="dim"))
        else:
            console.print("[dim]" + "-" * 79 + "[/dim]")
        console.print(
            f"  [dim]Scan completed in[/dim] [bold]{report.scan_duration:.1f}s[/bold]"
        )
        if html_path:
            console.print(
                f"  [dim]HTML report saved to:[/dim] [bold cyan]{html_path}[/bold cyan]"
            )
        if json_path:
            console.print(
                f"  [dim]JSON report saved to:[/dim] [bold cyan]{json_path}[/bold cyan]"
            )
        error_count = report.error_count
        if error_count:
            console.print(
                f"  [yellow]![/yellow]  [yellow bold]{error_count} check(s) could not "
                f"complete.[/yellow bold]  "
                "[dim]Run as Administrator for full results.[/dim]"
            )
        if not report.is_admin:
            console.print(
                "  [dim]Note:[/dim] Some checks were skipped — "
                "[bold]run as Administrator[/bold] for complete results."
            )
        if not self.verbose:
            console.print(
                "  [dim]Tip:[/dim] Run with [bold]--verbose[/bold] "
                "for full details and remediation steps"
            )
        console.print()

    # ── Plain-text fallback ───────────────────────────────────────────────────

    def _print_plain(self, report: AuditReport) -> None:
        """Minimal plain-text output when Rich is unavailable."""
        letter, label = score_grade(report.score)
        print(
            f"Apotrope v{__version__}  |  {report.hostname}"
            f"  |  Score: {report.score}/100 ({letter} {label})"
        )
        print(
            f"PASS: {report.pass_count}"
            f"  FAIL: {report.fail_count}"
            f"  WARN: {report.warn_count}"
        )
        print()
        for r in report.results:
            icon = _STATUS_ICON.get(r.status, "?")
            print(f"[{icon}] [{r.severity.value:8}] {r.category}: {r.check_name}")
            if self.verbose and r.details:
                print(f"       {r.details}")
            if self.verbose and r.remediation:
                print(f"       Fix: {r.remediation}")
