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
import shutil
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apotrope.scanner import Scanner

from apotrope import __version__
from apotrope.models import AuditReport, CheckResult, Severity, Status
from apotrope.scoring import calculate_category_scores, score_grade

log = logging.getLogger(__name__)

# ── Palette (truecolor hex — identical to the HTML report) ─────────────────────
# Rich emits these as 24-bit ANSI on capable terminals and silently degrades /
# strips them when no_color, NO_COLOR, or a non-tty stdout is detected.

_GREEN  = "#2bff88"   # PASS · A–B grade · rail · done
_CYAN   = "#44e0e6"   # INFO · progress bar
_AMBER  = "#ffb23d"   # WARN · C–D grade · MEDIUM
_RED    = "#ff5147"   # FAIL · F grade · HIGH
_CRIT   = "#ff2d6b"   # CRITICAL severity
_TEXT   = "#c4d6cd"   # default body text
_BRIGHT = "#e8fff2"   # command echo · emphasis
_MUTED  = "#5d776c"   # labels · meta · secondary
_FAINT  = "#2f4138"   # footnotes · CIS tags · "evaluated"
_BAR0   = "#16281f"   # unfilled bar cells

# ── Status / severity display config ──────────────────────────────────────────

_STATUS_HEX: dict[Status, str] = {
    Status.PASS:  _GREEN,
    Status.FAIL:  _RED,
    Status.WARN:  _AMBER,
    Status.INFO:  _CYAN,
    Status.ERROR: _MUTED,
}

_SEVERITY_HEX: dict[Severity, str] = {
    Severity.CRITICAL: _CRIT,
    Severity.HIGH:     _RED,
    Severity.MEDIUM:   _AMBER,
    Severity.LOW:      _MUTED,
    Severity.INFO:     _MUTED,
}

# Compact severity labels so the top-findings column stays width-5.
_SEVERITY_ABBR: dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MED",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}

# Plain-text fallback icons (used only by _print_plain when Rich is absent).
_STATUS_ICON: dict[Status, str] = {
    Status.PASS:  "✓",
    Status.FAIL:  "✗",
    Status.WARN:  "!",
    Status.INFO:  "i",
    Status.ERROR: "?",
}

# Severity sort key for top-findings ranking (CRITICAL first).
_SEV_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

_BAR_CELLS    = 24   # score-panel bar width (spec)
_PROG_CELLS   = 20   # banner progress bar width
_PANEL_WIDTH  = 56   # inner width for right-aligned hostname / grade
_REM_WRAP_WIDTH = 72  # detail / remediation wrap width (un-boxed fallback)
_BOX_W        = 74   # inner content width of a category box (total 78 + 2 indent)
_SEV_COL      = 4    # right-aligned severity column width inside a box


def _grade_hex(score: int) -> str:
    """Grade colour for a 0–100 score (number + badge share it)."""
    if score >= 80:
        return _GREEN   # A, B
    if score >= 60:
        return _AMBER   # C, D
    return _RED         # F


# Colour band shared by the HTML gauge, category bars, and scores.
_band = _grade_hex

# ── HTML report presentation maps (status glyph/colour, severity colour) ──────
# Note: the HTML report colours LOW severity cyan (vs muted in the terminal);
# this mirrors the report spec exactly.

_HTML_STATUS: dict[Status, tuple[str, str]] = {
    Status.PASS:  ("✓", _GREEN),
    Status.FAIL:  ("✗", _RED),
    Status.WARN:  ("!", _AMBER),
    Status.INFO:  ("i", _CYAN),
    Status.ERROR: ("?", _MUTED),
}

_HTML_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: _CRIT,
    Severity.HIGH:     _RED,
    Severity.MEDIUM:   _AMBER,
    Severity.LOW:      _CYAN,
    Severity.INFO:     _MUTED,
}

def _cis_version_for(report: AuditReport) -> str:
    """CIS Benchmark edition to display for *report*.

    Prefers the value the scanner stamped on the report (authoritative — it's
    derived from the same Win10/Win11 detection used to pick the CIS IDs). Falls
    back to parsing the build number out of os_version for reports constructed
    directly (API/tests) without a cis_version.
    """
    import re

    from apotrope import cis_map

    if report.cis_version:
        return report.cis_version
    m = re.search(r"(\d{3,})\s*$", (report.os_version or "").strip())
    build = int(m.group(1)) if m else 0
    # Match scanner.run's test, but treat an unparseable build as current (Win11).
    return cis_map.benchmark_version(is_win10=bool(build) and build < 22000)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _console_is_unicode(console) -> bool:
    """Return True if the console encoding can represent Unicode characters."""
    enc = (getattr(console, "encoding", None) or "utf-8").lower().replace("-", "")
    return "utf" in enc


def _u(console, unicode_char: str, ascii_char: str) -> str:
    """Return *unicode_char* when the console supports it, else *ascii_char*."""
    return unicode_char if _console_is_unicode(console) else ascii_char


def _glyphs(console) -> dict[str, str]:
    """Resolve the glyph set for *console*, falling back to ASCII when needed."""
    if _console_is_unicode(console):
        return {
            "brand": "◈", "rail": "▌", "bar_full": "█", "bar_empty": "░",
            "pass": "✓", "fail": "✗", "warn": "!", "info": "i", "error": "·",
            "flag": "⚑", "arrow": "→", "sep": "·",
            "box_tl": "┌", "box_tr": "┐", "box_bl": "└", "box_br": "┘",
            "box_h": "─", "box_v": "│",
        }
    return {
        "brand": "*", "rail": "|", "bar_full": "#", "bar_empty": "-",
        "pass": "[+]", "fail": "[x]", "warn": "[!]", "info": "[i]", "error": "[.]",
        "flag": "", "arrow": "->", "sep": "-",
        "box_tl": "+", "box_tr": "+", "box_bl": "+", "box_br": "+",
        "box_h": "-", "box_v": "|",
    }


def _text(*segments):
    """Build a Rich Text from (str) or (str, style) segments.

    User-supplied strings (check names, CIS tags) are appended as data, never
    parsed as markup — so a `[` in a check name can't corrupt the line.
    """
    from rich.text import Text

    t = Text()
    for seg in segments:
        if isinstance(seg, tuple):
            chunk, style = seg
            t.append(chunk, style=style)
        else:
            t.append(seg)
    return t


def _truncate(text: str, maxlen: int) -> str:
    return text if len(text) <= maxlen else text[:maxlen - 1] + "~"


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:
    """Formats and outputs Apotrope audit reports.

    Args:
        verbose:  Box every category and show every check (passing ones too).
                  The default view is a triage view: only categories with
                  FAIL/WARN findings, each with its fix and command.
        no_color: Disable Rich color markup (produces plain, no-ANSI output).
        fix:      Deprecated and ignored — fixes are shown by default.
    """

    def __init__(
        self, verbose: bool = False, no_color: bool = False, fix: bool = False
    ) -> None:
        self.verbose = verbose
        self.no_color = no_color
        self.fix = fix  # retained for API compatibility; no longer changes output

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
            from rich.progress import BarColumn, Progress, TextColumn
        except ImportError:
            return scanner.run()

        console = self._make_console()
        g       = _glyphs(console)
        modules = scanner.discover_modules()
        total   = len(modules)

        console.print()
        self._print_banner(console)
        if not scanner.is_admin:
            self._print_non_admin_warning(console)
        console.print()

        # A single inline bar — no spinner, no stacked columns. It tracks module
        # completion live, then is erased and replaced by the static "done" line.
        with Progress(
            TextColumn(f"  [{_MUTED}]scanning controls[/]"),
            BarColumn(bar_width=_PROG_CELLS, style=_BAR0,
                      complete_style=_CYAN, finished_style=_CYAN),
            TextColumn(f"[{_MUTED}]{{task.completed}}/{{task.total}}[/]"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("scan", total=total)

            def _on_module(module) -> None:
                progress.update(task, advance=1)

            report = scanner.run(modules=modules, on_module_start=_on_module)

        # Static completion line (mirrors the site's terminal demo).
        bar = g["bar_full"] * _PROG_CELLS
        console.print(_text(
            "  ",
            (f"scanning {len(report.results)} controls ", _MUTED),
            (f"[{bar}]", _CYAN),
            (f" done {g['sep']} {report.scan_duration:.1f}s", _MUTED),
        ))
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
        # Default = triage view: one box per category with FAIL/WARN findings.
        # --verbose widens the selection: every category, every check.
        # (console.width can come in below the OS-reported size — e.g. Rich
        # reserves a column on legacy Windows consoles — so check both.)
        if min(shutil.get_terminal_size().columns, console.width) < _BOX_W + 6:
            # Console too narrow for 78-column boxes — un-boxed fallback.
            self._print_category_detail(console, report,
                                        only_issues=not self.verbose)
        else:
            self._print_category_boxes(console, report,
                                       only_issues=not self.verbose)
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
        """Build the full Jinja2 template variable dict for the HTML report.

        Everything the report needs is computed here (server-side): per-finding
        presentation, category groupings, the gauge tick ring, the donut arcs,
        and the prioritised top-issues list. The template only loops and prints.
        """
        import math
        import re
        from collections import defaultdict

        letter, label = score_grade(report.score)
        cat_scores = calculate_category_scores(report.results)
        total = len(report.results)

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

        def _slug(name: str) -> str:
            # Mirror the JS: collapse whitespace runs to '-'. Used for ids/anchors.
            return re.sub(r"\s+", "-", name.strip())

        def _finding_view(r: CheckResult) -> dict:
            glyph, scolor = _HTML_STATUS.get(r.status, ("?", _MUTED))
            snippet = ""
            if r.status in (Status.FAIL, Status.WARN) and r.details:
                snippet = r.details.split("\n")[0].split(". ")[0]
            return {
                "status":       r.status.value,
                "status_glyph": glyph,
                "status_color": scolor,
                "severity":     r.severity.value,
                "sev_color":    _HTML_SEVERITY.get(r.severity, _MUTED),
                "category":     r.category,
                "check_name":   r.check_name,
                "description":  r.description,
                "details":      r.details,
                "remediation":  r.remediation,
                "command":      r.command,
                "cis":          r.cis_reference,
                "snippet":      snippet,
            }

        # ── Categories: alphabetical page order; results sorted within ────────
        by_cat: dict[str, list[CheckResult]] = defaultdict(list)
        for r in report.results:
            by_cat[r.category].append(r)

        category_data = []
        for cat_name in sorted(by_cat):
            cat_results = sorted(by_cat[cat_name], key=_sort_key)
            cs = cat_scores.get(cat_name, 100)
            cl, _ = score_grade(cs)
            category_data.append({
                "name":         cat_name,
                "slug":         _slug(cat_name),
                "score":        cs,
                "band":         _band(cs),
                "grade_letter": cl,
                "fail":         sum(1 for r in cat_results if r.status == Status.FAIL),
                "warn":         sum(1 for r in cat_results if r.status == Status.WARN),
                "pass":         sum(1 for r in cat_results if r.status == Status.PASS),
                "info":         sum(1 for r in cat_results if r.status == Status.INFO),
                "findings":     [_finding_view(r) for r in cat_results],
            })

        # Category-score bars: worst score first.
        category_bars = sorted(
            ({"name": c["name"], "slug": c["slug"],
              "score": c["score"], "band": c["band"]} for c in category_data),
            key=lambda c: c["score"],
        )

        # ── Top issues: FAIL/WARN with remediation, CRITICAL/HIGH or any FAIL ─
        candidates = [
            r for r in report.results
            if r.status in (Status.FAIL, Status.WARN) and r.remediation
            and (r.severity in (Severity.CRITICAL, Severity.HIGH)
                 or r.status == Status.FAIL)
        ]
        candidates.sort(key=lambda r: (_sev_ord.get(r.severity, 5),
                                       0 if r.status == Status.FAIL else 1))
        top_issues = [
            {
                "num":           f"{i + 1:02d}",
                "severity":      r.severity.value,
                "sev_color":     _HTML_SEVERITY.get(r.severity, _MUTED),
                "status":        r.status.value,
                "status_color":  _HTML_STATUS.get(r.status, ("", _MUTED))[1],
                "category":      r.category,
                "category_slug": _slug(r.category),
                "check_name":    r.check_name,
                "remediation":   r.remediation,
            }
            for i, r in enumerate(candidates[:5])
        ]

        # ── Score gauge: 40-tick ring + arc dash offset ───────────────────────
        band = _band(report.score)
        gauge_ticks = []
        for i in range(40):
            on  = (i / 40) <= (report.score / 100)
            ang = math.radians(-90 + i * 9)
            gauge_ticks.append({
                "x1": round(115 + 103 * math.cos(ang), 2),
                "y1": round(115 + 103 * math.sin(ang), 2),
                "x2": round(115 + 112 * math.cos(ang), 2),
                "y2": round(115 + 112 * math.sin(ang), 2),
                "color":   band if on else "#16241d",
                "opacity": 0.9 if on else 0.5,
            })
        gauge_dashoffset = round(603.2 * (1 - report.score / 100), 2)

        # ── Result-distribution donut (r=52, C≈326.7) ─────────────────────────
        circ = 2 * math.pi * 52
        donut, accum = [], 0.0
        for st, color in ((Status.PASS, _GREEN), (Status.FAIL, _RED),
                          (Status.WARN, _AMBER), (Status.INFO, _CYAN)):
            cnt = sum(1 for r in report.results if r.status == st)
            seg = (cnt / total * circ) if total else 0.0
            donut.append({
                "color":  color,
                "dash":   round(seg, 2),
                "gap":    round(circ - seg, 2),
                "offset": round(-accum, 2),
            })
            accum += seg

        ts = report.scan_timestamp
        generated_at = (
            ts.strftime("%Y-%m-%d %H:%M UTC") if ts.tzinfo
            else ts.strftime("%Y-%m-%d %H:%M")
        )

        return {
            "report":             report,
            "version":            __version__,
            "hostname":           report.hostname,
            "os_version":         report.os_version,
            "scan_timestamp":     generated_at,
            "scan_duration":      f"{report.scan_duration:.1f}",
            "score":              report.score,
            "grade_letter":       letter,
            "grade_label":        label,
            "band_color":         band,
            "total_checks":       total,
            "pass_count":         report.pass_count,
            "fail_count":         report.fail_count,
            "warn_count":         report.warn_count,
            "info_count":         sum(1 for r in report.results if r.status == Status.INFO),
            "error_count":        report.error_count,
            "exec_summary_html":  self._build_executive_summary_html(report),
            "gauge_ticks":        gauge_ticks,
            "gauge_dashoffset":   gauge_dashoffset,
            "donut":              donut,
            "donut_center":       report.fail_count,
            "category_data":      category_data,
            "category_bars":      category_bars,
            "n_cats":             len(category_data),
            "top_issues":         top_issues,
            "cis_version":        _cis_version_for(report),
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

    def _build_executive_summary_html(self, report: AuditReport):
        """Executive summary as escaped HTML with semantic highlight spans.

        Same narrative as :meth:`_build_executive_summary`, but emits `<b>` for
        host/grade/areas and `.hl-crit` / `.hl-high` / `.hl-ok` spans. All
        scan-derived text (the hostname) is HTML-escaped; the markup is ours.
        """
        from collections import Counter

        from markupsafe import Markup, escape

        letter, label = score_grade(report.score)
        total = len(report.results)
        host  = escape(report.hostname)

        critical_fails = sum(
            1 for r in report.results
            if r.status == Status.FAIL and r.severity == Severity.CRITICAL
        )
        high_fails = sum(
            1 for r in report.results
            if r.status == Status.FAIL and r.severity == Severity.HIGH
        )
        issue_cats = Counter(
            r.category for r in report.results
            if r.status in (Status.FAIL, Status.WARN)
        )

        parts: list[str] = [
            f"The security posture of <b>{host}</b> has been assessed as "
            f"<b>{label}</b> with an overall score of "
            f"<b>{report.score}/100 ({letter})</b> across {total} security checks."
        ]

        if report.fail_count == 0 and report.warn_count == 0:
            parts.append(
                '<span class="hl-ok">All checks passed with no failures or '
                "warnings detected — the system is configured in line with "
                "Windows security best practices.</span>"
            )
            return Markup(" ".join(parts))

        if critical_fails > 0:
            noun = "finding" if critical_fails == 1 else "findings"
            verb = "requires" if critical_fails == 1 else "require"
            parts.append(
                f'<span class="hl-crit">{critical_fails} critical {noun} '
                f"{verb} immediate remediation.</span>"
            )
        elif high_fails > 0:
            noun = "finding" if high_fails == 1 else "findings"
            parts.append(
                f'<span class="hl-high">{high_fails} high-severity {noun} '
                "should be addressed promptly.</span>"
            )

        detail_parts: list[str] = []
        if report.fail_count > 0:
            n = report.fail_count
            detail_parts.append(f"{n} check{'s' if n != 1 else ''} failed")
        if report.warn_count > 0:
            n = report.warn_count
            detail_parts.append(f"{n} check{'s' if n != 1 else ''} issued warnings")
        if detail_parts:
            parts.append(f"Of the checks performed, {' and '.join(detail_parts)}.")

        if issue_cats:
            top_cats = [escape(cat) for cat, _ in issue_cats.most_common(3)]
            if len(top_cats) == 1:
                parts.append(f"The primary area of concern is <b>{top_cats[0]}</b>.")
            else:
                joined = (", ".join(f"<b>{c}</b>" for c in top_cats[:-1])
                          + f" and <b>{top_cats[-1]}</b>")
                parts.append(f"The primary areas of concern are {joined}.")

        parts.append(
            "Remediation should be prioritized by severity, "
            "addressing critical and high-severity findings first."
        )

        if report.error_count:
            n = report.error_count
            parts.append(
                f"Note: {n} check{'s' if n != 1 else ''} could not complete "
                "— run as Administrator for full results."
            )

        return Markup(" ".join(parts))

    def _make_console(self):
        import sys

        from rich.console import Console

        # Check data (details/remediation) may contain characters a non-UTF-8
        # console (e.g. cp1252) cannot encode; degrade them to '?' rather than
        # letting the report crash mid-render.
        try:
            enc = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
            if "utf" not in enc.replace("-", ""):
                sys.stdout.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
        return Console(no_color=self.no_color, highlight=False)

    def _print_non_admin_warning(self, console) -> None:
        """Note (no box) that the scan is running without elevation."""
        g = _glyphs(console)
        console.print(_text(
            "  ",
            (f"{g['warn']} running without administrator privileges", _AMBER),
        ))
        console.print(_text(
            "    ",
            ("some checks (BitLocker, SMB) will be skipped — "
             "run elevated for a full audit", _MUTED),
        ))

    def _print_banner(self, console) -> None:
        """Print the Apotrope wordmark — two lines, no frame."""
        g = _glyphs(console)
        console.print(_text(
            "  ",
            (f"{g['brand']} APOTROPE", f"bold {_GREEN}"),
            (f"  v{__version__}", _MUTED),
        ))
        console.print(_text(
            "  ",
            ("Windows Security Posture Auditor", _MUTED),
        ))

    def _rail(self, console, body) -> None:
        """Print *body* (a Rich Text) prefixed by the green ▌ accent rail."""
        g = _glyphs(console)
        line = _text("  ", (g["rail"] + " ", _GREEN))
        line.append_text(body)
        console.print(line)

    def _print_score_panel(self, console, report: AuditReport) -> None:
        """Print the security-score block, accented by the ▌ rail."""
        g = _glyphs(console)
        letter, label = score_grade(report.score)
        gc = _grade_hex(report.score)

        total      = len(report.results)
        info_count = sum(1 for r in report.results if r.status == Status.INFO)

        # Header: SECURITY SCORE .......... HOSTNAME (right-aligned)
        host = report.hostname
        pad  = max(2, _PANEL_WIDTH - len("SECURITY SCORE") - len(host))
        self._rail(console, _text(
            ("SECURITY SCORE", f"bold {_GREEN}"),
            (" " * pad, None),
            (host, _MUTED),
        ))
        self._rail(console, _text((report.os_version, _MUTED)))
        self._rail(console, _text(" "))

        # Score number + grade badge (share the grade colour).
        self._rail(console, _text(
            (f"{report.score} / 100", f"bold {gc}"),
            ("   ", None),
            (f"{letter} {g['sep']} {label.upper()}", gc),
        ))

        # Score bar: 24 cells, filled in grade colour, empty in bar0.
        filled = round(report.score / 100 * _BAR_CELLS)
        self._rail(console, _text(
            (g["bar_full"] * filled, gc),
            (g["bar_empty"] * (_BAR_CELLS - filled), _BAR0),
        ))
        self._rail(console, _text(" "))

        # Distribution — each count in its status colour.
        dist = _text(
            (f"{g['pass']} {report.pass_count} pass", _GREEN),
            ("   ", None),
            (f"{g['fail']} {report.fail_count} fail", _RED),
            ("   ", None),
            (f"{g['warn']} {report.warn_count} warn", _AMBER),
            ("   ", None),
            (f"{g['info']} {info_count} info", _CYAN),
        )
        if report.error_count:
            dist.append(f"   {g['sep']} {report.error_count} error", style=_MUTED)
        self._rail(console, dist)
        self._rail(console, _text((f"{total} checks evaluated", _FAINT)))
        console.print()

    # ── Category boxes (default triage view and --verbose) ───────────────────

    @staticmethod
    def _issue_sort_key(r: CheckResult) -> tuple[int, int]:
        """FAIL before WARN, then severity CRITICAL→LOW."""
        return (0 if r.status == Status.FAIL else 1,
                _SEV_ORDER.get(r.severity, 5))

    def _box_row(self, console, g, segs=()) -> None:
        """Print one box content line: `  │ <segs padded to _BOX_W> │`."""
        pad = _BOX_W - sum(len(s[0]) if isinstance(s, tuple) else len(s)
                           for s in segs)
        line = _text("  ", (g["box_v"] + " ", _FAINT))
        if segs:
            line.append_text(_text(*segs))
        line.append(" " * max(0, pad))
        line.append(" " + g["box_v"], style=_FAINT)
        console.print(line)

    def _print_box_top(self, console, g, name: str, score: int) -> None:
        """Centered box header: `┌──── NAME  score/100 G ────┐`."""
        letter, _ = score_grade(score)
        gc    = _grade_hex(score)
        label = name.upper()
        badge = f"{score}/100 {letter}"
        content_len = 1 + len(label) + 2 + len(badge) + 1
        dashes_left  = (_BOX_W + 2 - content_len) // 2
        dashes_right = _BOX_W + 2 - content_len - dashes_left
        console.print(_text(
            "  ",
            (g["box_tl"] + g["box_h"] * dashes_left, _FAINT),
            " ",
            (label, f"bold {_BRIGHT}"),
            "  ",
            (badge, gc),
            " ",
            (g["box_h"] * dashes_right + g["box_tr"], _FAINT),
        ))

    def _print_box_bottom(self, console, g) -> None:
        console.print(_text(
            "  ", (g["box_bl"] + g["box_h"] * (_BOX_W + 2) + g["box_br"], _FAINT),
        ))

    def _print_box_check(self, console, g, r: CheckResult) -> None:
        """One check inside a box: name row, details, then fix/run if actionable."""
        glyph_for = {
            Status.PASS: g["pass"], Status.FAIL: g["fail"], Status.WARN: g["warn"],
            Status.INFO: g["info"], Status.ERROR: g["error"],
        }
        actionable = r.status in (Status.FAIL, Status.WARN)
        glyph = glyph_for.get(r.status, "?")
        sev   = _SEVERITY_ABBR.get(r.severity, "?").rjust(_SEV_COL)
        name_hex = {Status.FAIL: _RED, Status.WARN: _AMBER}.get(r.status, _TEXT)
        sev_hex  = _SEVERITY_HEX.get(r.severity, _TEXT) if actionable else _FAINT
        name = _truncate(r.check_name,
                         _BOX_W - len(glyph) - 1 - _SEV_COL - 2)
        gap = _BOX_W - len(glyph) - 1 - len(name) - _SEV_COL
        self._box_row(console, g, [
            (glyph, _STATUS_HEX.get(r.status, _MUTED)),
            " ",
            (name, name_hex),
            " " * gap,
            (sev, sev_hex),
        ])
        if r.details:
            body_hex = _TEXT if actionable else _MUTED
            for ln in textwrap.wrap(r.details, _BOX_W - 4):
                self._box_row(console, g, [("    " + ln, body_hex)])
        if actionable and r.remediation:
            for i, ln in enumerate(textwrap.wrap(r.remediation, _BOX_W - 9)):
                self._box_row(console, g,
                              [("    ", ""), ("fix", _MUTED), ("  ", ""), (ln, _TEXT)]
                              if i == 0 else [(" " * 9 + ln, _TEXT)])
        if actionable and r.command:
            first = True
            for stmt in r.command.split("\n"):
                # Wrap at spaces only — never inside a command token like
                # Select-String (textwrap breaks on hyphens by default).
                for ln in textwrap.wrap(stmt, _BOX_W - 9,
                                        break_on_hyphens=False) or [""]:
                    self._box_row(console, g,
                                  [("    ", ""), ("run", _MUTED), ("  ", ""), (ln, _GREEN)]
                                  if first else [(" " * 9 + ln, _GREEN)])
                    first = False

    def _print_category_box(
        self, console, g, name: str, score: int, results: list[CheckResult]
    ) -> None:
        """One category box: centered header, checks separated by blank rail rows."""
        self._print_box_top(console, g, name, score)
        for i, r in enumerate(results):
            if i:
                self._box_row(console, g)
            self._print_box_check(console, g, r)
        self._print_box_bottom(console, g)
        console.print()

    def _print_category_boxes(
        self, console, report: AuditReport, only_issues: bool
    ) -> None:
        """Boxed per-category view.

        only_issues=True (the default run) boxes only categories with FAIL/WARN
        findings — and only those findings — worst category score first.
        only_issues=False (--verbose) boxes every category alphabetically with
        every check.
        """
        from collections import defaultdict

        g = _glyphs(console)
        cat_scores = calculate_category_scores(report.results)
        by_cat: dict[str, list[CheckResult]] = defaultdict(list)
        for r in report.results:
            by_cat[r.category].append(r)

        if only_issues:
            selected = []
            for cat, results in by_cat.items():
                issues = sorted(
                    (r for r in results
                     if r.status in (Status.FAIL, Status.WARN)),
                    key=self._issue_sort_key,
                )
                if issues:
                    selected.append((cat, issues))
            # Worst category first; alphabetical tie-break.
            selected.sort(key=lambda c: (cat_scores.get(c[0], 100), c[0]))
        else:
            selected = [(cat, by_cat[cat]) for cat in sorted(by_cat)]

        for cat, results in selected:
            self._print_category_box(
                console, g, cat, cat_scores.get(cat, 100), results,
            )

    def _print_category_detail(
        self, console, report: AuditReport, only_issues: bool = False
    ) -> None:
        """Un-boxed per-category view for consoles too narrow for the boxes.

        Same selection rules as the boxed view: only_issues=True restricts to
        categories (and checks) with FAIL/WARN findings, worst category first.
        """
        g = _glyphs(console)
        glyph_for = {
            Status.PASS:  g["pass"],  Status.FAIL: g["fail"], Status.WARN: g["warn"],
            Status.INFO:  g["info"],  Status.ERROR: g["error"],
        }
        cat_scores = calculate_category_scores(report.results)

        categories = sorted({r.category for r in report.results})
        if only_issues:
            categories = [
                c for c in categories
                if any(r.category == c and r.status in (Status.FAIL, Status.WARN)
                       for r in report.results)
            ]
            categories.sort(key=lambda c: (cat_scores.get(c, 100), c))

        for category in categories:
            results = [r for r in report.results if r.category == category]
            if only_issues:
                results = sorted(
                    (r for r in results
                     if r.status in (Status.FAIL, Status.WARN)),
                    key=self._issue_sort_key,
                )
            cat_score = cat_scores.get(category, 100)
            letter, _ = score_grade(cat_score)
            gc        = _grade_hex(cat_score)

            badge = f"{cat_score}/100  {letter}"
            pad   = max(2, _PANEL_WIDTH - len(category) - len(badge))
            self._rail(console, _text(
                (category, f"bold {_GREEN}"),
                (" " * pad, None),
                (badge, gc),
            ))

            for r in results:
                sc = _STATUS_HEX[r.status]
                # CRITICAL failures get the critical-pink glyph.
                glyph_color = (
                    _CRIT if (r.status == Status.FAIL
                              and r.severity == Severity.CRITICAL)
                    else sc
                )
                line = _text(
                    "  ",
                    (glyph_for[r.status] + " ", glyph_color),
                    (r.check_name, sc),
                )
                if r.cis_reference:
                    line.append("  " + r.cis_reference, style=_FAINT)
                console.print(line)

                sev_c = _SEVERITY_HEX.get(r.severity, _TEXT)
                console.print(_text(
                    "       ", ("severity  ", _MUTED), (r.severity.value, sev_c),
                ))
                if r.details:
                    for i, ln in enumerate(textwrap.wrap(r.details, _REM_WRAP_WIDTH)):
                        label = "details   " if i == 0 else "          "
                        console.print(_text("       ", (label, _MUTED), (ln, _TEXT)))
                if r.remediation:
                    for i, ln in enumerate(textwrap.wrap(r.remediation, _REM_WRAP_WIDTH)):
                        label = "fix       " if i == 0 else "          "
                        console.print(_text("       ", (label, _MUTED), (ln, _TEXT)))
                if r.command:
                    # Verbatim (un-wrapped) so each line stays copy-paste-valid.
                    for i, ln in enumerate(r.command.split("\n")):
                        label = "run       " if i == 0 else "          "
                        console.print(_text("       ", (label, _MUTED), (ln, _GREEN)))
                console.print()
            console.print()

    def _print_footer(
        self,
        console,
        report: AuditReport,
        html_path: str | None,
        json_path: str | None,
    ) -> None:
        """Print the single-arrow summary footer (plus any caveats, muted)."""
        g = _glyphs(console)
        issues = report.fail_count + report.warn_count
        plural = "s" if issues != 1 else ""

        if html_path:
            tail = (f" {g['sep']} open to triage all {issues} issue{plural}"
                    if issues else f" {g['sep']} clean — no issues to triage")
            console.print(_text(
                "  ",
                (f"{g['arrow']} {html_path} written", _GREEN),
                (tail, _MUTED),
            ))
        else:
            head = (f"{g['arrow']} {issues} issue{plural} to triage" if issues
                    else f"{g['arrow']} no issues to triage")
            tail = f" {g['sep']} --html report.html for the full report"
            if not self.verbose and issues:
                tail += f" {g['sep']} --verbose for per-check detail"
            console.print(_text("  ", (head, _GREEN), (tail, _MUTED)))

        if json_path:
            console.print(_text("  ", (f"{g['sep']} {json_path} written", _MUTED)))
        if report.error_count:
            n = report.error_count
            console.print(_text(
                "  ",
                (f"{n} check{'s' if n != 1 else ''} could not complete", _AMBER),
                (" — run as Administrator for full results", _MUTED),
            ))
        if not report.is_admin:
            console.print(_text(
                "  ",
                ("note: some checks skipped — run as Administrator for complete results",
                 _MUTED),
            ))
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
            # Fixes are shown by default for actionable findings; --verbose
            # additionally shows detail for passing checks.
            show = self.verbose or r.status in (Status.FAIL, Status.WARN)
            if show and r.details:
                print(f"       {r.details}")
            if show and r.remediation:
                print(f"       Fix: {r.remediation}")
            if show and r.command:
                for ln in r.command.split("\n"):
                    print(f"       {ln}")
