"""CLI entry point for Apotrope.

Parses arguments and dispatches to the scanner and reporter.

Exit codes:
    0  Score >= 70 (passing) and no fatal scan errors
    1  Score <  70 (failing security posture)
    2  Fatal scan error (unhandled exception from the scanner)
"""

from __future__ import annotations

import argparse
import logging
import sys

from apotrope import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="apotrope",
        description="Apotrope — Windows Security Posture Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  apotrope                             Full audit, terminal output\n"
            "  apotrope --html report.html          Also save HTML report\n"
            "  apotrope --html r.html --exec-report brief.html\n"
            "                                       Technical + executive reports\n"
            "  apotrope --json report.json          Also save JSON report\n"
            "  apotrope --baseline b.json           Save scan as a baseline\n"
            "  apotrope --compare  b.json           Compare scan against baseline\n"
            "  apotrope --profile  custom.toml      Apply a custom check profile\n"
            "  apotrope --category firewall,encryption  Specific categories only\n"
            "  apotrope --dry-run                   List checks without running\n"
            "  apotrope --verbose                   Show details for every check\n"
            "\n"
            "NOTICE: Apotrope is a READ-ONLY tool for AUTHORISED auditing only.\n"
            "It makes no changes to the system.  Do not run on systems you do\n"
            "not own or have explicit written permission to audit.\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save an HTML report to FILE",
    )
    parser.add_argument(
        "--exec-report",
        metavar="FILE",
        help=(
            "Save a plain-English executive report "
            "(Security Posture Assessment) to FILE"
        ),
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save a JSON report to FILE",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Save current scan as a JSON baseline to FILE for future comparisons",
    )
    parser.add_argument(
        "--compare",
        metavar="FILE",
        help="Compare current scan against a previously saved baseline JSON file",
    )
    parser.add_argument(
        "--profile",
        metavar="FILE",
        help=(
            "Load a custom check profile from a TOML file.  "
            "Auto-detected from apotrope.toml in the current directory if omitted."
        ),
    )
    parser.add_argument(
        "--category",
        metavar="CATEGORIES",
        help="Comma-separated list of categories to run (default: all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List check modules that would run without executing them, then exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output for every check",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        # Retired: fixes are shown by default in the triage view. Kept as a
        # hidden no-op so existing scripts don't error. Do not repurpose the
        # name — a future auto-remediation flag should be e.g. --remediate.
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable Rich color formatting",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Internal logging verbosity (default: WARNING)",
    )
    return parser


def _exec_href(html_path: str, exec_path: str) -> str:
    """Href from the technical report to the executive report.

    Relative when both live on the same drive (portable — the pair can be
    moved or shared together); a ``file://`` URI when a Windows cross-drive
    relpath is impossible. Percent-encoded either way.
    """
    import os
    import urllib.parse
    from pathlib import Path

    try:
        rel = os.path.relpath(
            os.path.abspath(exec_path),
            os.path.dirname(os.path.abspath(html_path)) or ".",
        )
    except ValueError:  # different drives on Windows
        return Path(exec_path).resolve().as_uri()
    return urllib.parse.quote(rel.replace(os.sep, "/"), safe="/")


def _validate_output_paths(
    parser: argparse.ArgumentParser,
    html_path: str | None,
    exec_path: str | None,
) -> None:
    """Reject technical and executive reports that resolve to one file."""
    if not html_path or not exec_path:
        return
    from pathlib import Path

    if Path(html_path).resolve() == Path(exec_path).resolve():
        parser.error("--html and --exec-report must use different files")


def main() -> None:
    """Parse arguments, run the audit, and produce output."""
    parser = build_parser()
    args = parser.parse_args()
    _validate_output_paths(parser, args.html, args.exec_report)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Import here so startup is fast for --version / --help
    from apotrope.scanner import Scanner
    from apotrope.reporter import Reporter
    from apotrope.profile import load_profile
    from apotrope.utils import is_admin

    categories: list[str] | None = None
    if args.category:
        categories = [c.strip().lower() for c in args.category.split(",")]

    # Load optional profile (auto-detects apotrope.toml if --profile not given)
    profile = load_profile(getattr(args, "profile", None))

    admin    = is_admin()
    scanner  = Scanner(categories=categories, is_admin=admin, profile=profile)
    reporter = Reporter(verbose=args.verbose, no_color=args.no_color)

    if args.fix:
        # Retired flag — fixes print by default now.
        notice = "--fix is no longer needed — fixes are shown by default"
        try:
            from rich.console import Console
            Console(no_color=args.no_color, highlight=False).print(
                f"  [#5d776c]{notice}[/]"
            )
        except ImportError:
            print(f"  {notice}")

    # --dry-run: list modules and exit without scanning
    if args.dry_run:
        module_names = scanner.dry_run()
        print(f"Apotrope {__version__} — dry run ({len(module_names)} module(s) would run)\n")
        for name in module_names:
            print(f"  {name}")
        return

    # Load baseline for comparison mode
    baseline = None
    if args.compare:
        from apotrope.compare import load_baseline
        try:
            baseline = load_baseline(args.compare)
        except (FileNotFoundError, ValueError) as exc:
            print(f"[ERROR] Cannot load baseline: {exc}", file=sys.stderr)
            sys.exit(2)

    # Run scan — exit 2 on fatal scanner error
    try:
        report = reporter.run_with_progress(scanner)
    except Exception as exc:
        _log = logging.getLogger(__name__)
        _log.critical("Fatal scan error: %s", exc, exc_info=True)
        print(f"\n[FATAL] Scan could not complete: {exc}", file=sys.stderr)
        sys.exit(2)

    # Save outputs. The executive report is generated first so the technical
    # report's header link is only rendered once the target actually exists
    # (generation is a no-op when Jinja2 or the template is unavailable).
    if args.exec_report:
        reporter.generate_executive_report(report, args.exec_report)

    if args.html:
        exec_href = None
        if args.exec_report:
            from pathlib import Path
            if Path(args.exec_report).exists():
                exec_href = _exec_href(args.html, args.exec_report)
        reporter.generate_html_report(report, args.html, exec_href=exec_href)

    if args.json:
        reporter.generate_json_report(report, args.json)

    if args.baseline:
        from apotrope.compare import save_baseline
        save_baseline(report, args.baseline)

    # Terminal output
    reporter.print_terminal(report, html_path=args.html, json_path=args.json,
                            exec_path=args.exec_report)

    # Comparison diff display
    if baseline is not None:
        from apotrope.compare import compare_reports
        diff = compare_reports(baseline, report)
        reporter.print_comparison(diff)

    # Exit codes: 0 = score >= 70, 1 = score < 70, 2 = fatal error (handled above)
    if report.score < 70:
        sys.exit(1)


if __name__ == "__main__":
    main()
