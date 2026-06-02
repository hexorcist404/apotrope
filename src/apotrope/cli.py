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


def main() -> None:
    """Parse arguments, run the audit, and produce output."""
    parser = build_parser()
    args = parser.parse_args()

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

    # Save outputs
    if args.html:
        reporter.generate_html_report(report, args.html)

    if args.json:
        reporter.generate_json_report(report, args.json)

    if args.baseline:
        from apotrope.compare import save_baseline
        save_baseline(report, args.baseline)

    # Terminal output
    reporter.print_terminal(report, html_path=args.html, json_path=args.json)

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
