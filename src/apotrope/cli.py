"""CLI entry point for Apotrope.

Parses arguments and dispatches to the scanner and reporter.

Exit codes:
    0  Assessment completed and scored >= 70 (passing posture)
    1  Assessment completed and scored <  70 (failing posture)
    2  Result not trustworthy: invalid arguments, a fatal scan error,
       zero controls evaluated, or one or more checks errored
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
    args: argparse.Namespace,
) -> None:
    """Reject colliding or unwritable output paths *before* the scan runs.

    Every requested output (``--html`` / ``--exec-report`` / ``--json`` /
    ``--baseline``) must resolve to a distinct file, and each target directory
    must be writable — checked up front so a bad path fails fast with a clear
    message (exit 2) instead of a late traceback after a full scan.
    """
    import os
    from pathlib import Path

    named = [
        (flag, path) for flag, path in (
            ("--html", args.html),
            ("--exec-report", args.exec_report),
            ("--json", args.json),
            ("--baseline", args.baseline),
        ) if path
    ]

    # Preserve the original, specific message for the html/exec pair.
    if args.html and args.exec_report and (
        Path(args.html).resolve() == Path(args.exec_report).resolve()
    ):
        parser.error("--html and --exec-report must use different files")

    seen: dict[Path, str] = {}
    for flag, path in named:
        resolved = Path(path).resolve()
        if resolved in seen:
            parser.error(f"{seen[resolved]} and {flag} must use different files")
        seen[resolved] = flag

    for flag, path in named:
        parent = Path(path).resolve().parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            parser.error(
                f"cannot write {flag} to {path}: {parent} is not a writable directory"
            )


def main() -> None:
    """Parse arguments, run the audit, and produce output."""
    parser = build_parser()
    args = parser.parse_args()
    _validate_output_paths(parser, args)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Import here so startup is fast for --version / --help
    from apotrope.scanner import Scanner, known_categories
    from apotrope.reporter import Reporter
    from apotrope.profile import load_profile
    from apotrope.exceptions import ProfileError
    from apotrope.utils import is_admin

    categories: list[str] | None = None
    if args.category is not None:
        requested = [c.strip().lower() for c in args.category.split(",")]
        if any(not tok for tok in requested):
            parser.error("--category contains an empty category name")
        valid = known_categories()
        unknown = sorted({tok for tok in requested if tok not in valid})
        if unknown:
            parser.error(
                f"unknown categor{'y' if len(unknown) == 1 else 'ies'}: "
                f"{', '.join(unknown)}. Valid categories: {', '.join(sorted(valid))}"
            )
        categories = requested

    # Load optional profile (auto-detects apotrope.toml if --profile not given).
    # An explicitly requested profile that is missing/unparseable fails closed.
    try:
        profile = load_profile(getattr(args, "profile", None))
    except ProfileError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(2)

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
    # report's header link is only rendered once it was actually written. Each
    # generate_* returns whether the file was produced, so the footer below
    # reports only the outputs that truly exist — never a file that failed.
    exec_ok = bool(args.exec_report) and reporter.generate_executive_report(
        report, args.exec_report
    )

    html_ok = False
    if args.html:
        exec_href = _exec_href(args.html, args.exec_report) if exec_ok else None
        html_ok = reporter.generate_html_report(report, args.html, exec_href=exec_href)

    json_ok = bool(args.json) and reporter.generate_json_report(report, args.json)

    if args.baseline:
        from apotrope.compare import save_baseline
        save_baseline(report, args.baseline)

    # Terminal output — footer lists only the outputs actually written.
    reporter.print_terminal(
        report,
        html_path=args.html if html_ok else None,
        json_path=args.json if json_ok else None,
        exec_path=args.exec_report if exec_ok else None,
    )

    # Comparison diff display
    if baseline is not None:
        from apotrope.compare import compare_reports
        diff = compare_reports(baseline, report)
        reporter.print_comparison(diff)

    # Exit codes:
    #   2  result cannot be trusted: zero controls evaluated, or >=1 ERROR
    #   1  complete assessment, failing score (< 70)
    #   0  complete assessment, passing score (>= 70)
    # ERROR never changes the score (scoring.py) — it only affects the exit code.
    if report.evaluated_count == 0 or report.error_count:
        sys.exit(2)
    if report.score < 70:
        sys.exit(1)


if __name__ == "__main__":
    main()
