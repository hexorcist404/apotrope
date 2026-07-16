"""Generate README terminal screenshots (HTML stage; PNG via headless browser).

Runs real scans, sanitizes identifying details (hostname, username), renders
the terminal output through a recording Rich console, and exports truecolor
HTML framed like the design mock (reference/terminal-mock.html). Screenshot
the .term element of each output HTML at 2x device pixel ratio (headless
browser) to produce assets/screenshots/Ap-scan-*.png. Dev tool — not part of
the package.

Usage:  python gen_screenshots.py <outdir>
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest import mock

from rich.console import Console
from rich.terminal_theme import TerminalTheme

from apotrope.models import Status
from apotrope.reporter import Reporter, _text, _MUTED, _CYAN, _BRIGHT
from apotrope.scanner import Scanner
from apotrope.utils import is_admin

HOSTNAME = "WORKSTATION-07"
USERNAME = "jsmith"
PROMPT = r"C:\Users\jsmith\Downloads>"

# Mock palette: page #0a0d0b, terminal panel #03060a, default text #c4d6cd.
THEME = TerminalTheme(
    (3, 6, 10), (196, 214, 205),
    [(3, 6, 10), (255, 81, 71), (43, 255, 136), (255, 178, 61),
     (68, 224, 230), (255, 45, 107), (68, 224, 230), (196, 214, 205)],
    [(93, 119, 108), (255, 81, 71), (43, 255, 136), (255, 178, 61),
     (68, 224, 230), (255, 45, 107), (68, 224, 230), (232, 255, 242)],
)

CODE_FORMAT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body {{ background:#0a0d0b; margin:0; padding:36px 24px; display:flex; justify-content:center; }}
  .term {{ background:#03060a; border:1px solid #16281f; border-radius:6px; padding:26px 30px;
           box-shadow:0 18px 60px rgba(0,0,0,0.55); display:inline-block; }}
  pre {{ font-family:"Cascadia Code","IBM Plex Mono",Consolas,monospace; font-size:13.5px;
         line-height:1.5; margin:0; color:#c4d6cd; }}
</style>
</head>
<body><div class="term"><pre><code>{code}</code></pre></div></body>
</html>
"""


def sanitize(report):
    """Strip machine-identifying data; present the recommended (admin) run."""
    report.hostname = HOSTNAME
    report.results = [r for r in report.results if r.status is not Status.ERROR]
    for r in report.results:
        for field in ("details", "remediation", "command"):
            value = getattr(r, field)
            if value:
                setattr(r, field, value.replace("rsmit", USERNAME))
    report.is_admin = True
    return report


def capture(args_label: str, report, verbose: bool) -> str:
    console = Console(
        file=io.StringIO(), record=True, width=100,
        force_terminal=True, color_system="truecolor", legacy_windows=False,
    )
    reporter = Reporter(verbose=verbose)
    # Prompt + banner + static scan line, mirroring run_with_progress.
    console.print(_text((PROMPT, _MUTED), (f"apotrope.exe{args_label}", _BRIGHT)))
    console.print()
    reporter._print_banner(console)
    console.print()
    console.print(_text(
        "  ",
        (f"scanning {len(report.results)} controls ", _MUTED),
        (f"[{'█' * 20}]", _CYAN),
        (f" done · {report.scan_duration:.1f}s", _MUTED),
    ))
    console.print()
    with mock.patch.object(Reporter, "_make_console", return_value=console):
        reporter.print_terminal(report)
    return console.export_html(theme=THEME, inline_styles=True,
                               code_format=CODE_FORMAT)


def main() -> None:
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)

    admin = is_admin()
    print(f"running as admin: {admin}", flush=True)

    print("scan 1/2: full audit (default view)...", flush=True)
    full = sanitize(Scanner(categories=None, is_admin=admin).run())
    (outdir / "overview.html").write_text(
        capture("", full, verbose=False), encoding="utf-8")

    print("scan 2/2: access control+accounts+encryption (--verbose)...", flush=True)
    scoped = sanitize(
        Scanner(categories=["access control", "accounts", "encryption"],
                is_admin=admin).run())
    (outdir / "verbose.html").write_text(
        capture(" --verbose", scoped, verbose=True), encoding="utf-8")

    print(f"done -> {outdir}")


if __name__ == "__main__":
    main()
