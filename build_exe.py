"""
Apotrope build script — produces a self-contained apotrope.exe via PyInstaller.

Usage:
    python build_exe.py [--no-icon]

The resulting exe is written to dist/apotrope.exe and bundles:
  - All Python dependencies (rich, jinja2, ...)
  - The Jinja2 HTML template (src/apotrope/templates/report.html.j2)
  - The Apotrope brand mark on a dark tile as the Windows app icon (assets/icon.ico)

The exe runs on any Windows 10/11 machine without a Python installation.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
BRAND_MARK = ROOT / "docs" / "apotrope-mark.png"  # official brand eye-mark (512², transparent)
BRAND_MARK_SMALL = ROOT / "assets" / "icon-mark-16.png"  # simplified mark for tiny sizes, from assets/icon-16.svg
BRAND_TOKENS = ROOT / "brand" / "tokens.json"     # single source of truth for brand colors
MARK_GROUND_FALLBACK = (11, 13, 14)               # brand/tokens.json mark.ground #0B0D0E
ICON_SIZES = [256, 128, 64, 48, 32, 16]           # multi-res frames baked into the ICO


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _tile_rgb() -> tuple[int, int, int]:
    """The app-icon tile color = brand token mark.ground (the mark's void ground).

    Read from brand/tokens.json so the icon tile can never drift from the palette.
    Falls back to the documented #0B0D0E if the tokens file is unreadable.
    """
    try:
        import json
        data = json.loads(BRAND_TOKENS.read_text(encoding="utf-8"))
        return _hex_to_rgb(data["mark"]["ground"]["hex"])
    except Exception as exc:  # missing/renamed token -> documented fallback, but say so
        print(f"[build] Could not read mark.ground from {BRAND_TOKENS} ({exc}); "
              f"using fallback {MARK_GROUND_FALLBACK}")
        return MARK_GROUND_FALLBACK


def _ensure_icon() -> Path:
    """Return path to assets/icon.ico, generating it from the brand mark if absent.

    The committed assets/icon.ico is what actually ships: the release CI has no
    Pillow and consumes the committed file verbatim (see release.yml). This
    generator is the local fallback — it composites the Apotrope brand mark
    (docs/apotrope-mark.png) onto a rounded tile colored by the brand token
    mark.ground (brand/tokens.json) and writes a multi-resolution ICO. The vector
    masters live at assets/icon.svg / icon-16.svg. To change the shipped icon,
    regenerate + commit locally.
    """
    icon_path = ROOT / "assets" / "icon.ico"
    if icon_path.exists():
        return icon_path

    icon_path.parent.mkdir(exist_ok=True)
    print("[build] Generating assets/icon.ico from brand mark …")
    try:
        from PIL import Image, ImageDraw  # type: ignore[import]
    except ImportError:
        print("[build] Pillow not installed — skipping icon (exe will use default)")
        return icon_path  # caller checks .exists()

    if not BRAND_MARK.exists():
        print(f"[build] Brand mark not found at {BRAND_MARK} — skipping icon")
        return icon_path  # caller checks .exists()

    mark = Image.open(BRAND_MARK).convert("RGBA")
    # At tiny sizes the intricate mark (thin hexagon + 6 spokes) turns to mush, so
    # the <=24px frame uses the simplified small master (spokes dropped, strokes
    # thickened) rendered from assets/icon-16.svg. Its ~10% padding is baked in.
    mark_small = (Image.open(BRAND_MARK_SMALL).convert("RGBA")
                  if BRAND_MARK_SMALL.exists() else None)
    tile_rgb = _tile_rgb()

    def _make_frame(size: int) -> Image.Image:
        # Render at 4x then downscale so the rounded corners and the mark stay
        # clean at small sizes (there is no vector source to re-export).
        ss = 4
        big = size * ss
        # Rounded tile in the mark.ground token color, opaque inside the corner
        # radius (16%, matching assets/icon.svg's rx) and transparent outside it.
        mask = Image.new("L", (big, big), 0)
        ImageDraw.Draw(mask).rounded_rectangle(
            (0, 0, big - 1, big - 1), radius=int(big * 0.16), fill=255)
        tile = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        tile.paste(Image.new("RGBA", (big, big), tile_rgb + (255,)), (0, 0), mask)
        if size <= 24 and mark_small is not None:
            # Simplified master already carries its padding — paste at full tile.
            m = mark_small.resize((big, big), Image.LANCZOS)
            tile.paste(m, (0, 0), m)
        else:
            # Full mark, centered with ~10% padding, using its own alpha as mask.
            inner = int(big * 0.80)
            m = mark.resize((inner, inner), Image.LANCZOS)
            off = (big - inner) // 2
            tile.paste(m, (off, off), m)
        return tile.resize((size, size), Image.LANCZOS)

    frames = [_make_frame(s) for s in ICON_SIZES]
    frames[0].save(str(icon_path), format="ICO",
                   sizes=[(s, s) for s in ICON_SIZES],
                   append_images=frames[1:])
    print(f"[build] icon.ico written ({icon_path.stat().st_size} bytes)")
    return icon_path


def build(use_icon: bool = True) -> int:
    """Run PyInstaller and return its exit code."""
    print("[build] Starting PyInstaller build …")

    templates_src = ROOT / "src" / "apotrope" / "templates"
    if not templates_src.exists():
        print(f"[build] ERROR: templates/ directory not found at {templates_src}")
        return 1

    entry = ROOT / "src" / "apotrope" / "__main__.py"
    if not entry.exists():
        print(f"[build] ERROR: entry point not found at {entry}")
        return 1

    # Keep PyInstaller's intermediate work dir and generated spec OUT of the repo
    # root: its default workpath is ./build, and a top-level build/ directory
    # shadows the PyPA `build` package when running `python -m build` from the
    # repo root. Nest both under .pyinstaller/ (gitignored) so the root stays clean.
    work_dir = ROOT / ".pyinstaller"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "apotrope",
        "--add-data", f"{templates_src};templates",
        "--paths", str(ROOT / "src"),
        "--collect-submodules", "apotrope.checks",
        "--workpath", str(work_dir),
        "--specpath", str(work_dir),
        "--noconfirm",
        "--clean",
        str(entry),
    ]

    if use_icon:
        icon_path = _ensure_icon()
        if icon_path.exists():
            cmd += ["--icon", str(icon_path)]
        else:
            print("[build] No icon found — building without custom icon")

    # --collect-submodules imports the package in an isolated subprocess that
    # does NOT see --paths; unless apotrope is importable there (installed, or
    # src on PYTHONPATH) it silently collects nothing and the exe ships with
    # zero check modules.
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(ROOT / "src"), env.get("PYTHONPATH")) if p
    )

    print(f"[build] Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=str(ROOT), env=env)

    if result.returncode != 0:
        print(f"\n[build] FAILED (exit {result.returncode})")
        return result.returncode

    exe = ROOT / "dist" / "apotrope.exe"
    size_mb = exe.stat().st_size / 1024 / 1024 if exe.exists() else 0

    # Smoke test: a build where collect_submodules found nothing still exits 0
    # but bundles no checks — fail loudly instead of shipping a useless exe.
    probe = subprocess.run(
        [str(exe), "--dry-run", "--no-color"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120,
    )
    match = re.search(r"\((\d+) module\(s\) would run\)", probe.stdout)
    bundled = int(match.group(1)) if match else 0
    if probe.returncode != 0 or bundled == 0:
        print("\n[build] FAILED — exe bundles no check modules "
              "(--dry-run probe). Is apotrope importable at build time?")
        return 1

    print(f"\n[build] SUCCESS — dist/apotrope.exe ({size_mb:.1f} MB)")
    print(f"[build] Probe: {bundled} check module(s) bundled")
    print("[build] Test with:  dist\\apotrope.exe --version")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Build apotrope.exe via PyInstaller")
    parser.add_argument("--no-icon", action="store_true",
                        help="Skip icon embedding (faster, good for CI)")
    args = parser.parse_args()
    sys.exit(build(use_icon=not args.no_icon))


if __name__ == "__main__":
    main()
