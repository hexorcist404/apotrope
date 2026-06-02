"""
Apotrope build script — produces a self-contained apotrope.exe via PyInstaller.

Usage:
    python build.py [--no-icon]

The resulting exe is written to dist/apotrope.exe and bundles:
  - All Python dependencies (rich, jinja2, psutil, ...)
  - The Jinja2 HTML template (templates/report.html.j2)
  - A Windows shield application icon (assets/icon.ico)

The exe runs on any Windows 10/11 machine without a Python installation.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def _ensure_icon() -> Path:
    """Return path to icon.ico, generating it with Pillow if absent."""
    icon_path = ROOT / "assets" / "icon.ico"
    if icon_path.exists():
        return icon_path

    icon_path.parent.mkdir(exist_ok=True)
    print("[build] Generating assets/icon.ico …")
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore[import]
    except ImportError:
        print("[build] Pillow not installed — skipping icon (exe will use default)")
        return icon_path  # caller checks .exists()

    def _draw_shield(draw, x0, y0, x1, y1, fill, outline=None, lw=0):
        w, h = x1 - x0, y1 - y0
        split = y0 + int(h * 0.62)
        pts = [(x0, y0), (x1, y0), (x1, split), (x0 + w // 2, y1), (x0, split)]
        draw.polygon(pts, fill=fill)
        if outline and lw:
            draw.line(pts + [pts[0]], fill=outline, width=lw)

    def _make_frame(size: int) -> Image.Image:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        pad = max(2, size // 10)
        steps = max(4, size // 16)
        # Shadow
        off = max(1, size // 32)
        _draw_shield(draw, pad + off, pad + off, size - pad + off,
                     size - pad // 2 + off, fill=(10, 30, 60, 120))
        # Gradient fill (concentric layers)
        for i in range(steps, 0, -1):
            t = i / steps
            shrink = (steps - i) * (pad / steps)
            r = int(10 + (0 - 10) * (1 - t))
            g = int(60 + (100 - 60) * (1 - t))
            b = int(140 + (200 - 140) * (1 - t))
            _draw_shield(draw,
                         pad + shrink, pad + shrink,
                         size - pad - shrink, size - pad // 2 - shrink,
                         fill=(r, g, b, 255))
        # Highlight outline
        _draw_shield(draw, pad, pad, size - pad, size - pad // 2,
                     fill=None, outline=(100, 180, 255, 200), lw=max(1, size // 32))
        # "W" label
        cx, cy = size // 2, int(size * 0.40)
        font_size = max(8, int(size * 0.38))
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()
        for dx, dy in [(1, 1), (0, 0)]:
            colour = (20, 40, 80, 200) if (dx, dy) == (1, 1) else (255, 255, 255, 255)
            bb = draw.textbbox((0, 0), "W", font=font)
            tw, th = bb[2] - bb[0], bb[3] - bb[1]
            draw.text((cx - tw // 2 + dx, cy - th // 2 + dy), "W",
                      font=font, fill=colour)
        return img

    sizes = [256, 64, 48, 32, 16]
    frames = [_make_frame(s) for s in sizes]
    frames[0].save(str(icon_path), format="ICO",
                   sizes=[(s, s) for s in sizes],
                   append_images=frames[1:])
    print(f"[build] icon.ico written ({icon_path.stat().st_size} bytes)")
    return icon_path


def build(use_icon: bool = True) -> int:
    """Run PyInstaller and return its exit code."""
    print("[build] Starting PyInstaller build …")

    templates_src = ROOT / "templates"
    if not templates_src.exists():
        print(f"[build] ERROR: templates/ directory not found at {templates_src}")
        return 1

    entry = ROOT / "src" / "apotrope" / "__main__.py"
    if not entry.exists():
        print(f"[build] ERROR: entry point not found at {entry}")
        return 1

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "apotrope",
        "--add-data", f"{templates_src};templates",
        "--paths", str(ROOT / "src"),
        "--collect-submodules", "apotrope.checks",
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

    print(f"[build] Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=str(ROOT))

    if result.returncode == 0:
        exe = ROOT / "dist" / "apotrope.exe"
        size_mb = exe.stat().st_size / 1024 / 1024 if exe.exists() else 0
        print(f"\n[build] SUCCESS — dist/apotrope.exe ({size_mb:.1f} MB)")
        print("[build] Test with:  dist\\apotrope.exe --version")
    else:
        print(f"\n[build] FAILED (exit {result.returncode})")

    return result.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Build apotrope.exe via PyInstaller")
    parser.add_argument("--no-icon", action="store_true",
                        help="Skip icon embedding (faster, good for CI)")
    args = parser.parse_args()
    sys.exit(build(use_icon=not args.no_icon))


if __name__ == "__main__":
    main()
