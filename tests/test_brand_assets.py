"""Brand-palette drift guards.

brand/tokens.json is the single source of truth for Apotrope's colors. These
tests fail CI if the committed icon SVGs stop matching those tokens, so the
app-icon tile and mark linework can't quietly drift from the palette.

Pure stdlib (json + regex) — no Pillow, so it runs on the Linux CI runner.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ROOT / "brand" / "tokens.json"
ICON_SVG = ROOT / "assets" / "icon.svg"
ICON_16_SVG = ROOT / "assets" / "icon-16.svg"


def _tokens() -> dict:
    return json.loads(TOKENS.read_text(encoding="utf-8"))


def _rect_fill(svg_text: str) -> str:
    """The tile <rect>'s fill hex, lowercased."""
    m = re.search(r"<rect\b[^>]*\bfill=\"(#[0-9a-fA-F]{6})\"", svg_text)
    assert m, "no <rect fill=...> tile found in SVG"
    return m.group(1).lower()


def test_tokens_parse_and_have_mark_layer():
    t = _tokens()
    for key in ("cyan", "mint", "ember", "ground"):
        assert key in t["mark"], f"mark.{key} missing"
    assert re.fullmatch(r"#[0-9A-Fa-f]{6}", t["mark"]["ground"]["hex"])
    assert re.fullmatch(r"#[0-9A-Fa-f]{6}", t["mark"]["ember"]["core"]["hex"])


def test_icon_tile_matches_mark_ground():
    ground = _tokens()["mark"]["ground"]["hex"].lower()
    for svg in (ICON_SVG, ICON_16_SVG):
        assert _rect_fill(svg.read_text(encoding="utf-8")) == ground, (
            f"{svg.name} tile drifted from mark.ground ({ground})"
        )


def test_icon_uses_mark_linework_colors():
    """The primary mark hues in icon.svg must be the brand tokens, not lookalikes."""
    mark = _tokens()["mark"]
    svg = ICON_SVG.read_text(encoding="utf-8").lower()
    for hexval in (mark["cyan"]["hex"], mark["mint"]["hex"], mark["ember"]["core"]["hex"]):
        assert hexval.lower() in svg, f"icon.svg is missing brand color {hexval}"
