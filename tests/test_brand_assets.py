"""Brand-token drift guards for every committed palette consumer."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest
from PIL import IcoImagePlugin, Image

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ROOT / "brand" / "tokens.json"
ICON_SVG = ROOT / "assets" / "icon.svg"
ICON_16_SVG = ROOT / "assets" / "icon-16.svg"
ICON_ICO = ROOT / "assets" / "icon.ico"
REPORT_TEMPLATE = ROOT / "src" / "apotrope" / "templates" / "report.html.j2"
PAGES_CSS = ROOT / "docs" / "pages.css"
EXPECTED_ICON_SIZES = {(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)}

TokenMap = dict[str, object]


def _tokens() -> TokenMap:
    """Load the canonical brand-token document."""
    return cast(TokenMap, json.loads(TOKENS.read_text(encoding="utf-8")))


def _token_hex(*path: str) -> str:
    """Return the hexadecimal value at a token path."""
    current: object = _tokens()
    for segment in path:
        assert isinstance(current, Mapping)
        current = current[segment]
    assert isinstance(current, str)
    return current


def _visible_svg_colors(path: Path) -> set[str]:
    """Return visible fill, stroke, and gradient colors, excluding comments."""
    root = ET.parse(path).getroot()
    attributes = ("fill", "stroke", "stop-color")
    return {
        value.lower()
        for element in root.iter()
        for attribute in attributes
        if (value := element.attrib.get(attribute, "")).startswith("#")
    }


def _path_name(path: Path) -> str:
    """Return a stable pytest parameter identifier for a path."""
    return path.name


def _css_vars(path: Path, *, enforced: set[str]) -> dict[str, str]:
    """Return active CSS hex variables and reject enforced duplicates."""
    text = re.sub(
        r"/\*.*?\*/",
        "",
        path.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    declarations = re.findall(
        r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})",
        text,
    )
    variables: dict[str, str] = {}
    duplicates: set[str] = set()
    for name, value in declarations:
        normalized_name = name.lower()
        if normalized_name in enforced and normalized_name in variables:
            duplicates.add(normalized_name)
        variables[normalized_name] = value.lower()
    assert not duplicates, f"duplicate active CSS variables: {sorted(duplicates)}"
    return variables


def test_tokens_parse_and_have_mark_layer() -> None:
    """Canonical tokens include each required mark layer and valid colors."""
    tokens = _tokens()
    mark = tokens["mark"]
    assert isinstance(mark, Mapping)
    for key in ("cyan", "mint", "ember", "ground"):
        assert key in mark, f"mark.{key} missing"
    assert re.fullmatch(r"#[0-9A-Fa-f]{6}", _token_hex("mark", "ground", "hex"))
    assert re.fullmatch(r"#[0-9A-Fa-f]{6}", _token_hex("mark", "ember", "core", "hex"))


def test_visible_svg_colors_excludes_comment_colors(tmp_path: Path) -> None:
    """Commented legacy colors cannot satisfy visible SVG assertions."""
    svg = tmp_path / "comment-trap.svg"
    svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><!-- fill="#6FE0D6" -->'
        '<path fill="#000000" /></svg>',
        encoding="utf-8",
    )
    assert _visible_svg_colors(svg) == {"#000000"}


def test_icon_masters_use_visible_mark_colors() -> None:
    """Both SVG masters visibly use every canonical mark color."""
    expected = {
        _token_hex("mark", "ground", "hex").lower(),
        _token_hex("mark", "cyan", "hex").lower(),
        _token_hex("mark", "mint", "hex").lower(),
        _token_hex("mark", "ember", "core", "hex").lower(),
        _token_hex("mark", "ember", "highlight", "hex").lower(),
        _token_hex("mark", "ember", "shade", "hex").lower(),
    }
    for svg in (ICON_SVG, ICON_16_SVG):
        assert _visible_svg_colors(svg) == expected


def test_visible_svg_extra_color_is_rejected(tmp_path: Path) -> None:
    """An extra active color makes the visible set differ from its allowlist."""
    svg = tmp_path / "extra.svg"
    svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><path fill="#6FE0D6" />'
        '<path stroke="#123456" /></svg>',
        encoding="utf-8",
    )
    assert _visible_svg_colors(svg) != {"#6fe0d6"}


def test_css_comments_cannot_mask_wrong_active_value(tmp_path: Path) -> None:
    """A canonical value in a comment cannot hide a wrong active value."""
    css = tmp_path / "comment-trap.css"
    css.write_text(
        "/* --green: #2bff88; */\n:root { --green: #000000; }",
        encoding="utf-8",
    )
    assert _css_vars(css, enforced={"green"}) == {"green": "#000000"}


def test_css_duplicate_active_enforced_variable_is_rejected(tmp_path: Path) -> None:
    """Duplicate active declarations cannot win by source order."""
    css = tmp_path / "duplicate.css"
    css.write_text(
        ":root { --green: #000000; --green: #2bff88; }",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="duplicate active CSS"):
        _css_vars(css, enforced={"green"})

def test_reporter_palette_matches_product_tokens() -> None:
    """Terminal palette constants match canonical product tokens."""
    from apotrope import reporter

    expected = {
        "_GREEN": _token_hex("product", "status", "pass", "hex"),
        "_CYAN": _token_hex("product", "status", "info", "hex"),
        "_AMBER": _token_hex("product", "status", "warn", "hex"),
        "_RED": _token_hex("product", "status", "fail", "hex"),
        "_CRIT": _token_hex("product", "status", "critical", "hex"),
        "_TEXT": _token_hex("product", "text", "body", "hex"),
        "_BRIGHT": _token_hex("product", "text", "bright", "hex"),
        "_MUTED": _token_hex("product", "text", "muted", "hex"),
        "_FAINT": _token_hex("product", "text", "faint", "hex"),
    }
    for name, token in expected.items():
        assert getattr(reporter, name).lower() == token.lower()


@pytest.mark.parametrize("stylesheet", [REPORT_TEMPLATE, PAGES_CSS], ids=_path_name)
def test_css_palette_matches_product_tokens(stylesheet: Path) -> None:
    """Report and site CSS custom properties match canonical product tokens."""
    expected = {
        "green": _token_hex("product", "green", "hex"),
        "cyan": _token_hex("product", "status", "info", "hex"),
        "amber": _token_hex("product", "status", "warn", "hex"),
        "red": _token_hex("product", "status", "fail", "hex"),
        "crit": _token_hex("product", "status", "critical", "hex"),
        "orange": _token_hex("product", "status", "glow", "hex"),
        "text": _token_hex("product", "text", "body", "hex"),
        "bright": _token_hex("product", "text", "bright", "hex"),
        "muted": _token_hex("product", "text", "muted", "hex"),
        "faint": _token_hex("product", "text", "faint", "hex"),
        "void": _token_hex("product", "surface", "void", "hex"),
        "bg": _token_hex("product", "surface", "bg", "hex"),
        "panel-2": _token_hex("product", "surface", "panel", "hex"),
    }
    actual = _css_vars(stylesheet, enforced=set(expected))
    for name, token in expected.items():
        assert actual[name] == token.lower()

    # --panel is an intentional intermediate surface, not product.surface.panel.
    assert actual["panel"] == "#080d11"


def test_committed_ico_has_required_frames_and_ground_color() -> None:
    """The shipped ICO contains every frame and enough opaque mark ground."""
    ground_hex = _token_hex("mark", "ground", "hex").lstrip("#")
    ground = tuple(bytes.fromhex(ground_hex))

    with Image.open(ICON_ICO) as opened:
        icon = cast(IcoImagePlugin.IcoImageFile, opened)
        assert set(icon.ico.sizes()) == EXPECTED_ICON_SIZES
        for size in EXPECTED_ICON_SIZES:
            frame = icon.ico.getimage(size).convert("RGBA")
            pixels = cast(
                Sequence[tuple[int, int, int, int]],
                frame.get_flattened_data(),
            )
            opaque_ground = sum(
                1
                for red, green, blue, alpha in pixels
                if (red, green, blue) == ground and alpha == 255
            )
            assert opaque_ground >= max(1, int(size[0] * size[1] * 0.03))
