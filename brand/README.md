# Apotrope brand palette

`tokens.json` is the canonical palette definition. Runtime consumers keep local
constants for zero-I/O startup and self-contained CSS; `tests/test_brand_assets.py`
enforces that those constants, both SVG masters, and the committed ICO match the
tokens. A token change therefore requires updating its validated consumers in the
same commit.

## Two layers, both canonical, deliberately different

- **`mark`** — the watching-eye logo. Soft cyan (`#6FE0D6`, *sight*) + mint
  (`#BCE7C0`, *ward*) linework with a warm ember iris (`#E8702A`, *the watching
  point*) on **void ground `#0B0D0E`**. Used for the mark, key art, and the
  app/brand icons.
- **`product`** — the CRT/terminal UI (website, HTML report, terminal). Vivid
  terminal green `#2BFF88` plus the load-bearing status scale on the near-black
  product surfaces (`#03060A → #0B1218`).

These are **not** the same palette and should not be merged. The mark's softer
teal/ember is intentionally distinct from the product's neon green/cyan — see
`_meta.rules` in `tokens.json`.

## Rules that travel with the values

- Never recolor the ember iris (`mark.ember.core`).
- The mark always sits on `mark.ground` (`#0B0D0E`) — this is the **app-icon tile**
  color, not a product surface (`product.surface.*`).
- The product status scale is load-bearing and must never drift.

## Who consumes this

- `src/apotrope/reporter.py` — local terminal palette constants.
- `src/apotrope/templates/report.html.j2` and `docs/pages.css` — self-contained
  product CSS custom properties.
- `assets/icon.svg` / `assets/icon-16.svg` — vector masters for the app icon (mark
  on `mark.ground`).
- `assets/icon.ico` — committed multi-frame Windows icon built from those masters.
- `tests/test_brand_assets.py` — enforces token parity across every consumer above.

Origin: distilled from `Apotrope-Design-System.md`.
