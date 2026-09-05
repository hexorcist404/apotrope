"""Public-claims policy: what Apotrope's public copy may say about scoring and CIS.

The invariant: Apotrope produces its own 0-100 posture score; CIS references are
optional mappings on *applicable* findings; remediation exists for failed and
warning checks. Nothing public may describe an official CIS score, a compliance
verdict, or "every finding" being mapped or remediated.

``PROHIBITED`` holds the phrasings that break that invariant, each with the
examples that prove the pattern fires. ``ALLOWED`` holds the single authorised
exception - a sentence whose subject is CIS-CAT, not Apotrope - bound to one
path and exactly one occurrence. ``scan`` reads every public-copy file once and
reports each unsuppressed match with its original line number.

``tests/test_public_claims.py`` exercises every branch here and asserts the
shipped copy is clean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class PolicyError(Exception):
    """The exception table cannot be applied as written (wrong path or count)."""


@dataclass(frozen=True)
class Rule:
    """A prohibited phrasing and the examples that must trip it."""

    name: str
    pattern: re.Pattern[str]
    bad_examples: tuple[str, ...]


@dataclass(frozen=True)
class Allowed:
    """One authorised fragment, bound to a repository-relative path and an exact count."""

    path: str
    fragment: str
    count: int


@dataclass(frozen=True)
class Finding:
    """An unsuppressed match. ``line`` is computed from the original file offset."""

    path: Path
    line: int
    rule: str
    start: int
    end: int
    excerpt: str


# ASCII hyphen, hyphen, non-breaking hyphen, figure dash, en dash, em dash.
DASH = "[-" + "".join(chr(c) for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014)) + "]"
THE = r"(?:the\s+)?"
_DASHES = tuple(chr(c) for c in (0x2D, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014))


def _rule(name: str, pattern: str, *bad_examples: str) -> Rule:
    return Rule(name, re.compile(pattern, re.IGNORECASE), bad_examples)


PROHIBITED: tuple[Rule, ...] = (
    _rule(
        "scores_against_cis",
        rf"\bscor(?:e|es|ed|ing)\b\s+(?:\S+\s+){{0,4}}against\s+{THE}CIS\b",
        "score against CIS",
        "scores your box against CIS controls",
        "scored against CIS",
        "scoring against CIS",
        "scores a machine against the CIS Benchmarks",
    ),
    _rule("cis_score", r"\bCIS\s+score\b", "a CIS score of 80"),
    _rule(
        "cis_style_score",
        rf"\bCIS{DASH}style\s+score\b",
        *(f"a CIS{dash}style score" for dash in _DASHES),
    ),
    _rule("percent_compliant", r"(?:%|\bpercent)\s*compliant\b", "64% compliant", "64 percent compliant"),
    _rule("compliant_configuration", r"\bcompliant\s+configuration\b", "evidence of a compliant configuration"),
    _rule(
        "audits_against_cis",
        rf"\baudit(?:s|ed|ing|or)?\b\s+(?:\S+\s+){{0,4}}against\s+{THE}CIS\b",
        "audit against CIS",
        "audits the local machine against CIS controls",
        "audited against CIS",
        "auditing against CIS",
        "auditor against CIS",
        "audits read-only against the CIS Benchmarks",
    ),
    _rule(
        "against_cis",
        rf"\bagainst\s+{THE}CIS\s+(?:\S+\s+){{0,4}}(?:controls?|benchmarks?)\b",
        "against CIS control",
        "against CIS controls",
        "against CIS benchmark",
        "against CIS Benchmarks",
        "against the CIS Benchmarks",
        "against CIS Microsoft Windows Benchmarks",
    ),
    _rule(
        "maps_every_finding",
        r"\bmap(?:s|ped|ping)?\s+(?:every|each)\s+finding\b",
        "map every finding",
        "maps each finding",
        "mapped every finding",
        "mapping each finding",
    ),
    _rule(
        "every_finding_mapped",
        rf"\b(?:every|each)\s+finding\s+(?:is\s+|gets\s+)?(?:mapped|annotated|linked|tagged|cross{DASH}referenced)\b",
        "every finding mapped",
        "each finding is annotated",
        "every finding gets linked",
        "each finding tagged",
        *(f"every finding cross{dash}referenced" for dash in _DASHES),
    ),
    _rule(
        "remediation_every_finding",
        r"\bremediation\b\s+(?:\S+\s+){0,2}(?:on|for)\s+(?:every|each)\s+(?:finding|check)\b",
        "remediation on every finding",
        "remediation for each check",
        "remediation on each check",
        "remediation for every finding",
        "remediation guidance for every finding",
        "remediation guidance provided on each check",
    ),
)

ALLOWED: tuple[Allowed, ...] = (
    Allowed(
        "docs/vs-cis-cat/index.html",
        "CIS-CAT Lite is CIS's own free assessor and scores a machine against the CIS Benchmarks",
        1,
    ),
)

CATEGORIES: dict[str, tuple[str, ...]] = {
    "readme": ("README.md",),
    "docs_html": ("docs/**/*.html",),
    "docs_llms": ("docs/llms.txt",),
    "templates": ("src/apotrope/templates/*.j2",),
}


def _require_root(root: Path) -> None:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise RuntimeError(f"pyproject.toml not found under {root}")
    if not re.search(r'^name\s*=\s*"apotrope"', pyproject.read_text(encoding="utf-8"), re.MULTILINE):
        raise RuntimeError(f"pyproject.toml under {root} does not name apotrope")


def repo_root() -> Path:
    """The apotrope checkout this module lives in, validated by its pyproject."""
    root = Path(__file__).resolve().parents[1]
    _require_root(root)
    return root


def discover(root: Path) -> list[Path]:
    """Every public-copy file under ``root``. Each category must find at least one file."""
    root = root.resolve()
    _require_root(root)
    found: set[Path] = set()
    for category, patterns in CATEGORIES.items():
        hits = {p.resolve() for pattern in patterns for p in root.glob(pattern) if p.is_file()}
        if not hits:
            raise RuntimeError(f"discovery category {category!r} found no files under {root}")
        found |= hits
    files = sorted(found)
    for path in files:
        if not path.is_relative_to(root):
            raise RuntimeError(f"{path} resolves outside {root}")
    return files


def _suppressed_spans(root: Path, discovered: set[Path]) -> dict[Path, list[tuple[int, int]]]:
    spans: dict[Path, list[tuple[int, int]]] = {}
    for allowed in ALLOWED:
        path = (root / allowed.path).resolve()
        if path not in discovered:
            raise PolicyError(f"exception path {allowed.path!r} not discovered under {root}")
        text = path.read_text(encoding="utf-8")
        starts = [m.start() for m in re.finditer(re.escape(allowed.fragment), text)]
        if len(starts) != allowed.count:
            raise PolicyError(
                f"expected {allowed.count} occurrence(s) of {allowed.fragment!r} in {allowed.path}, found {len(starts)}"
            )
        spans[path] = [(s, s + len(allowed.fragment)) for s in starts]
    return spans


def scan(root: Path) -> list[Finding]:
    """Report every prohibited match in the public copy that is not inside an authorised span."""
    root = root.resolve()
    files = discover(root)
    spans = _suppressed_spans(root, set(files))
    findings: list[Finding] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        file_spans = spans.get(path, [])
        for rule in PROHIBITED:
            for match in rule.pattern.finditer(text):
                if any(s <= match.start() and match.end() <= e for s, e in file_spans):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                findings.append(Finding(path, line, rule.name, match.start(), match.end(), match.group(0)))
    findings.sort(key=lambda f: (str(f.path), f.line, f.start, f.rule))
    return findings
