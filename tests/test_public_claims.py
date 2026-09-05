"""Public-claims policy: the public copy never overstates what Apotrope does.

Apotrope produces its own 0-100 posture score. CIS references are optional
mappings on *applicable* findings, and remediation exists for failed and warning
checks. ``tools/public_claims.py`` holds the prohibited phrasings and the single
authorised exception; this module proves the rules fire on every intended
variant, stay quiet on the near misses, and that the shipped copy is clean.
"""

from __future__ import annotations

import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import public_claims
from public_claims import PROHIBITED, PolicyError, discover, repo_root, scan

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

INDEX_META = (
    "Free, offline Windows security auditor, like Lynis but for Windows. One .exe scores your box "
    "0–100, maps applicable findings to CIS Benchmark recommendations, and gives plain-English "
    "fixes. No cloud, no agent."
)
INDEX_JSONLD_DESCRIPTION = (
    "Portable, offline Windows security posture auditor. 50+ checks across 14 categories with a "
    "0-100 score, applicable findings mapped to CIS Microsoft Windows Benchmark recommendations "
    "(Windows 11 v5.0.0, Windows 10 v4.0.0), and a self-contained HTML report. Single executable, "
    "no cloud, no agent, read-only."
)
HWS_META = (
    "Harden Windows Security applies a hardened baseline; Apotrope is a read-only auditor with its "
    "own 0–100 score and CIS Benchmark references on applicable findings. Different jobs "
    "— they compose."
)
HWS_FAQ = (
    "Both, if you like — they do different jobs. Harden Windows Security applies a hardened "
    "baseline to your machine; Apotrope is a read-only auditor that gives any Windows box its own "
    "0–100 posture score and cites CIS Benchmark recommendations on applicable findings. Audit "
    "with Apotrope, harden with Harden Windows Security or Group Policy, then re-audit."
)
HWS_QUESTION = "Should I use Apotrope or Harden Windows Security?"
CISCAT_ALLOWED = "CIS-CAT Lite is CIS's own free assessor and scores a machine against the CIS Benchmarks"
CISCAT_REMEDIATION = "plain-English remediation for failed and warning checks"
RECORD_SENTENCE = "This is a record of which checks passed at the time of assessment."

DASHES = ("-", "‐", "‑", "‒", "–", "—")
RULES = {rule.name: rule for rule in PROHIBITED}
EXAMPLES = [(rule.name, example) for rule in PROHIBITED for example in rule.bad_examples]
NEGATIVES = (
    "plain-English remediation for failed and warning checks",
    "remediation for each failing check",
    "remediation where available",
    "every finding shows a severity",
    "remediation on the finding",
    "verifies compliance against its baseline",
)
INNOCUOUS = "Nothing to see here.\n"


def _tree(tmp_path: Path, files: dict[str, str] | None = None, *, seed: bool = True) -> Path:
    """Build a synthetic checkout. Seeded trees are policy-valid by default."""
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    seeded = {
        "pyproject.toml": '[project]\nname = "apotrope"\n',
        "README.md": INNOCUOUS,
        "docs/index.html": INNOCUOUS,
        "docs/llms.txt": INNOCUOUS,
        "src/apotrope/templates/report.html.j2": INNOCUOUS,
        "docs/vs-cis-cat/index.html": f"<p>{CISCAT_ALLOWED}.</p>\n",
    }
    contents = {**seeded, **(files or {})} if seed else dict(files or {})
    for rel, text in contents.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _rule_hits(text: str) -> set[str]:
    return {rule.name for rule in PROHIBITED if rule.pattern.search(text)}


# --- module identity and policy shape ----------------------------------------------------------


def test_imports_the_intended_module() -> None:
    assert Path(public_claims.__file__).resolve() == (TOOLS / "public_claims.py").resolve()


def test_exactly_ten_rules_each_with_examples() -> None:
    assert len(PROHIBITED) == 10
    assert len(RULES) == 10
    for rule in PROHIBITED:
        assert rule.bad_examples, rule.name


@pytest.mark.parametrize(("name", "example"), EXAMPLES)
def test_every_example_matches_its_own_rule(name: str, example: str) -> None:
    assert RULES[name].pattern.search(example), f"{name!r} misses {example!r}"


@pytest.mark.parametrize(("name", "example"), EXAMPLES)
def test_case_variants_match(name: str, example: str) -> None:
    for variant in (example.upper(), example.lower(), example.title()):
        assert RULES[name].pattern.search(variant), f"{name!r} misses {variant!r}"


@pytest.mark.parametrize(("name", "example"), EXAMPLES)
def test_whitespace_variants_match(name: str, example: str) -> None:
    for sep in ("  ", "\t", "\n"):
        variant = example.replace(" ", sep)
        assert RULES[name].pattern.search(variant), f"{name!r} misses {variant!r}"


@pytest.mark.parametrize("dash", DASHES)
def test_dash_variants_match(dash: str) -> None:
    assert RULES["cis_style_score"].pattern.search(f"a CIS{dash}style score")
    assert RULES["every_finding_mapped"].pattern.search(f"every finding cross{dash}referenced")


@pytest.mark.parametrize("the", ("", "the "))
def test_optional_the_before_cis(the: str) -> None:
    assert RULES["against_cis"].pattern.search(f"against {the}CIS Benchmarks")
    assert RULES["scores_against_cis"].pattern.search(f"scores against {the}CIS Benchmarks")
    assert RULES["audits_against_cis"].pattern.search(f"audits against {the}CIS Benchmarks")


@pytest.mark.parametrize("text", NEGATIVES)
def test_near_misses_match_no_rule(text: str) -> None:
    assert _rule_hits(text) == set(), text


def test_multiline_match_reports_its_starting_line(tmp_path: Path) -> None:
    body = "one\ntwo\nthree\nfour\nmaps every\nfinding to CIS\n"
    root = _tree(tmp_path, {"docs/multi.html": body})
    findings = scan(root)
    assert findings, "expected the wrapped claim to be found"
    assert {f.line for f in findings if f.path.name == "multi.html"} == {5}


# --- exception semantics ------------------------------------------------------------------------


def test_default_tree_is_policy_valid(tmp_path: Path) -> None:
    assert scan(_tree(tmp_path)) == []


def test_allowed_fragment_in_wrong_path_is_a_finding(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/other.html": f"<p>{CISCAT_ALLOWED}.</p>\n"})
    rules = {f.rule for f in scan(root) if f.path.name == "other.html"}
    assert {"against_cis", "scores_against_cis"} <= rules


def test_duplicate_allowed_fragment_is_rejected(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": f"{CISCAT_ALLOWED}. {CISCAT_ALLOWED}.\n"})
    with pytest.raises(PolicyError, match="expected 1 occurrence"):
        scan(root)


def test_missing_allowed_fragment_is_rejected(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": INNOCUOUS})
    with pytest.raises(PolicyError, match="found 0"):
        scan(root)


def test_missing_exception_path_is_rejected(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "docs/vs-cis-cat/index.html").unlink()
    with pytest.raises(PolicyError, match="not discovered"):
        scan(root)


def test_changed_subject_is_not_silently_suppressed(tmp_path: Path) -> None:
    apotrope_claim = "Apotrope is CIS's own free assessor and scores a machine against the CIS Benchmarks"
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": f"<p>{apotrope_claim}.</p>\n"})
    with pytest.raises(PolicyError):
        scan(root)
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": f"<p>{CISCAT_ALLOWED}.</p>\n<p>{apotrope_claim}.</p>\n"})
    text = (root / "docs/vs-cis-cat/index.html").read_text(encoding="utf-8")
    allowed_end = text.index(CISCAT_ALLOWED) + len(CISCAT_ALLOWED)
    findings = [f for f in scan(root) if f.path.name == "index.html"]
    assert findings
    assert all(f.start >= allowed_end for f in findings)


def test_same_line_allowed_plus_bad_reports_only_the_bad_span(tmp_path: Path) -> None:
    line = f"{CISCAT_ALLOWED}; Apotrope scores your box against CIS controls.\n"
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": line})
    findings = scan(root)
    assert findings
    assert all(f.start >= len(CISCAT_ALLOWED) for f in findings)


def test_same_line_with_only_the_allowed_fragment_is_clean(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": f"{CISCAT_ALLOWED}; nothing else.\n"})
    assert scan(root) == []


def test_match_crossing_the_span_edge_is_reported(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/vs-cis-cat/index.html": f"{CISCAT_ALLOWED} controls\n"})
    assert {f.rule for f in scan(root)} >= {"against_cis"}


def test_hws_baseline_sentence_is_not_flagged() -> None:
    assert _rule_hits("verifies compliance against its baseline") == set()


# --- discovery contract -------------------------------------------------------------------------


def test_repo_root_is_the_apotrope_checkout() -> None:
    root = repo_root()
    assert root == ROOT
    assert 'name = "apotrope"' in (root / "pyproject.toml").read_text(encoding="utf-8")


def test_real_repo_discovery_is_complete(record_property: Any) -> None:
    files = discover(ROOT)
    names = {p.relative_to(ROOT).as_posix() for p in files}
    for anchor in (
        "README.md",
        "docs/index.html",
        "docs/report.html",
        "docs/exec-report.html",
        "docs/llms.txt",
        "src/apotrope/templates/report.html.j2",
        "src/apotrope/templates/exec_report.html.j2",
    ):
        assert anchor in names, anchor
    assert len(files) == len(set(files))
    assert all(p.resolve().is_relative_to(ROOT) for p in files)
    record_property("public_claims_files_scanned", len(files))
    assert len(files) >= 8, f"only {len(files)} public-copy files discovered"


def test_nested_docs_html_is_discovered(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"docs/nested/deeper/page.html": INNOCUOUS})
    assert (root / "docs/nested/deeper/page.html").resolve() in {p.resolve() for p in discover(root)}


def test_missing_category_fails_discovery(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "docs/llms.txt").unlink()
    with pytest.raises(RuntimeError, match="docs_llms"):
        discover(root)


def test_broken_root_fails_discovery(tmp_path: Path) -> None:
    root = _tree(tmp_path, seed=False)
    with pytest.raises(RuntimeError, match="pyproject"):
        discover(root)


def test_path_resolving_outside_root_fails_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _tree(tmp_path)
    (tmp_path / "escape.md").write_text(INNOCUOUS, encoding="utf-8")
    monkeypatch.setattr(public_claims, "CATEGORIES", {**public_claims.CATEGORIES, "escape": ("../escape.md",)})
    with pytest.raises(RuntimeError, match="outside"):
        discover(root)


def test_foreign_project_root_fails_discovery(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"pyproject.toml": '[project]\nname = "somethingelse"\n'})
    with pytest.raises(RuntimeError, match="does not name apotrope"):
        discover(root)


# --- positive targets in the shipped copy -------------------------------------------------------


REQUIRED_FRAGMENTS = [
    ("README.md", "maps applicable findings to CIS Microsoft Windows Benchmark recommendations", 1),
    ("README.md", "useful as supporting evidence for audits", 1),
    ("docs/index.html", "Applicable findings are annotated with their CIS Benchmark recommendation ID", 1),
    ("docs/llms.txt", "maps applicable findings to CIS Microsoft Windows Benchmark recommendations", 1),
    ("docs/lynis-for-windows/index.html", "maps applicable findings to CIS Benchmark recommendations", 1),
    ("docs/vs-cis-cat/index.html", "cites CIS recommendations on applicable findings", 1),
    ("docs/vs-cis-cat/index.html", CISCAT_ALLOWED, 1),
    ("docs/vs-cis-cat/index.html", CISCAT_REMEDIATION, 1),
    ("docs/vs-cis-cat/index.html", "remediation on every finding", 0),
    ("docs/vs-harden-windows-security/index.html", "cites CIS Benchmark recommendations on applicable findings", 3),
    ("docs/vs-harden-windows-security/index.html", "CIS references where applicable", 1),
    (
        "docs/vs-harden-windows-security/index.html",
        "Failed and warning checks ship with a copy-paste PowerShell fix",
        2,
    ),
    ("docs/vs-harden-windows-security/index.html", "Every finding ships with", 0),
    ("src/apotrope/templates/exec_report.html.j2", "% of checks passed", 1),
    ("src/apotrope/templates/exec_report.html.j2", RECORD_SENTENCE, 1),
    ("docs/exec-report.html", "% of checks passed", 1),
    ("docs/exec-report.html", RECORD_SENTENCE, 1),
]


@pytest.mark.parametrize(("rel", "fragment", "count"), REQUIRED_FRAGMENTS)
def test_required_fragment_count(rel: str, fragment: str, count: int) -> None:
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert text.count(fragment) == count, f"{rel}: {fragment!r} occurs {text.count(fragment)} times, expected {count}"


class _Head(HTMLParser):
    """Collects meta descriptions and JSON-LD blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.ld: list[str] = []
        self._in_ld = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "meta":
            key = a.get("name") or a.get("property")
            if key in {"description", "og:description", "twitter:description"} and a.get("content") is not None:
                self.meta.setdefault(key, []).append(str(a["content"]))
        if tag == "script" and a.get("type") == "application/ld+json":
            self._in_ld = True

    def handle_data(self, data: str) -> None:
        if self._in_ld:
            self.ld.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_ld = False


def _parse_head(rel: str) -> _Head:
    parser = _Head()
    parser.feed((ROOT / rel).read_text(encoding="utf-8"))
    return parser


def _ld_objects(parser: _Head) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in parser.ld:
        data = json.loads(block)
        items = data.get("@graph", [data]) if isinstance(data, dict) else data
        out.extend(item for item in items if isinstance(item, dict))
    return out


def test_index_meta_descriptions_are_identical_and_approved() -> None:
    head = _parse_head("docs/index.html")
    for key in ("description", "og:description", "twitter:description"):
        assert head.meta.get(key) == [INDEX_META], key


def test_index_jsonld_description_is_approved() -> None:
    apps = [o for o in _ld_objects(_parse_head("docs/index.html")) if o.get("@type") == "SoftwareApplication"]
    assert len(apps) == 1
    assert apps[0]["description"] == INDEX_JSONLD_DESCRIPTION


def test_hws_meta_descriptions_are_identical_and_approved() -> None:
    head = _parse_head("docs/vs-harden-windows-security/index.html")
    for key in ("og:description", "twitter:description"):
        assert head.meta.get(key) == [HWS_META], key


def test_hws_jsonld_faq_answer_is_approved() -> None:
    head = _parse_head("docs/vs-harden-windows-security/index.html")
    faqs = [o for o in _ld_objects(head) if o.get("@type") == "FAQPage"]
    assert len(faqs) == 1
    answers = [q["acceptedAnswer"]["text"] for q in faqs[0]["mainEntity"] if q.get("name") == HWS_QUESTION]
    assert answers == [HWS_FAQ]


def test_shipped_copy_has_no_prohibited_claims() -> None:
    findings = scan(ROOT)
    report = "\n".join(f"{f.path.relative_to(ROOT).as_posix()}:{f.line} {f.rule} - {f.excerpt}" for f in findings)
    assert findings == [], report
