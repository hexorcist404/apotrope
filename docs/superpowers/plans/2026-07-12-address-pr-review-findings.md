# PR Review Findings Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct all 11 findings from retrospective reviews of PRs #81, #82, #84, and #85 so reports never overstate security posture, technical-report controls are accurate and accessible, and brand assets cannot drift while CI remains green.

**Architecture:** Keep the existing report and build architecture. Add explicit reliability metadata to `ScanDiff`, make executive-report clean-state copy depend on both open findings and evaluation errors, validate colliding output paths at the CLI boundary, and strengthen static asset tests rather than loading brand JSON at runtime. Each task is independently testable and commit-ready.

**Tech Stack:** Python 3.12+, pytest, Rich, Jinja2, stdlib XML parsing, Pillow for development-time ICO inspection, GitHub Actions.

## Global Constraints

- Preserve Windows 10/11 and Windows Server 2019/2022 behavior.
- Add type hints to every new function and docstrings to public functions/classes.
- Use `logging`, not `print()`, for new diagnostic output in application code.
- Keep generated HTML self-contained, offline, and autoescaped.
- Do not change scoring deductions; INFO and ERROR remain score-neutral.
- Do not add runtime dependencies for brand-token validation; Pillow is development-only.
- Before every commit, run `git config user.name "hexorcist404"` and `git config user.email "hexorcist404@pm.me"`.
- Do not add a `Co-Authored-By` trailer for `hexorcist404` to commits already authored by `hexorcist404`.

---

## File Map

- `src/apotrope/compare.py`: classify comparison-score reliability.
- `src/apotrope/reporter.py`: render unreliable deltas neutrally and generate truthful executive-report narratives.
- `src/apotrope/cli.py`: reject technical/executive output path collisions.
- `src/apotrope/templates/report.html.j2`: technical-report copy, status emphasis, and command disclosure accessibility.
- `src/apotrope/templates/exec_report.html.j2`: distinguish clean assessments from incomplete assessments.
- `tests/test_compare.py`: comparison reliability unit tests.
- `tests/test_reporter_terminal.py`: comparison rendering regressions.
- `tests/test_cli.py`: output path collision regressions.
- `tests/test_reporter.py`: generated HTML, narrative, copy, semantics, and ARIA regressions.
- `tests/test_brand_assets.py`: token-consumer, SVG, and ICO integrity checks.
- `pyproject.toml`: add Pillow to development dependencies only.
- `.github/workflows/test.yml`: exercise icon-enabled executable builds.
- `.github/workflows/release.yml`: keep release comments consistent with installed dependencies and asset validation.
- `brand/README.md`: accurately describe CI-enforced synchronization.

---

### Task 1: Make Comparison Score Changes Honest When Coverage Is Indeterminate

**Findings covered:** PR #81 P1.

**Files:**
- Modify: `src/apotrope/compare.py:30-151`
- Modify: `src/apotrope/reporter.py:590-620`
- Test: `tests/test_compare.py`
- Test: `tests/test_reporter_terminal.py:466-530`

**Interfaces:**
- Consumes: existing `ScanDiff`, `missing_findings`, and `errored_findings`.
- Produces: `ScanDiff.score_delta_reliable: bool`; `Reporter.print_comparison()` uses it to choose trustworthy green/red rendering or an amber indeterminate label.

- [ ] **Step 1: Write failing comparison reliability tests**

Add to `TestErroredChecks` in `tests/test_compare.py`:

```python
def test_fail_to_error_makes_raw_score_delta_unreliable(self):
    baseline = _make_report(
        [_make_result("Firewall", Status.FAIL, severity=Severity.HIGH)],
        score=90,
    )
    current = _make_report(
        [_make_result("Firewall", Status.ERROR, severity=Severity.HIGH)],
        score=100,
    )

    diff = compare_reports(baseline, current)

    assert diff.score_delta == 10
    assert diff.score_delta_reliable is False

def test_missing_bad_check_makes_raw_score_delta_unreliable(self):
    baseline = _make_report([_make_result("Firewall", Status.FAIL)], score=90)
    current = _make_report([], score=100)

    assert compare_reports(baseline, current).score_delta_reliable is False

def test_complete_comparison_keeps_score_delta_reliable(self):
    baseline = _make_report([_make_result("Firewall", Status.FAIL)], score=90)
    current = _make_report([_make_result("Firewall", Status.PASS)], score=100)

    assert compare_reports(baseline, current).score_delta_reliable is True
```

Update the `_diff()` helper in `tests/test_reporter_terminal.py` to accept `score_delta_reliable: bool = True`, then add:

```python
def test_unreliable_positive_delta_is_not_rendered_green(self):
    diff = _diff(90, 100, score_delta_reliable=False)

    out = _render(Reporter(), "print_comparison", diff)

    assert "+10 raw" in out
    assert "indeterminate" in out
    assert "[green]" not in out
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_compare.py tests/test_reporter_terminal.py -q
```

Expected: failures because `ScanDiff` has no `score_delta_reliable` field and the renderer still colors every non-negative delta green.

- [ ] **Step 3: Add reliability metadata to `ScanDiff`**

In `src/apotrope/compare.py`, add the field and document that the numeric score remains the raw current-minus-baseline value:

```python
@dataclasses.dataclass
class ScanDiff:
    # Existing fields remain unchanged.
    missing_findings: list[CheckResult] = dataclasses.field(default_factory=list)
    errored_findings: list[CheckResult] = dataclasses.field(default_factory=list)
    score_delta_reliable: bool = True
```

After classification, compute:

```python
score_delta = current.score - baseline.score
score_delta_reliable = not missing_findings and not errored_findings
```

Pass `score_delta_reliable=score_delta_reliable` into `ScanDiff(...)`. Update the class docstring so callers know `False` means the raw delta must not be presented as confirmed improvement or regression.

- [ ] **Step 4: Render incomplete comparisons neutrally**

Replace the unconditional color choice in `Reporter.print_comparison()` with:

```python
delta_sign = "+" if diff.score_delta >= 0 else ""
if diff.score_delta_reliable:
    delta_col = "green" if diff.score_delta >= 0 else "red"
    delta_label = f"{delta_sign}{diff.score_delta}"
else:
    delta_col = "yellow"
    delta_label = f"{delta_sign}{diff.score_delta} raw · indeterminate"
```

Render `delta_label` inside the existing score line. Do not change either stored report score and do not invent a replacement score.

- [ ] **Step 5: Run focused and static checks**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_compare.py tests/test_reporter_terminal.py -q
.\.venv\Scripts\ruff.exe check src/apotrope/compare.py src/apotrope/reporter.py tests/test_compare.py tests/test_reporter_terminal.py
.\.venv\Scripts\mypy.exe src tests
```

Expected: all pass; the FAIL-to-ERROR regression displays an amber indeterminate raw delta.

- [ ] **Step 6: Commit Task 1**

```powershell
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
git add src/apotrope/compare.py src/apotrope/reporter.py tests/test_compare.py tests/test_reporter_terminal.py
git commit -m "fix(compare): mark incomplete score deltas indeterminate"
```

---

### Task 2: Make Executive Reports Truthful for ERROR Results and Safe for Output Paths

**Findings covered:** PR #85 P1 category-pass claim, PR #85 P1 error-only all-clear claim, PR #85 P2 path collision.

**Files:**
- Modify: `src/apotrope/cli.py:195-222`
- Modify: `src/apotrope/reporter.py:1130-1315`
- Modify: `src/apotrope/templates/exec_report.html.j2:320-375`
- Test: `tests/test_cli.py`
- Test: `tests/test_reporter.py:490-710`

**Interfaces:**
- Consumes: `AuditReport.error_count`, `AuditReport.results`, `Status.PASS`, CLI `--html`, and CLI `--exec-report`.
- Produces: `_validate_output_paths(parser: argparse.ArgumentParser, html_path: str | None, exec_path: str | None) -> None`; executive copy with explicit clean, incomplete, and open-findings branches.

- [ ] **Step 1: Write failing CLI path-collision tests**

Add to the CLI output tests in `tests/test_cli.py`:

```python
def test_html_and_exec_report_must_use_distinct_paths(self):
    with pytest.raises(SystemExit, match="2"):
        self._run_main(
            ["--html", "report.html", "--exec-report", "report.html"],
            self._reporter_with_report()[0],
        )

def test_html_and_exec_report_reject_equivalent_paths(self, tmp_path):
    target = tmp_path / "report.html"
    equivalent = tmp_path / "." / "report.html"
    with pytest.raises(SystemExit, match="2"):
        self._run_main(
            ["--html", str(target), "--exec-report", str(equivalent)],
            self._reporter_with_report()[0],
        )
```

If `_run_main()` captures `stderr`, also assert it contains `--html and --exec-report must use different files`.

- [ ] **Step 2: Write failing ERROR-state executive-report tests**

Add helpers/tests in `TestExecNarrative` and `TestGenerateExecutiveReport`:

```python
def test_bottom_line_does_not_call_error_only_report_clean(self):
    results = [
        CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"),
        CheckResult("Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"),
    ]

    line = str(Reporter()._build_exec_bottom_line(self._report(results, 100)))

    assert "could not be evaluated" in line
    assert "No corrective action is required" not in line

def test_error_category_is_not_claimed_as_fully_passed(self):
    results = [
        CheckResult("Firewall", "FW", Status.FAIL, Severity.HIGH, "d", "off", "fix"),
        CheckResult("Network", "Known Good", Status.PASS, Severity.INFO, "d", "ok"),
        CheckResult("Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"),
    ]

    paragraphs = Reporter()._build_exec_paragraphs(self._report(results, 90))
    rendered = " ".join(str(paragraph) for paragraph in paragraphs)

    assert "Network category passed all of its checks" not in rendered

def test_error_only_report_renders_incomplete_not_all_clear(self):
    results = [
        CheckResult("Firewall", "FW", Status.PASS, Severity.HIGH, "d", "ok"),
        CheckResult("Network", "Probe", Status.ERROR, Severity.INFO, "d", "failed"),
    ]
    html = self._generate(AuditReport(
        hostname="TEST-PC",
        os_version="Windows 11",
        scan_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_duration=1.0,
        results=results,
        score=100,
        is_admin=True,
    ))

    assert "Assessment incomplete" in html
    assert "All clear" not in html
```

- [ ] **Step 3: Run focused tests and confirm failure**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_cli.py tests/test_reporter.py -q
```

Expected: path collisions are accepted, error-only output says no action is required, and ERROR categories are called fully passed.

- [ ] **Step 4: Reject colliding output files before scanning**

Add to `src/apotrope/cli.py`:

```python
def _validate_output_paths(
    parser: argparse.ArgumentParser,
    html_path: str | None,
    exec_path: str | None,
) -> None:
    """Reject technical and executive reports that resolve to one file."""
    if not html_path or not exec_path:
        return
    from pathlib import Path

    if Path(html_path).resolve() == Path(exec_path).resolve():
        parser.error("--html and --exec-report must use different files")
```

Call `_validate_output_paths(parser, args.html, args.exec_report)` immediately after `args = parser.parse_args()`, before loading profiles or running a scan.

- [ ] **Step 5: Restrict “passed all checks” to all-PASS categories**

Replace the `open_cats` subtraction in `_build_exec_paragraphs()` with:

```python
categories = {result.category for result in report.results}
clean = sorted(
    category
    for category in categories
    if all(
        result.status is Status.PASS
        for result in report.results
        if result.category == category
    )
)
```

Change the scope sentence from `evaluated {total} security controls` to `attempted {total} security controls`; later sentences already distinguish passed, open, informational, and unevaluable results.

- [ ] **Step 6: Add an incomplete-assessment bottom line and template branch**

In `_build_exec_bottom_line()`, insert this before the current `open_n == 0` clean branch:

```python
if open_n == 0 and report.error_count:
    count = report.error_count
    noun = "control" if count == 1 else "controls"
    return Markup(
        f"No remediation findings were confirmed, but {count} {noun} "
        "could not be evaluated. Resolve those errors and re-run the "
        "assessment before treating this system as clear."
    )
```

In both the roadmap and detailed-findings empty branches of `exec_report.html.j2`, use three states:

```jinja2
{% if open_total %}
  {# existing open-finding content #}
{% elif error_count %}
  <div class="note-box assessment-incomplete">
    <div class="fk">Assessment incomplete</div>
    {{ error_count }} control{{ 's' if error_count != 1 }} could not be evaluated.
    Resolve the errors and re-run the assessment before treating this system as clear.
  </div>
{% else %}
  {# existing all-clear content #}
{% endif %}
```

- [ ] **Step 7: Run focused checks**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_cli.py tests/test_reporter.py -q
.\.venv\Scripts\ruff.exe check src/apotrope/cli.py src/apotrope/reporter.py tests/test_cli.py tests/test_reporter.py
.\.venv\Scripts\mypy.exe src tests
```

Expected: all pass; no error-bearing report contains “All clear” or “passed all of its checks” for the errored category.

- [ ] **Step 8: Commit Task 2**

```powershell
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
git add src/apotrope/cli.py src/apotrope/reporter.py src/apotrope/templates/exec_report.html.j2 tests/test_cli.py tests/test_reporter.py
git commit -m "fix(report): handle incomplete assessments honestly"
```

---

### Task 3: Correct Technical-Report Semantics, Copy, and Disclosure Accessibility

**Findings covered:** PR #81 P2; all three PR #84 P2 findings.

**Files:**
- Modify: `src/apotrope/templates/report.html.j2:340-445, 555-595, 670-680, 730-745`
- Test: `tests/test_reporter.py:60-370`

**Interfaces:**
- Consumes: `top_remainder`, Jinja `loop.index`, `.ti-cmd-toggle`, and adjacent `.code` panels.
- Produces: accurate “additional open findings” copy; PASS/INFO de-emphasis; `aria-expanded`/`aria-controls` disclosure contract.

- [ ] **Step 1: Write failing generated-HTML regressions**

Add to `TestGenerateHtmlReport`:

```python
def test_footer_uses_canonical_privacy_copy(self):
    html = self._generate(_make_report())
    assert "No data leaves this machine" in html
    assert "No data left this machine" not in html

def test_pass_and_info_are_deemphasized_but_error_is_not(self):
    html = self._generate(_make_report())
    assert ".frow.is-pass, .frow.is-info { opacity:0.62; }" in html
    assert ".frow.is-pass, .frow.is-error { opacity:0.62; }" not in html

def test_top_remainder_is_not_called_lower_severity(self):
    extras = [
        CheckResult(
            "Firewall",
            f"Critical {index}",
            Status.FAIL,
            Severity.CRITICAL,
            "d",
            "off",
            "fix",
        )
        for index in range(9)
    ]
    html = self._generate(_make_report(extra_results=extras))
    assert "additional open findings not shown here" in html
    assert "more lower-severity" not in html

def test_top_issue_command_toggle_has_aria_contract(self):
    command = CheckResult(
        "Firewall",
        "Command Finding",
        Status.FAIL,
        Severity.HIGH,
        "d",
        "off",
        "fix",
        "Set-NetFirewallProfile -Enabled True",
    )
    html = self._generate(_make_report(extra_results=[command]))

    match = re.search(
        r'<button class="ti-cmd-toggle"[^>]*aria-expanded="false"'
        r'[^>]*aria-controls="([^"]+)"[^>]*>',
        html,
    )
    assert match is not None
    assert f'id="{match.group(1)}"' in html
    assert "btn.setAttribute('aria-expanded', String(opening));" in html
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_reporter.py::TestGenerateHtmlReport -q
```

Expected: all four new tests fail against current template copy/selectors/markup.

- [ ] **Step 3: Correct footer, remainder, and row-emphasis semantics**

In `report.html.j2`:

```css
.frow.is-pass, .frow.is-info { opacity:0.62; }
.frow.is-pass:hover, .frow.is-info:hover { opacity:1; }
.frow.is-pass:has(.is-open), .frow.is-info:has(.is-open) { opacity:1; }
```

Update the matching print selector to `.frow.is-pass, .frow.is-info`. Replace the footer phrase with `No data leaves this machine`. Replace the remainder sentence with:

```jinja2
+ {{ top_remainder }} additional open {{ 'finding' if top_remainder == 1 else 'findings' }} not shown here —
```

- [ ] **Step 4: Add a complete ARIA disclosure contract**

Inside the `top_issues` loop, use a stable per-render ID:

```jinja2
{% set command_id = 'top-issue-command-' ~ loop.index %}
<button
  class="ti-cmd-toggle"
  type="button"
  data-on="false"
  aria-expanded="false"
  aria-controls="{{ command_id }}"
>
  <span class="chev" aria-hidden="true">▶</span>
  <span class="lbl">Show remediation command</span>
</button>
<div id="{{ command_id }}" class="code" data-cmd="{{ r.command }}" hidden>
```

Update the click handler after calculating `opening`:

```javascript
btn.setAttribute('aria-expanded', String(opening));
```

Keep `data-on` because CSS uses it for the chevron rotation.

- [ ] **Step 5: Run focused and full template tests**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_reporter.py tests/test_reporter_terminal.py -q
.\.venv\Scripts\ruff.exe check tests/test_reporter.py
```

Expected: all pass, including autoescape and command-copy regressions.

- [ ] **Step 6: Regenerate the checked-in sample report if the repository generator requires it**

Search for the documented generation command:

```powershell
rg -n "docs/report.html|gen_sample_report|generate_html_report" README.md CONTRIBUTING.md scripts tests .github
```

If an existing deterministic generator is found, run it and verify `docs/report.html` contains `No data leaves this machine`. If no generator exists, do not hand-edit the generated sample in this task; log a follow-up documentation-generation issue instead.

- [ ] **Step 7: Commit Task 3**

```powershell
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
git add src/apotrope/templates/report.html.j2 tests/test_reporter.py
git add docs/report.html  # only when regenerated by an existing deterministic command
git commit -m "fix(report): correct finding semantics and disclosure a11y"
```

---

### Task 4: Enforce Brand Tokens Across Python, CSS, SVG, and the Shipped ICO

**Findings covered:** all three PR #82 P2 findings.

**Files:**
- Modify: `tests/test_brand_assets.py`
- Modify: `pyproject.toml:30-38`
- Modify: `.github/workflows/test.yml:45-65`
- Modify: `.github/workflows/release.yml:43-64`
- Modify: `brand/README.md:1-36`
- Verify, do not manually edit: `assets/icon.ico`, `assets/icon.svg`, `assets/icon-16.svg`

**Interfaces:**
- Consumes: `brand/tokens.json`, private reporter palette constants, CSS custom properties, SVG visible attributes, and Pillow's `IcoImagePlugin` frame API.
- Produces: CI failures whenever a consumer, visible SVG attribute, or committed ICO drifts from canonical brand tokens.

- [ ] **Step 1: Add Pillow as a development-only dependency**

Add to `[project.optional-dependencies].dev` in `pyproject.toml`:

```toml
"pillow>=10.0",
```

Do not add Pillow to `[project].dependencies`; normal Apotrope installations remain unchanged.

- [ ] **Step 2: Replace comment-sensitive SVG checks with XML attribute checks**

In `tests/test_brand_assets.py`, import `xml.etree.ElementTree as ET` and replace raw substring matching with:

```python
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

def test_icon_masters_use_visible_mark_colors():
    mark = _tokens()["mark"]
    expected = {
        mark["ground"]["hex"].lower(),
        mark["cyan"]["hex"].lower(),
        mark["mint"]["hex"].lower(),
        mark["ember"]["core"]["hex"].lower(),
        mark["ember"]["highlight"]["hex"].lower(),
        mark["ember"]["shade"]["hex"].lower(),
    }
    for svg in (ICON_SVG, ICON_16_SVG):
        assert expected <= _visible_svg_colors(svg)
```

This test must fail if visible fills/strokes change even when comments retain old hex strings.

- [ ] **Step 3: Validate canonical Python and CSS consumers**

Add helpers and mappings to `tests/test_brand_assets.py`:

```python
def _css_vars(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    return {
        name.lower(): value.lower()
        for name, value in re.findall(
            r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})",
            text,
        )
    }

def test_reporter_palette_matches_product_tokens():
    from apotrope import reporter

    product = _tokens()["product"]
    expected = {
        "_GREEN": product["status"]["pass"]["hex"],
        "_CYAN": product["status"]["info"]["hex"],
        "_AMBER": product["status"]["warn"]["hex"],
        "_RED": product["status"]["fail"]["hex"],
        "_CRIT": product["status"]["critical"]["hex"],
        "_TEXT": product["text"]["body"]["hex"],
        "_BRIGHT": product["text"]["bright"]["hex"],
        "_MUTED": product["text"]["muted"]["hex"],
        "_FAINT": product["text"]["faint"]["hex"],
    }
    for name, token in expected.items():
        assert getattr(reporter, name).lower() == token.lower()
```

Add a parameterized CSS test for `src/apotrope/templates/report.html.j2` and `docs/pages.css`, mapping `green/cyan/amber/red/crit/orange/text/bright/muted/faint/void/bg/panel-2` to their token paths. Document any intentionally non-tokenized intermediate surface such as `--panel: #080d11`; do not silently treat it as `product.surface.panel`.

- [ ] **Step 4: Validate the committed ICO's frames and ground color**

Add:

```python
from PIL import Image

ICON_ICO = ROOT / "assets" / "icon.ico"
EXPECTED_ICON_SIZES = {(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)}

def test_committed_ico_has_required_frames_and_ground_color():
    ground_hex = _tokens()["mark"]["ground"]["hex"].lstrip("#")
    ground = tuple(bytes.fromhex(ground_hex))

    with Image.open(ICON_ICO) as icon:
        assert set(icon.ico.sizes()) == EXPECTED_ICON_SIZES
        for size in EXPECTED_ICON_SIZES:
            frame = icon.ico.getimage(size).convert("RGBA")
            opaque_ground = sum(
                1
                for red, green, blue, alpha in frame.getdata()
                if (red, green, blue) == ground and alpha == 255
            )
            assert opaque_ground >= max(1, int(size[0] * size[1] * 0.03))
```

If the 3% threshold fails because ICO quantization slightly changes exact values, inspect actual pixels and replace equality with a documented per-channel tolerance of at most 2; do not remove the color assertion.

- [ ] **Step 5: Make the executable smoke build include the committed icon**

In `.github/workflows/test.yml`, change:

```yaml
- name: Build apotrope.exe
  run: python build_exe.py
```

Update the comment to state that `tests/test_brand_assets.py` validates the committed ICO before the icon-enabled build. In `.github/workflows/release.yml`, remove the stale statement that Pillow is not installed; retain `test -f assets/icon.ico` as a cheap explicit release guard.

- [ ] **Step 6: Correct the brand source-of-truth documentation**

Change `brand/README.md` to say:

```markdown
`tokens.json` is the canonical palette definition. Runtime consumers keep local
constants for zero-I/O startup and self-contained CSS; `tests/test_brand_assets.py`
enforces that those constants, both SVG masters, and the committed ICO match the
tokens. A token change therefore requires updating its validated consumers in the
same commit.
```

This removes the inaccurate claim that every consumer directly reads the JSON file while preserving the CI-backed source-of-truth guarantee.

- [ ] **Step 7: Run brand, build, and static checks**

Run:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest tests/test_brand_assets.py -q
.\.venv\Scripts\ruff.exe check tests/test_brand_assets.py
.\.venv\Scripts\mypy.exe src tests
.\.venv\Scripts\python.exe build_exe.py
.\dist\apotrope.exe --version
.\dist\apotrope.exe --dry-run --no-color
```

Expected: token/consumer/SVG/ICO checks pass, and the icon-enabled executable completes both smoke probes.

- [ ] **Step 8: Commit Task 4**

```powershell
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
git add pyproject.toml tests/test_brand_assets.py brand/README.md .github/workflows/test.yml .github/workflows/release.yml
git commit -m "test(brand): enforce token and icon integrity"
```

---

### Task 5: Full Regression Gate and Review Handoff

**Files:**
- Verify: all files changed by Tasks 1-4
- Update only if policy requires: `CHANGELOG.md`

**Interfaces:**
- Consumes: completed Tasks 1-4.
- Produces: a review-ready branch with evidence that all 11 findings are covered.

- [ ] **Step 1: Run the complete project verification suite**

```powershell
.\.venv\Scripts\python.exe -m pytest tests\ -q --tb=short --cov --cov-report=term-missing --cov-fail-under=95
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src tests
.\.venv\Scripts\bandit.exe -r src
.\.venv\Scripts\pip-audit.exe
```

Expected: every command exits 0; coverage remains at least 95%.

- [ ] **Step 2: Run explicit finding-to-test traceability checks**

```powershell
rg -n "score_delta_reliable|indeterminate" src tests
rg -n "Assessment incomplete|could not be evaluated|all\(.*Status.PASS" src tests
rg -n "aria-expanded|aria-controls|additional open findings|No data leaves" src tests
rg -n "visible_svg_colors|committed_ico|reporter_palette|css_vars" tests/test_brand_assets.py
```

Expected: every reviewed finding has both an implementation match and a regression-test match.

- [ ] **Step 3: Inspect the final diff for scope and generated artifacts**

```powershell
git status --short
git diff --check
git diff --stat
git diff
```

Expected: only files named in this plan changed; no `dist/`, `.pyinstaller/`, cache, or unrelated generated files are staged.

- [ ] **Step 4: Update the changelog only if the project release policy requires unreleased fix entries**

Add concise `[Unreleased]` bullets for comparison honesty, incomplete executive-report handling, technical-report accessibility/copy, and brand integrity. Do not duplicate an existing entry.

- [ ] **Step 5: Commit any required changelog update**

```powershell
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
git add CHANGELOG.md
git commit -m "docs: record report correctness fixes"
```

Skip this commit when no changelog change is required.

- [ ] **Step 6: Request a fresh pre-landing review**

Run the repository's `/review` workflow against the completed branch. The reviewer must specifically challenge:

- FAIL/WARN→ERROR and missing-check score deltas.
- ERROR-only and mixed PASS/ERROR executive reports.
- same-file and equivalent-path CLI output collisions.
- ninth-or-later CRITICAL/HIGH Top Issues.
- keyboard and screen-reader state for command disclosures.
- token changes that leave Python, CSS, SVG, or ICO consumers stale.

## Self-Review Results

- **Spec coverage:** All 11 findings map to Tasks 1-4 and named regression tests.
- **Placeholder scan:** No TBD/TODO/“implement later” steps remain. Conditional sample-report and changelog steps name explicit decision criteria.
- **Type consistency:** `score_delta_reliable` is defined once on `ScanDiff`; `_validate_output_paths()` has exact typed parameters; all later tests use those same names.
- **Scope control:** No scoring-rule changes, runtime brand dependency, template redesign, or unrelated refactor is included.
