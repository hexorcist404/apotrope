# Changelog

All notable changes to Apotrope are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.7] - 2026-06-12

### Changed
- **Triage view is now the default terminal output.** Every category with
  issues gets its own box listing each FAIL/WARN finding with its fix and a
  ready-to-paste PowerShell command — no flag needed. `--fix` is retired and
  kept only as a hidden no-op so existing scripts don't error; `--verbose`
  shows the same boxes for every category and check, passing ones included.
- **Error messages no longer tell elevated users to "run as Administrator".**
  When a check errors during an already-elevated scan, the terminal footer,
  scanner warning, and report summaries now point to `--log-level DEBUG` /
  per-check detail instead of suggesting elevation that wouldn't help.

### Fixed
- **PowerShell Execution Policy check no longer errors when Apotrope is
  launched from PowerShell 7.** pwsh 7 leaves its own Core-only module paths
  in `PSModulePath`; the Windows PowerShell 5.1 subprocesses then resolved
  `Microsoft.PowerShell.Security` to the PS7 copy and failed to load it.
  Apotrope now strips `PSModulePath` from check subprocesses so Windows
  PowerShell rebuilds its correct default.
- **`build_exe.py` can no longer ship an exe with zero check modules.**
  PyInstaller's `--collect-submodules` silently collected nothing unless
  apotrope was pip-installed in the build Python; the build script now puts
  `src` on `PYTHONPATH` for the build and probes the finished exe with
  `--dry-run`, failing loudly if no check modules are bundled.

### Docs
- All PowerShell run examples now use `.\apotrope.exe` (bare `apotrope.exe`
  fails in PowerShell, which doesn't run programs from the current folder by
  name) and `cd $env:USERPROFILE\Downloads` for navigation.
- README terminal screenshots regenerated for the triage-box output.

### Tests
- Rich terminal rendering paths in the reporter are now covered end-to-end,
  including the new admin-aware error hints and build-probe behaviors.

---

## [0.1.6] - 2026-06-06

### Added
- **Copy-paste-ready remediation commands.** Every failing/warning check now
  carries an exact, paste-ready PowerShell command alongside its plain-English
  explanation, split into a new `CheckResult.command` field.
  - **HTML report:** each FAIL/WARN finding shows the explanation plus a labeled
    "Windows PowerShell · run as Administrator" code block with a copy button
    that copies only the command. The findings filter also matches command text.
  - **Terminal:** new `--fix` flag prints a `TOP FIXES` block whose command
    lines are bare and paste-valid (no glyphs, rails, or prompts); `--verbose`
    prints every command verbatim under its finding. Honors `--no-color`.
  - **JSON:** the `command` field serializes automatically for SIEM/pipeline use
    and round-trips through `--compare` baselines.

### Changed
- Remediation strings are now pure prose (the *what & why*); the PowerShell to
  run lives in the new `command` field. Manual/firmware fixes (Secure Boot, OS
  upgrade) ship a commented note plus the closest verification cmdlet so the
  block is always safe to paste.

---

## [0.1.5] - 2026-06-02

### Changed
- First release published to PyPI through the automated trusted-publishing
  workflow (`pip install apotrope`). No functional changes from 0.1.4 — this
  release exists to exercise the OIDC publishing pipeline end to end.

---

## [0.1.4] - 2026-06-02

### Fixed
- **HTML reports now work when installed from PyPI.** The Jinja2 template
  (`report.html.j2`) shipped outside the package with no `package-data`, so
  wheels/sdists contained no template and `apotrope --html` failed on any
  `pip install`. The template now lives in `apotrope/templates/` and is
  packaged as package data; `reporter.py` loads it relative to the module.

### Changed
- First release published to **PyPI** (`pip install apotrope`).
- Renamed the PyInstaller build script `build.py` → `build_exe.py` so it no
  longer shadows the PyPA `build` package (`python -m build` was invoking
  PyInstaller instead of producing the sdist/wheel).

---

## [0.1.3] - 2026-06-02

### Changed
- **Renamed the project from WinPosture to Apotrope.** The Python package is now
  `apotrope`, the console script and bundled executable are `apotrope` / `apotrope.exe`,
  and all documentation, templates, and tests reference the new name. No functional
  audit logic changed.
- Build icon now renders an "A" glyph to match the new name.

---

## [0.1.2] - 2026-04-21

### Security
- Fixed Jinja2 autoescape silently disabled for HTML reports — `select_autoescape(["html"])` checks the last file extension, so `report.html.j2` resolved to `.j2` and autoescape was `False`. Changed to `autoescape=True`. Regression test added to catch future regressions.
- Locked GitHub Actions `claude.yml` to `author_association == 'OWNER'` only — previously had no `if:` guard, allowing any GitHub user to invoke Claude with `contents: write` permissions via an issue comment.

### Changed
- HTML report: score gauge enlarged (130 → 160 px) with larger typography for improved readability
- HTML report: category sections now collapse by default when all checks pass; only sections with failures, warnings, or errors expand automatically
- HTML report: ERROR stat box added (purple) — shown when any checks could not complete
- HTML report: `"Segoe UI"` moved to front of font stack (Windows-native tool, Segoe UI is always available on target systems)
- HTML report: executive summary now notes how many checks could not complete when `error_count > 0`
- README: added "How Apotrope queries your system" section explaining `-ExecutionPolicy Bypass` usage

### Fixed
- HTML report: categories containing only ERROR-status results no longer render collapsed (looked like passing categories)

---

## [0.1.1] - 2026-03-27

### Fixed
- Fixed Defender Tamper Protection check using wrong property (`TamperProtectionEnabled` → `IsTamperProtected`)
- Fixed Unquoted Service Paths check returning ERROR when no unquoted paths found (now correctly returns PASS)
- Fixed CIS benchmark version references (updated to current CIS Windows 11 v5.0.0 and Windows 10 v4.0.0)
- Corrected CIS control ID mappings against latest benchmark PDFs
- Removed non-existent `pip install apotrope` from README (not yet on PyPI)

### Changed
- Updated README checks table to include all 53 checks (was missing ~20)
- Added CIS Benchmark Mapping section to README
- Updated scoring table in README to match actual code deductions
- Added admin privilege note to "Why Apotrope?" section
- WARN deductions now broken out by severity level in documentation

---

## [0.1.0] - 2026-03-17

Initial public release.

### Added

**Core engine**
- `Scanner` orchestrates all check modules; auto-discovers `checks/*.py`
- `REQUIRES_ADMIN` module flag — scanner skips and emits an INFO result when
  not elevated, rather than failing or erroring
- Per-check timing (`check_duration`) recorded on every `CheckResult`
- `AuditReport.error_count` property for post-scan summaries
- `is_admin` flag propagated from scanner through to the report

**Check modules** (27 individual checks across 14 categories)
- Firewall: Domain / Private / Public profiles
- Antivirus: Windows Defender real-time protection and signature age
- Patching: Last hotfix date, Windows Update service, pending update count
- Encryption: BitLocker status per fixed drive (requires admin)
- Accounts: Local admin count, guest account, password policy
- Services: Risky/unnecessary running services (Telnet, SNMP, FTP, …)
- Network: Unexpected listening ports
- Startup: Startup program inventory
- SMB: SMBv1, SMB signing (requires admin)
- RDP: RDP state and NLA enforcement
- UAC: UAC consent prompt level
- PowerShell: Execution policy, script block logging, constrained language mode
- OS: Windows version and build info
- Misc: LLMNR, AutoPlay, Remote Registry, audit policy

**Scoring engine**
- 0–100 score with CRITICAL/HIGH/MEDIUM/LOW/WARN deductions
- Grade A–F with labels (Excellent → Critical)
- Per-category scores for the HTML report

**Terminal reporter** (Rich)
- Animated progress bar with module names, elapsed time, ETA
- Score bar with grade
- Pass/Fail/Warn/Info/Error summary counts
- Top issues panel (critical/high failures)
- Full verbose table on `--verbose`
- Non-admin warning banner when running without elevation
- Error count summary in footer
- ASCII fallbacks for legacy cp1252 terminals (cmd.exe)

**HTML report** (Jinja2, fully self-contained)
- CSS conic-gradient score gauge
- Executive summary paragraph (auto-generated)
- Per-category collapsible breakdown tables
- Detailed findings cards with inline remediation
- Appendix A: INFO inventory
- Appendix B: full check list
- Print-friendly CSS (`@media print`)
- Zero external dependencies (no CDN, no `<script src>`)

**JSON export**
- Full `AuditReport` serialization including all `CheckResult` fields

**CLI** (`apotrope`)
- `--html`, `--json`, `--category`, `--verbose`, `--no-color`, `--log-level`
- Exits 0 on clean scan, 1 if any failures
- `--version` flag

**Distribution**
- `pip install apotrope` via `pyproject.toml` (setuptools, src layout)
- Standalone `apotrope.exe` via `python build.py` (PyInstaller `--onefile`)
- `assets/icon.ico` — shield icon (generated by Pillow)
- GitHub Actions CI: pytest on Python 3.12 and 3.13, `windows-latest`

**Tests**
- 511 tests across 20 test files
- Full mock coverage for all PowerShell/registry/WMI calls
- Scanner, CLI, reporter, and scenario integration tests
