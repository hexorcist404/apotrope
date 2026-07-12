# Apotrope — Codex Project Context

## Git Commit Author

Always use these credentials for commits in this repo:

```
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
```

Do not add a `Co-Authored-By` trailer for `hexorcist404` when the commit is
already authored by `hexorcist404`; that trailer is redundant.

## Project Overview

Apotrope is a portable Windows security posture auditor. It runs locally on a
Windows machine, audits common security configurations, scores the result (0–100),
and produces a terminal report (Rich) and/or HTML/JSON output.

## Language & Runtime

- Python 3.12+
- Type hints on **all** functions and methods (no bare `Any` unless unavoidable)
- Docstrings on all public functions/classes
- Logging via Python's `logging` module — never use `print()` for diagnostic output

## Architecture

```
cli.py  →  scanner.py  →  checks/*.py  →  models.CheckResult
                      ↓
                  reporter.py  (terminal via Rich, HTML via Jinja2)
                  scoring.py   (0-100 score from results list)
```

### Check Modules (`src/apotrope/checks/`)

Each file is an independent audit module. Conventions:

- Expose a `run() -> list[CheckResult]` function (the scanner calls this)
- Never call `sys.exit()` or raise unhandled exceptions — return a result with
  `status=Status.ERROR` and the exception message in `details` instead
- All PowerShell / WMI / registry calls go through helpers in `utils.py`
- A single module may return multiple `CheckResult` objects

### `utils.py`

Shared helpers only. Key functions to build out:

- `run_powershell(script: str) -> str` — runs a PS snippet, returns stdout
- `read_registry(hive, key, value)` — reads a registry value safely
- `is_admin() -> bool` — checks for elevated privileges

### Data Model (`models.py`)

```python
@dataclass
class CheckResult:
    category: str       # e.g. "Firewall", "Encryption"
    check_name: str     # e.g. "Windows Firewall - Domain Profile"
    status: Status      # PASS | FAIL | WARN | INFO | ERROR
    severity: Severity  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str    # What is being verified
    details: str        # What was actually found
    remediation: str    # How to fix it (empty string if status is PASS)
```

## Check Categories (files in `checks/`)

| File | Category | Notes |
|------|----------|-------|
| `os_info.py` | System | Version, build, patch level |
| `updates.py` | Patching | Windows Update status |
| `firewall.py` | Firewall | All three profiles |
| `antivirus.py` | Antivirus | Defender / third-party AV |
| `encryption.py` | Encryption | BitLocker per drive |
| `accounts.py` | Accounts | Local users, admins, guest, password policy |
| `services.py` | Services | Risky/unnecessary running services |
| `network.py` | Network | Open ports, listening services |
| `startup.py` | Persistence | Startup programs, scheduled tasks |
| `smb.py` | File Sharing | SMBv1 disabled? Signing? |
| `rdp.py` | Remote Access | Enabled? NLA enforced? |
| `uac.py` | Access Control | UAC level |
| `powershell.py` | PowerShell | Execution policy, logging, constrained mode |
| `misc.py` | Hardening | AutoPlay, remote registry, LLMNR |

## Testing

- Framework: **pytest**
- Mock all subprocess / WMI / registry calls with `unittest.mock` so tests run on
  any OS (including Linux CI)
- Test files mirror the source: `tests/test_checks/test_firewall.py` etc.
- `tests/conftest.py` holds shared fixtures (sample `CheckResult`, mock PS output…)

## Target Platforms

- Windows 10 (21H2+) and Windows 11
- Windows Server 2019 and 2022

## Output Formats

- **Terminal**: Rich tables with color-coded status/severity
- **HTML**: Jinja2 template at `src/apotrope/templates/report.html.j2`
- **JSON**: Serialized `AuditReport` dataclass (use `dataclasses.asdict`)

## Scoring Logic (`scoring.py`)

Start at 100. Deduct points per failed/warned check weighted by severity:

| Outcome | Severity | Deduction |
|---------|----------|-----------|
| FAIL    | CRITICAL | −15       |
| FAIL    | HIGH     | −10       |
| FAIL    | MEDIUM   | −5        |
| FAIL    | LOW      | −2        |
| WARN    | CRITICAL | −7        |
| WARN    | HIGH     | −5        |
| WARN    | MEDIUM   | −2        |
| WARN    | LOW      | −1        |

Clamp to [0, 100]. INFO and ERROR results do not affect the score.

## Gstack

For all web browsing, use the `/browse` skill from gstack. Never use `mcp__claude-in-chrome__*` tools directly.

### Available Skills

- `/office-hours` — YC-style forcing questions for startup/product decisions
- `/plan-ceo-review` — CEO/founder-mode plan review
- `/plan-eng-review` — Eng manager-mode plan review
- `/plan-design-review` — Designer's eye plan review
- `/design-consultation` — Understand product and research the landscape
- `/design-shotgun` — Generate multiple AI design variants
- `/design-html` — Generate production-quality HTML
- `/review` — Pre-landing PR review
- `/ship` — Ship workflow: merge base, run tests, review diff
- `/land-and-deploy` — Merge PR, wait for CI and deploy
- `/canary` — Post-deploy canary monitoring
- `/benchmark` — Performance regression detection
- `/browse` — Fast headless browser for QA and dogfooding
- `/connect-chrome` — Launch GStack Browser (AI-controlled Chromium)
- `/qa` — Systematically QA test a web app and fix bugs
- `/qa-only` — Report-only QA testing
- `/design-review` — Designer's eye QA for visual issues
- `/setup-browser-cookies` — Import cookies from real Chromium into headless browser
- `/setup-deploy` — Configure deployment settings for `/land-and-deploy`
- `/setup-gbrain` — Configure gbrain settings
- `/retro` — Weekly engineering retrospective
- `/investigate` — Systematic debugging with root cause investigation
- `/document-release` — Post-ship documentation update
- `/document-generate` — Generate documentation
- `/codex` — OpenAI Codex CLI wrapper for code review and generation
- `/cso` — Chief Security Officer mode security audit
- `/autoplan` — Auto-review pipeline
- `/plan-devex-review` — Developer experience plan review
- `/devex-review` — Live developer experience audit
- `/careful` — Safety guardrails for destructive commands
- `/freeze` — Restrict file edits to a specific directory
- `/guard` — Full safety mode: destructive warnings + directory-scoped edits
- `/unfreeze` — Clear the freeze boundary set by `/freeze`
- `/gstack-upgrade` — Upgrade gstack to the latest version
- `/learn` — Manage project learnings
