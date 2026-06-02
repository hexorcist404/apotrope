# Apotrope — Claude Code Project Context

## Git Commit Author

Always use these credentials for commits in this repo:

```
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
```

The `Co-Authored-By` trailer should also use this identity:
`Co-Authored-By: hexorcist404 <hexorcist404@pm.me>`

## Git Commit Author

Always use these credentials for commits in this repo:

```
git config user.name "hexorcist404"
git config user.email "hexorcist404@pm.me"
```

The `Co-Authored-By` trailer should also use this identity:
`Co-Authored-By: hexorcist404 <hexorcist404@pm.me>`

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
- **HTML**: Jinja2 template at `templates/report.html.j2`
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
