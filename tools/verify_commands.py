"""Windows pre-release harness: verify every remediation command actually runs.

For each command Apotrope can emit (from :func:`tools.command_audit.collect_commands`),
this:

1. Substitutes runtime placeholders (``{port}``, ``{mount}``, ...) with sample values.
2. Parses it with the PowerShell language parser — catching syntax errors (e.g. a
   ``<placeholder>`` that PowerShell reads as a redirection operator).
3. Enumerates every command/cmdlet/native tool the parse tree invokes and confirms
   each resolves via ``Get-Command`` — catching cmdlets from modules that are not
   installed (e.g. ``Install-WindowsUpdate``).

Comment lines are ignored (they never execute). This is the Windows counterpart to
the cross-platform static lint in ``tests/test_remediation_commands.py``; run it on a
real Windows box before tagging a release (Linux CI cannot run PowerShell).

Usage:  python tools/verify_commands.py
Exit code 0 == every command parses and every invoked command resolves.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from command_audit import collect_commands

# Sample values for the runtime interpolations in command templates.
_PLACEHOLDERS = {
    "{port}": "445",
    "{mount}": "D:",
    "{name}": "SampleAdmin",
    "{count}": "3",
    # Deliberately a name containing a space: auditpol subcategories all do, and
    # an unquoted expansion would parse as two arguments.
    "{subcategory}": "Sensitive Privilege Use",
}

# PowerShell that parses each command and resolves every invoked command name.
# Command resolution is done against a single upfront enumeration of every available
# command (loaded + auto-discoverable modules + PATH applications) rather than a
# per-name Get-Command in the loop, which can non-deterministically miss an
# auto-loadable core cmdlet inside a long-running runspace.
_PS_VERIFY = r"""
$items = Get-Content -LiteralPath $env:APOTROPE_CMD_FILE -Raw | ConvertFrom-Json
$available = @{}
Get-Command -CommandType Cmdlet,Function,Alias,Filter,Application -ErrorAction SilentlyContinue |
    ForEach-Object { $available[$_.Name.ToLower()] = $true }
function Resolves([string]$name) {
    $key = $name.ToLower()
    if ($available.ContainsKey($key)) { return $true }
    if ($available.ContainsKey("$key.exe")) { return $true }   # native tool listed as name.exe
    return [bool](Get-Command -Name $name -ErrorAction SilentlyContinue)
}
$fail = 0
foreach ($item in $items) {
    $text = $item.text
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errs)
    $label = "$($item.module):$($item.line)"
    if ($errs.Count -gt 0) {
        $fail++
        Write-Output "SYNTAX-FAIL  $label  $($errs[0].Message)"
        continue
    }
    $cmdAsts = $ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    $missing = @()
    foreach ($ca in $cmdAsts) {
        $name = $ca.GetCommandName()
        if ($name -and -not (Resolves $name)) { $missing += $name }
    }
    if ($missing.Count -gt 0) {
        $fail++
        Write-Output "CMDLET-FAIL  $label  unresolved: $($missing -join ', ')"
    } else {
        Write-Output "OK           $label"
    }
}
Write-Output "---"
Write-Output "FAILURES=$fail  TOTAL=$($items.Count)"
if ($fail -gt 0) { exit 1 } else { exit 0 }
"""


def _substitute(text: str) -> str:
    for token, value in _PLACEHOLDERS.items():
        text = text.replace(token, value)
    return text


def main() -> int:
    commands = collect_commands()
    payload = [
        {"module": c.module, "line": c.line, "text": _substitute(c.text)}
        for c in commands
    ]

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump(payload, fh)
        cmd_file = fh.name

    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_VERIFY],
        env={**__import__("os").environ, "APOTROPE_CMD_FILE": cmd_file},
        capture_output=True,
        text=True,
        # Explicitly False, never True: the return code is this script's own
        # exit code (see main()), so check=True would turn a reported command
        # failure into a CalledProcessError traceback in the CI step.
        check=False,
    )
    print(proc.stdout)
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
