"""Guard: validate every shipped command with PowerShell's OWN parser.

``tools/command_audit.py`` matches text with regular expressions, and the
review history of this repository is a list of PowerShell spellings that text
matching got wrong: quoted tokens, backtick escapes that differ per edition,
statement splices, guard-shaped strings, indirect invocation through ``&``.
Each fix narrowed the approximation; none of them made it a parser.

So this module stops approximating. It hands the command text to
``[System.Management.Automation.Language.Parser]::ParseInput`` — the same
parser that will run it — and asserts against the real tree:

* every command invocation names its executable **directly** (no call
  operator, no variable, no computed name), because an indirect invocation is
  one a static guard cannot correlate with an exit-code check;
* every ``reg.exe add`` is immediately followed, in its own statement list, by
  ``if ($LASTEXITCODE -ne 0) { throw ... }`` — adjacency as a tree relation,
  not as neighbouring lines of text;
* every ``auditpol`` invocation is the canonical enable shape.

The negative controls at the bottom run the same assertions over the exact
strings that slipped past the text lint in earlier rounds. They must fail —
otherwise the checks above prove nothing.

Windows-only, and it reaches a real PowerShell — hence ``allow_subprocess``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from command_audit import collect_commands

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser"),
    pytest.mark.allow_subprocess,
]

#: Emits one JSON object per command: parse errors, plus a record of every
#: CommandAst — how it was invoked, how its name was written, its elements,
#: and whether the next statement in its own list is the exit-code guard.
_ANALYZER = r"""
$ErrorActionPreference = 'Stop'
$commands = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @()
foreach ($entry in $commands) {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $entry.text, [ref]$null, [ref]$errors)
    $found = @()
    $nodes = $ast.FindAll({
        param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($node in $nodes) {
        $head = $node.CommandElements[0]
        # The statement list this command belongs to, so "the next statement"
        # is a tree relation rather than the next line of text.
        $pipeline = $node.Parent
        $guarded = $false
        if ($pipeline -and $pipeline.Parent -and
            $pipeline.Parent.PSObject.Properties['Statements']) {
            $siblings = $pipeline.Parent.Statements
            $index = $siblings.IndexOf($pipeline)
            if ($index -ge 0 -and $index + 1 -lt $siblings.Count) {
                $next = $siblings[$index + 1]
                if ($next -is [System.Management.Automation.Language.IfStatementAst]) {
                    $cond = $next.Clauses[0].Item1.Extent.Text
                    $body = $next.Clauses[0].Item2.Extent.Text
                    $guarded = ($cond -match '\$LASTEXITCODE\s+-ne\s+0') -and
                               ($body -match '\bthrow\b')
                }
            }
        }
        $found += [pscustomobject]@{
            invocationOperator = [string]$node.InvocationOperator
            headType           = $head.GetType().Name
            name               = if ($head -is
                [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $head.Value } else { $null }
            elements           = @($node.CommandElements | ForEach-Object { $_.Extent.Text })
            guardedNext        = $guarded
        }
    }
    $out += [pscustomobject]@{
        id       = $entry.id
        errors   = @($errors | ForEach-Object { $_.Message })
        commands = @($found)
    }
}
$out | ConvertTo-Json -Depth 8 -Compress
"""


def _parse(entries: list[dict[str, str]]) -> dict[str, dict]:
    """Return {id: analysis} for each {'id', 'text'} entry, via PowerShell."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _ANALYZER],
        input=json.dumps(entries), capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    if isinstance(parsed, dict):  # ConvertTo-Json unwraps a single element
        parsed = [parsed]
    return {item["id"]: item for item in parsed}


@pytest.fixture(scope="module")
def analysis() -> dict[str, dict]:
    """Every shipped command, parsed once — one PowerShell process for all 48."""
    entries = [
        {"id": f"{c.module}:{c.line}", "text": c.text} for c in collect_commands()
    ]
    assert len(entries) >= 30, f"inventory collapsed to {len(entries)} commands"
    return _parse(entries)


def test_every_command_parses(analysis) -> None:
    broken = {cid: item["errors"] for cid, item in analysis.items() if item["errors"]}
    assert not broken, broken


def test_every_invocation_names_its_executable_directly(analysis) -> None:
    # An indirect invocation — `& $exe add ...`, `& ('re' + 'g.exe') add ...` —
    # runs the same program while defeating any static correlation between the
    # call and its exit-code check. The rule is structural: the command name
    # must be a literal in the source.
    indirect = [
        (cid, cmd["invocationOperator"], cmd["headType"])
        for cid, item in analysis.items()
        for cmd in item["commands"]
        if cmd["invocationOperator"] != "Unknown"
        or cmd["headType"] != "StringConstantExpressionAst"
    ]
    assert not indirect, indirect


def test_every_reg_add_is_followed_by_the_exit_code_guard(analysis) -> None:
    # reg.exe reports failure through the exit code only, so the guard must be
    # the very next statement — before anything can overwrite $LASTEXITCODE.
    adds = [
        (cid, cmd)
        for cid, item in analysis.items()
        for cmd in item["commands"]
        if (cmd["name"] or "").lower() in {"reg", "reg.exe"}
        and len(cmd["elements"]) > 1
        and cmd["elements"][1].strip().lower() == "add"
    ]
    assert adds, "no reg.exe add invocations found — the check would be vacuous"
    unguarded = [cid for cid, cmd in adds if not cmd["guardedNext"]]
    assert not unguarded, unguarded


def test_every_auditpol_invocation_is_the_enable_shape(analysis) -> None:
    invocations = [
        (cid, cmd["elements"])
        for cid, item in analysis.items()
        for cmd in item["commands"]
        if (cmd["name"] or "").lower() == "auditpol"
    ]
    assert invocations, "no auditpol invocations found — the check would be vacuous"
    for cid, elements in invocations:
        assert elements[1:2] == ["/set"], (cid, elements)
        assert elements[2].lower().startswith("/subcategory:"), (cid, elements)
        assert [e.lower() for e in elements[3:]] == ["/success:enable", "/failure:enable"], (
            cid, elements
        )


# ── Negative controls ────────────────────────────────────────────────────────
#
# The exact strings that passed the text lint in earlier rounds. If the
# assertions above cannot reject these, they are not testing anything.

_INDIRECT = [
    pytest.param("$e = 'reg.exe'\n& $e add \"HKXX\\S\" /v A /f", id="variable-name"),
    pytest.param("& ('re' + 'g.exe') add \"HKXX\\S\" /v A /f", id="split-literal"),
    pytest.param(
        "& ('audit' + 'pol') /set /subcategory:'Logon' /success:disable /failure:disable",
        id="split-literal-auditpol",
    ),
]


@pytest.mark.parametrize("text", _INDIRECT)
def test_the_parser_rejects_indirect_invocations(text) -> None:
    item = _parse([{"id": "probe", "text": text}])["probe"]
    assert any(
        cmd["invocationOperator"] != "Unknown"
        or cmd["headType"] != "StringConstantExpressionAst"
        for cmd in item["commands"]
    ), "an indirect invocation was seen as a direct one"


def test_the_parser_sees_an_unguarded_add_after_a_guard_prefix() -> None:
    # `<guard>; reg.exe add ...` — the text lint exempted the whole line for a
    # while. In the tree the appended command is its own statement with no
    # following guard.
    text = (
        'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed" }\n'
        'reg.exe add "HKXX\\S" /v A /f'
    )
    item = _parse([{"id": "probe", "text": text}])["probe"]
    adds = [c for c in item["commands"] if (c["name"] or "").lower() == "reg.exe"]
    assert adds and not any(c["guardedNext"] for c in adds)


def test_a_guarded_add_is_recognised_as_guarded() -> None:
    # The positive half: the shipped layout must satisfy the same check, or
    # the test above would pass for the wrong reason.
    text = (
        'reg.exe add "HKLM\\S" /v A /t REG_DWORD /d 1 /f\n'
        'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }'
    )
    item = _parse([{"id": "probe", "text": text}])["probe"]
    adds = [c for c in item["commands"] if (c["name"] or "").lower() == "reg.exe"]
    assert adds and all(c["guardedNext"] for c in adds)
