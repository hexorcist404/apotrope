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
    """Return {id: analysis} for each {'id', 'text'} entry, via PowerShell.

    The result is keyed by id, so a duplicate id would silently collapse two
    commands into one and shrink what every assertion in this module covers —
    the quiet coverage loss the whole guard exists to prevent. All three id
    invariants live here so every caller inherits them.
    """
    submitted = [entry["id"] for entry in entries]
    assert len(set(submitted)) == len(submitted), (
        "duplicate ids submitted: "
        f"{sorted({i for i in submitted if submitted.count(i) > 1})}"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _ANALYZER],
        input=json.dumps(entries), capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    if isinstance(parsed, dict):  # ConvertTo-Json unwraps a single element
        parsed = [parsed]

    analysed = {item["id"]: item for item in parsed}
    assert len(parsed) == len(entries), (
        f"parsed {len(parsed)} commands from {len(entries)} submitted"
    )
    assert set(analysed) == set(submitted), (
        f"ids came back changed: missing {set(submitted) - set(analysed)}, "
        f"unexpected {set(analysed) - set(submitted)}"
    )
    return analysed


@pytest.fixture(scope="module")
def analysis() -> dict[str, dict]:
    """Every shipped command, parsed once — one PowerShell process for all 48.

    Ids carry an ordinal because ``module:line`` is not unique: a conditional
    command expression (``A if cond else B``, as rdp.py uses) resolves to two
    commands on the same source line.
    """
    entries = [
        {"id": f"{c.module}:{c.line}#{ordinal}", "text": c.text}
        for ordinal, c in enumerate(collect_commands())
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


#: Commands that take another command as string data and run it. Their child
#: is invisible to every check in this file — the tree shows the broker, and
#: the real command sits inside an argument PowerShell never parses.
#: Start-Process is judged on its arguments instead: updates.py legitimately
#: opens a URI with it, which carries no child command.
_BROKERS = frozenset(
    {"invoke-expression", "iex", "invoke-command", "icm", "cmd",
     "powershell", "pwsh", "start-process", "saps", "start"}
)


def _normalized_command(token: str) -> str:
    """A command name reduced to the program it runs (see command_audit)."""
    base = token.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _is_broker(cmd: dict) -> bool:
    # Same normalization the text lint uses: an alias, a module qualifier
    # (Microsoft.PowerShell.Management\Start-Process) and a full path
    # (C:\Windows\System32\cmd.exe) all name the same program, so the name is
    # reduced before it is classified rather than matched spelling by spelling.
    raw = cmd["name"] or ""
    if _normalized_command(raw) not in _BROKERS:
        return False
    # The one reviewed launcher, permitted only as its literal shipped form:
    # not an alias, not another Settings page, and with nothing else on it.
    return not (
        raw == "Start-Process"
        and [e.strip() for e in cmd["elements"]]
        == ["Start-Process", "'ms-settings:windowsupdate'"]
    )


def test_no_command_runs_through_an_execution_broker(analysis) -> None:
    brokers = [
        (cid, cmd["name"], cmd["elements"])
        for cid, item in analysis.items()
        for cmd in item["commands"]
        if _is_broker(cmd)
    ]
    assert not brokers, brokers


# ── Controls ─────────────────────────────────────────────────────────────────
#
# Four negative controls — the exact strings that passed the text lint in
# earlier rounds — and one positive control, so the assertions above cannot
# pass vacuously. All of them are parsed in ONE PowerShell process alongside
# each other: a process launch dominates the runtime of this file, and
# spawning one per case cost ~70s on the CI Windows runner.

_CONTROLS = {
    "indirect-variable-name": "$e = 'reg.exe'\n& $e add \"HKXX\\S\" /v A /f",
    "indirect-split-literal": "& ('re' + 'g.exe') add \"HKXX\\S\" /v A /f",
    "indirect-split-literal-auditpol": (
        "& ('audit' + 'pol') /set /subcategory:'Logon' /success:disable /failure:disable"
    ),
    "unguarded-add-after-guard-prefix": (
        'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed" }\n'
        'reg.exe add "HKXX\\S" /v A /f'
    ),
    "broker-start-process": (
        "Start-Process -FilePath reg.exe -ArgumentList 'add HKXX\\S /v A /f' -Wait"
    ),
    "broker-invoke-expression": "Invoke-Expression 'reg.exe add HKXX\\S /v A /f'",
    "broker-nested-powershell": "powershell.exe -Command 'reg.exe add HKXX\\S /v A /f'",
    # Spellings that reach the same programs by other names.
    "broker-module-qualified": (
        "Microsoft.PowerShell.Management\\Start-Process reg 'add HKXX\\S /v A /f'"
    ),
    "broker-full-path-cmd": "C:\\Windows\\System32\\cmd.exe /c 'reg.exe add HKXX\\S /v A /f'",
    "broker-alias-saps": "saps reg 'add HKXX\\S /v A /f'",
    "broker-alias-icm": "icm -FilePath C:\\temp\\fix.ps1",
    # The permit is the reviewed command, not the URI scheme or an alias.
    "broker-other-settings-uri": "Start-Process 'ms-settings:privacy-webcam'",
    "broker-alias-with-shipped-uri": "saps 'ms-settings:windowsupdate'",
    # The shipped launcher itself, which must NOT be treated as a broker.
    "permitted-uri-launch": "Start-Process 'ms-settings:windowsupdate'",
    # The positive control: the shipped layout must SATISFY the guard check.
    "guarded-add": (
        'reg.exe add "HKLM\\S" /v A /t REG_DWORD /d 1 /f\n'
        'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }'
    ),
}


@pytest.fixture(scope="module")
def controls() -> dict[str, dict]:
    """Every control case, parsed in a single PowerShell process."""
    return _parse([{"id": cid, "text": text} for cid, text in _CONTROLS.items()])


@pytest.mark.parametrize(
    "case",
    ["indirect-variable-name", "indirect-split-literal", "indirect-split-literal-auditpol"],
)
def test_the_parser_rejects_indirect_invocations(controls, case) -> None:
    assert any(
        cmd["invocationOperator"] != "Unknown"
        or cmd["headType"] != "StringConstantExpressionAst"
        for cmd in controls[case]["commands"]
    ), "an indirect invocation was seen as a direct one"


def test_the_parser_sees_an_unguarded_add_after_a_guard_prefix(controls) -> None:
    # `<guard>` then `reg.exe add ...` — the text lint exempted the whole line
    # for a while. In the tree the add is its own statement with no guard after.
    item = controls["unguarded-add-after-guard-prefix"]
    adds = [c for c in item["commands"] if (c["name"] or "").lower() == "reg.exe"]
    assert adds and not any(c["guardedNext"] for c in adds)


@pytest.mark.parametrize(
    "case",
    [
        "broker-start-process",
        "broker-invoke-expression",
        "broker-nested-powershell",
        "broker-module-qualified",
        "broker-full-path-cmd",
        "broker-alias-saps",
        "broker-alias-icm",
        "broker-other-settings-uri",
        "broker-alias-with-shipped-uri",
    ],
)
def test_the_broker_check_rejects_wrappers(controls, case) -> None:
    assert any(_is_broker(cmd) for cmd in controls[case]["commands"]), (
        "a wrapped child command was not recognised as brokered"
    )


def test_the_shipped_uri_launcher_is_not_a_broker(controls) -> None:
    # The positive half of the broker check: the one reviewed launcher must
    # pass, or the assertions above would be satisfied by rejecting everything.
    assert not any(
        _is_broker(cmd) for cmd in controls["permitted-uri-launch"]["commands"]
    )


def test_duplicate_ids_are_rejected_rather_than_collapsed() -> None:
    # Keying by id means two entries sharing one would silently become a
    # single analysed command, shrinking coverage without any test failing.
    with pytest.raises(AssertionError, match="duplicate ids"):
        _parse([
            {"id": "dup", "text": 'reg.exe add "HKXX\\S" /v A /f'},
            {"id": "dup", "text": "Write-Host fine"},
        ])


def test_a_guarded_add_is_recognised_as_guarded(controls) -> None:
    # The positive control: the shipped layout must satisfy the same check, or
    # the negative ones would pass for the wrong reason.
    item = controls["guarded-add"]
    adds = [c for c in item["commands"] if (c["name"] or "").lower() == "reg.exe"]
    assert adds and all(c["guardedNext"] for c in adds)
