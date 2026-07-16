"""Static inventory + lint of every remediation command Apotrope emits.

`collect_commands()` walks the check modules' AST and returns every string
assigned to a ``command`` (as a ``command=`` keyword on a ``CheckResult`` or as a
``command = ...`` local/const assignment), resolving module-level constants,
f-strings, string concatenation, and ``"" if cond else ...`` expressions. Runtime
interpolations (``{port}``, ``{mount}``, ...) are preserved as ``{name}`` placeholders.

`lint_commands()` flags the structural defects that shipped broken remediation in
≤ v0.1.12 — patterns a substring test can never catch:

* CIM-instance method calls — ``(Get-CimInstance ...).Method(...)`` (inert objects
  have no callable methods; use ``Invoke-CimMethod``).
* ``New-NetFirewallRule`` without ``-DisplayName`` (hangs on a mandatory-param prompt).
* An uncommented ``Install-WindowsUpdate`` with no ``Install-Module`` bootstrap
  (the module is not installed by default → "not recognized").
* ``<placeholder>`` angle-bracket tokens (PowerShell parses ``<...>`` as redirection).

Used by ``tests/test_remediation_commands.py`` (CI, cross-platform) and by
``tools/verify_commands.py`` (Windows: PowerShell syntax + cmdlet resolution).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

CHECKS_DIR = Path(__file__).resolve().parents[1] / "src" / "apotrope" / "checks"


@dataclass(frozen=True)
class Command:
    """A single resolved remediation-command template."""

    module: str
    line: int
    text: str


@dataclass(frozen=True)
class Violation:
    """A lint failure against one command."""

    module: str
    line: int
    rule: str
    detail: str
    command: str


# --------------------------------------------------------------------------- #
# AST resolution
# --------------------------------------------------------------------------- #

def _collect_constants(tree: ast.Module) -> dict[str, str]:
    """Map ``NAME = <string|number expr>`` assignments (module- or function-level) to text.

    Resolves in source order so an earlier constant is available to a later one. Numeric
    constants (e.g. ``_MIN_PW_TARGET = 14``) are captured as their string form so they
    resolve inside f-strings; ``command`` targets are skipped (handled separately).
    """
    consts: dict[str, str] = {}
    assigns = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id != "command"
    ]
    for node in sorted(assigns, key=lambda n: n.lineno):
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, (str, int, float, bool)):
            consts[node.targets[0].id] = str(value.value)
        else:
            resolved = _resolve(value, consts)
            if resolved is not None:
                consts[node.targets[0].id] = resolved
    return consts


def _placeholder(node: ast.AST, consts: dict[str, str]) -> str:
    """Render a non-literal sub-expression as a ``{name}`` placeholder (or its const value)."""
    if isinstance(node, ast.Name):
        return consts.get(node.id, "{" + node.id + "}")
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute):
        return "{" + node.attr + "}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return "{" + node.func.attr + "}"
    return "{expr}"


def _resolve(node: ast.AST, consts: dict[str, str]) -> str | None:
    """Resolve a string-valued AST node to text with ``{placeholders}``; None if not a string."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):  # f-string
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append(_placeholder(value.value, consts))
            else:
                parts.append("{expr}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve(node.left, consts)
        right = _resolve(node.right, consts)
        if left is None:
            left = _placeholder(node.left, consts)
        if right is None:
            right = _placeholder(node.right, consts)
        return left + right
    return None


def _resolve_branches(node: ast.AST, consts: dict[str, str]) -> list[str]:
    """Resolve a command expression, expanding ``a if cond else b`` into both arms."""
    if isinstance(node, ast.IfExp):
        out: list[str] = []
        for arm in (node.body, node.orelse):
            out.extend(_resolve_branches(arm, consts))
        return out
    resolved = _resolve(node, consts)
    return [resolved] if resolved is not None else []


def collect_commands() -> list[Command]:
    """Return every distinct remediation command emitted by the check modules."""
    commands: list[Command] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(CHECKS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        consts = _collect_constants(tree)

        # Every `command=` keyword on any call, plus every `command = ...` assignment
        # (checks that build the string in a local variable before passing it on).
        exprs: list[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "command":
                        exprs.append(kw.value)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "command":
                        exprs.append(node.value)

        for expr in exprs:
            for text in _resolve_branches(expr, consts):
                if not text or not text.strip():
                    continue
                key = (path.name, text)
                if key in seen:
                    continue
                seen.add(key)
                commands.append(Command(module=path.name, line=expr.lineno, text=text))
    return commands


# --------------------------------------------------------------------------- #
# Lint rules
# --------------------------------------------------------------------------- #

_CIM_METHOD = re.compile(r"\)\s*\.\s*[A-Za-z_]\w*\s*\(")
# angle-bracket placeholder, but NOT a regex named group `(?<name>...)`
_ANGLE_PLACEHOLDER = re.compile(r"(?<!\?)<[A-Za-z_][\w -]*>")


def _uncommented_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def lint_commands(commands: list[Command]) -> list[Violation]:
    """Return every structural defect found across *commands* (empty == all clean)."""
    violations: list[Violation] = []
    for cmd in commands:
        text = cmd.text
        active = "\n".join(_uncommented_lines(text))

        if "Get-CimInstance" in active and _CIM_METHOD.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "cim-method-call",
                "method call on a Get-CimInstance result — use Invoke-CimMethod",
                text,
            ))
        if "New-NetFirewallRule" in active and "-DisplayName" not in active:
            violations.append(Violation(
                cmd.module, cmd.line, "firewall-rule-no-displayname",
                "New-NetFirewallRule without -DisplayName hangs on a mandatory-param prompt",
                text,
            ))
        if "Install-WindowsUpdate" in active and "Install-Module" not in active:
            violations.append(Violation(
                cmd.module, cmd.line, "bare-install-windowsupdate",
                "Install-WindowsUpdate with no Install-Module bootstrap (module absent by default)",
                text,
            ))
        if _ANGLE_PLACEHOLDER.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "angle-bracket-placeholder",
                "<...> placeholder is parsed as a redirection operator by PowerShell",
                text,
            ))
    return violations


if __name__ == "__main__":
    cmds = collect_commands()
    print(f"collected {len(cmds)} commands from {CHECKS_DIR}")
    for v in lint_commands(cmds):
        print(f"  [{v.rule}] {v.module}:{v.line} — {v.detail}")
