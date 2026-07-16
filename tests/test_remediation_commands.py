"""Guard: every remediation command Apotrope emits must be structurally sound.

The per-check tests assert command *substrings* (``"Disable-LocalUser" in r.command``);
they cannot catch a command that fails to *run* — a method call on an inert
``Get-CimInstance`` object, a ``New-NetFirewallRule`` missing its mandatory
``-DisplayName``, a cmdlet from a module that isn't installed by default, or a
``<placeholder>`` that PowerShell parses as a redirection operator. Exactly those
defects shipped broken remediation in ≤ v0.1.12.

This test statically extracts every command the check modules can emit and lints it
against those failure classes (see ``tools/command_audit.py``). It is the
cross-platform CI counterpart to the Windows-only ``tools/verify_commands.py``
harness, which additionally parses each command with PowerShell and resolves every
cmdlet it invokes.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from command_audit import collect_commands, lint_commands  # noqa: E402


def test_command_inventory_is_populated() -> None:
    """The AST extractor must find the full command inventory.

    Guards against a silent extraction regression that would make the lint below
    pass vacuously (zero commands == zero violations).
    """
    commands = collect_commands()
    assert len(commands) >= 30, (
        f"expected the full remediation-command inventory, extracted only {len(commands)} "
        "— did the AST extraction in tools/command_audit.py break?"
    )


def test_no_broken_remediation_commands() -> None:
    """No emitted remediation command may match a known runtime-failure pattern."""
    violations = lint_commands(collect_commands())
    if violations:
        report = "\n".join(
            f"  [{v.rule}] {v.module}:{v.line} — {v.detail}\n      {v.command!r}"
            for v in violations
        )
        raise AssertionError(
            f"{len(violations)} remediation command(s) match a runtime-failure pattern:\n{report}"
        )
