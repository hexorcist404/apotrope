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

from command_audit import Command, collect_commands, lint_commands


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


def test_destructive_command_rule_flags_tpm_clear_and_bare_reboot() -> None:
    planted = [
        Command("fake.py", 1, "Get-Tpm\nInitialize-Tpm -AllowClear -AllowPhysicalPresence"),
        Command("fake.py", 2, "Restart-Computer"),
        Command("fake.py", 3, "Clear-Tpm"),
    ]
    destructive = [v for v in lint_commands(planted) if v.rule == "destructive-command"]
    assert len(destructive) == 3


def test_commented_reboot_is_not_flagged_destructive() -> None:
    # A reboot kept as a comment is safe — the lint only inspects active lines.
    ok = [Command("fake.py", 1, "Set-ItemProperty -Path X -Name Y -Value 1\n# Restart-Computer")]
    assert not [v for v in lint_commands(ok) if v.rule == "destructive-command"]


class TestLocalizedFirewallSelectorRule:
    """Regression guard: -DisplayGroup must never come back."""

    def test_rule_flags_displaygroup_selectors(self):
        planted = [
            Command("fake.py", 1, "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'"),
            Command("fake.py", 2,
                    "Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -RemoteAddress LocalSubnet"),
        ]
        hits = [v for v in lint_commands(planted) if v.rule == "localized-firewall-selector"]
        assert len(hits) == 2

    def test_group_indirect_string_is_accepted(self):
        ok = [Command("fake.py", 1, "Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'")]
        assert not [v for v in lint_commands(ok) if v.rule == "localized-firewall-selector"]

    def test_new_rule_displayname_is_not_flagged(self):
        """-DisplayName *names* a rule being created; it is not a localized selector."""
        ok = [Command("fake.py", 1,
                      "New-NetFirewallRule -DisplayName 'Block inbound TCP 21 (Apotrope)' "
                      "-Direction Inbound -LocalPort 21 -Protocol TCP -Action Block")]
        assert not [v for v in lint_commands(ok) if v.rule == "localized-firewall-selector"]

    def test_commented_selector_is_ignored(self):
        ok = [Command("fake.py", 1, "# Set-NetFirewallRule -DisplayGroup 'Remote Desktop'")]
        assert not [v for v in lint_commands(ok) if v.rule == "localized-firewall-selector"]


class TestUnresolvedExpressionRule:
    """A '{expr}' in collected text means the real command was never linted."""

    def test_rule_flags_unresolved_expression(self):
        planted = [Command("fake.py", 1, "Set-ItemProperty -Path 'X'\n{expr}")]
        hits = [v for v in lint_commands(planted) if v.rule == "unresolved-expression"]
        assert len(hits) == 1

    def test_real_inventory_has_no_unresolved_expressions(self):
        """Guards the policy-aware `A if cond else B` conditionals in rdp.py."""
        bad = [v for v in lint_commands(collect_commands())
               if v.rule == "unresolved-expression"]
        assert not bad, bad
