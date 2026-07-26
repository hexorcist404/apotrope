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


class TestDestructiveRuleIsCaseInsensitive:
    """PowerShell resolves cmdlet names case-insensitively; the rule must too.

    `restart-computer -Force` reboots exactly as `Restart-Computer -Force` does.
    A case-sensitive denylist reads as protection while catching only the
    spelling its author happened to use.
    """

    def test_lowercase_reboot_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, "restart-computer -Force")]
        assert [v for v in lint_commands(planted) if v.rule == "destructive-command"]

    def test_mixed_case_tpm_clear_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, "clear-TPM")]
        assert [v for v in lint_commands(planted) if v.rule == "destructive-command"]


class TestDestructiveRuleCoversMoreThanReboots:
    """The denylist covers the whole class, not just the two forms that shipped."""

    def test_shutdown_exe_is_flagged(self) -> None:
        for spelling in ("shutdown /r /t 0", "shutdown.exe -s -t 0", "shutdown /g"):
            planted = [Command("fake.py", 1, spelling)]
            assert [v for v in lint_commands(planted) if v.rule == "destructive-command"], spelling

    def test_volume_and_bitlocker_teardown_is_flagged(self) -> None:
        for spelling in (
            "Disable-BitLocker -MountPoint 'C:'",
            "Format-Volume -DriveLetter D",
            "Clear-Disk -Number 1",
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2",
        ):
            planted = [Command("fake.py", 1, spelling)]
            assert [v for v in lint_commands(planted) if v.rule == "destructive-command"], spelling

    def test_autoreboot_update_is_flagged(self) -> None:
        planted = [Command(
            "fake.py", 1,
            "Install-Module PSWindowsUpdate -Force\nInstall-WindowsUpdate -AutoReboot",
        )]
        assert [v for v in lint_commands(planted) if v.rule == "destructive-command"]

    def test_ordinary_commands_are_not_flagged(self) -> None:
        # A rule that fires on safe commands gets silenced and then protects nothing.
        for safe in (
            "Set-NetFirewallProfile -Profile Domain -Enabled True",
            "Restart-Service -Name W32Time",           # a service, not the computer
            "Get-Tpm",
            "net accounts /minpwlen:14",
            "Update-MpSignature",
        ):
            planted = [Command("fake.py", 1, safe)]
            assert not [
                v for v in lint_commands(planted) if v.rule == "destructive-command"
            ], safe


class TestUnguardedNewItemForceRule:
    """`New-Item -Force` on the registry provider REPLACES the key.

    It deletes every value and subkey underneath. On a shared policy container
    that means destroying unrelated policy the operator never asked to touch.
    """

    _REG = r"$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Foo'" + "\n"

    def test_unguarded_registry_new_item_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._REG + "New-Item -Path $key -Force | Out-Null")]
        assert [v for v in lint_commands(planted) if v.rule == "unguarded-new-item-force"]

    def test_test_path_guard_clears_it(self) -> None:
        planted = [Command(
            "fake.py", 1,
            self._REG + "if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }",
        )]
        assert not [v for v in lint_commands(planted) if v.rule == "unguarded-new-item-force"]

    def test_commented_new_item_is_not_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._REG + "# New-Item -Path $key -Force")]
        assert not [v for v in lint_commands(planted) if v.rule == "unguarded-new-item-force"]

    def test_filesystem_new_item_is_not_flagged(self) -> None:
        # On the filesystem provider -Force creates parents; that is the
        # documented behaviour and not destructive of unrelated state.
        planted = [Command(
            "fake.py", 1, r'New-Item -Path "$env:TEMP\apotrope" -ItemType Directory -Force',
        )]
        assert not [v for v in lint_commands(planted) if v.rule == "unguarded-new-item-force"]

    def test_every_shipped_registry_create_is_guarded(self) -> None:
        # The real inventory, not a planted case: this is what would have caught
        # the AutoPlay block before it shipped.
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "unguarded-new-item-force"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestBitLockerKeyEscrowRule:
    """A recovery password the operator never sees is worse than no advice.

    Enable-BitLocker / Add-BitLockerKeyProtector return a volume object whose
    default table renders the protector TYPES; the 48-digit password lives in
    .KeyProtector[].RecoveryPassword and is never printed. The operator gets a
    success-looking table, keeps no copy, and the only surviving copy sits in
    volume metadata that the recovery prompt cannot read. One firmware update
    later, the disk is gone.
    """

    _CREATE = "Enable-BitLocker -MountPoint 'C:' -RecoveryPasswordProtector"

    def _fired(self, text):
        return [
            v for v in lint_commands([Command("fake.py", 1, text)])
            if v.rule == "bitlocker-no-key-escrow"
        ]

    def test_creating_without_surfacing_is_flagged(self) -> None:
        assert self._fired(self._CREATE)

    def test_protector_flag_alone_does_not_count_as_surfacing(self) -> None:
        # -RecoveryPasswordProtector contains the substring "RecoveryPassword".
        # If the rule matched that, every command would self-satisfy and the
        # rule would be permanently inert.
        assert self._fired(self._CREATE + "\nWrite-Host done")

    def test_readback_satisfies_it(self) -> None:
        assert not self._fired(
            self._CREATE
            + "\n$rp = (Get-BitLockerVolume -MountPoint 'C:').KeyProtector | "
              "Where-Object KeyProtectorType -eq 'RecoveryPassword'"
              "\n$rp | Format-List KeyProtectorId, RecoveryPassword"
        )

    def test_ad_escrow_satisfies_it(self) -> None:
        assert not self._fired(
            self._CREATE + "\nBackup-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $id"
        )

    def test_entra_escrow_satisfies_it(self) -> None:
        assert not self._fired(
            self._CREATE + "\nBackupToAAD-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $id"
        )

    def test_commented_readback_does_not_satisfy_it(self) -> None:
        # A commented escrow line is an inert manual step; it does not put the
        # key in the operator's hands.
        assert self._fired(
            self._CREATE + "\n# Backup-BitLockerKeyProtector -MountPoint 'C:'"
        )

    def test_commands_without_a_recovery_protector_are_untouched(self) -> None:
        for safe in (
            "Enable-BitLocker -MountPoint 'C:' -TpmProtector",
            "Get-BitLockerVolume",
            "Set-NetFirewallProfile -Profile Domain -Enabled True",
        ):
            assert not self._fired(safe), safe

    def test_every_shipped_bitlocker_command_surfaces_the_key(self) -> None:
        # The real inventory — this is the assertion that would have caught the
        # shipped commands before an operator lost a volume.
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "bitlocker-no-key-escrow"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]
