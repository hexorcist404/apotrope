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

import pytest

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


def test_backtick_split_destructive_name_is_flagged() -> None:
    # Outside the named escape sequences, a backtick before a character IS that
    # character to PowerShell's tokenizer: Restart-`Computer executes exactly as
    # Restart-Computer while reading past any pattern matching the raw text.
    planted = [
        Command("fake.py", 1, "Restart-`Computer -Force"),
        Command("fake.py", 2, "Clear-Tp`m"),
    ]
    destructive = [v for v in lint_commands(planted) if v.rule == "destructive-command"]
    assert len(destructive) == 2


def test_a_real_escape_sequence_is_not_misread_as_a_word() -> None:
    # `n IS a newline, so "shutdow`n" executes as "shutdow" + newline — treating
    # it as the word "shutdown" would be a false positive.
    ok = [Command("fake.py", 1, "shutdow`n /r")]
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


class TestRegistryNewItemForceRule:
    """`New-Item -Force` on the registry provider REPLACES the key.

    It deletes every value and subkey underneath. On a shared policy container
    that means destroying unrelated policy the operator never asked to touch.

    A `Test-Path` guard used to clear this rule. It no longer does: the test and
    the create are two operations, so a key created in the window between them
    is still replaced, losing exactly the values the guard existed to protect.
    """

    _REG = r"$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Foo'" + "\n"

    def test_unguarded_registry_new_item_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._REG + "New-Item -Path $key -Force | Out-Null")]
        assert [v for v in lint_commands(planted) if v.rule == "registry-new-item-force"]

    def test_test_path_guard_no_longer_clears_it(self) -> None:
        # The racy form the rule used to prescribe.
        planted = [Command(
            "fake.py", 1,
            self._REG + "if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }",
        )]
        assert [v for v in lint_commands(planted) if v.rule == "registry-new-item-force"]

    def test_backtick_continuation_does_not_hide_force(self) -> None:
        # A trailing backtick continues the statement onto the next physical
        # line. A per-line rule that stops at the newline never sees the -Force.
        planted = [Command(
            "fake.py", 1,
            self._REG + "New-Item -Path $key `\n  -Force | Out-Null",
        )]
        assert [v for v in lint_commands(planted) if v.rule == "registry-new-item-force"]

    def test_reg_exe_add_is_accepted(self) -> None:
        # The prescribed remedy: writes the value, creates missing parents,
        # touches nothing else, and runs under Constrained Language Mode.
        planted = [Command(
            "fake.py", 1,
            'reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Foo" '
            "/v Enabled /t REG_DWORD /d 1 /f\n"
            'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }',
        )]
        assert not lint_commands(planted)

    def test_commented_new_item_is_not_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._REG + "# New-Item -Path $key -Force")]
        assert not [v for v in lint_commands(planted) if v.rule == "registry-new-item-force"]

    def test_filesystem_new_item_is_not_flagged(self) -> None:
        # On the filesystem provider -Force creates parents; that is the
        # documented behaviour and not destructive of unrelated state.
        planted = [Command(
            "fake.py", 1, r'New-Item -Path "$env:TEMP\apotrope" -ItemType Directory -Force',
        )]
        assert not [v for v in lint_commands(planted) if v.rule == "registry-new-item-force"]

    def test_no_shipped_command_creates_a_registry_key_with_new_item(self) -> None:
        # The real inventory, not a planted case.
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "registry-new-item-force"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestRegAddExitCodeRule:
    """A `reg add` with no exit-code check hides its own failure.

    reg.exe reports a denied or malformed write through the exit code, not a
    PowerShell error, so without an immediate `$LASTEXITCODE` check the
    operator sees the same silence for success and failure. Every shipped
    registry write pairs the add with `if ($LASTEXITCODE -ne 0) { throw ... }`
    on the very next line; this rule keeps future ones honest.
    """

    _ADD = 'reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Foo" /v Enabled /t REG_DWORD /d 1 /f'
    _CHECK = 'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }'

    def test_unchecked_reg_add_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._ADD)]
        assert [v for v in lint_commands(planted) if v.rule == "reg-add-unchecked-exit-code"]

    def test_bare_reg_add_without_exe_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._ADD.replace("reg.exe", "reg"))]
        assert [v for v in lint_commands(planted) if v.rule == "reg-add-unchecked-exit-code"]

    def test_an_immediate_exit_check_is_clean(self) -> None:
        planted = [Command("fake.py", 1, self._ADD + "\n" + self._CHECK)]
        assert not lint_commands(planted)

    def test_a_check_two_lines_later_is_flagged(self) -> None:
        # $LASTEXITCODE holds the LAST native exit code; anything that runs in
        # between can overwrite it, so only the immediately following line
        # counts as a check.
        planted = [Command("fake.py", 1, self._ADD + "\nWrite-Output done\n" + self._CHECK)]
        assert [v for v in lint_commands(planted) if v.rule == "reg-add-unchecked-exit-code"]

    def test_the_error_message_is_not_read_as_an_invocation(self) -> None:
        # The throw message says "reg.exe add failed" — a substring match would
        # count it as a second, unchecked invocation and flag every compliant
        # command in the tree.
        planted = [Command("fake.py", 1, self._ADD + "\n" + self._CHECK)]
        assert not [v for v in lint_commands(planted) if v.rule == "reg-add-unchecked-exit-code"]

    def test_no_shipped_reg_add_lacks_an_exit_check(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "reg-add-unchecked-exit-code"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestRiskyServiceInventory:
    """The risky-service commands must stay inside the inventory.

    They lived in a dict of positional tuples, which the AST collector cannot
    read: `services.py` contributed exactly one command to a 44-command
    inventory, and it was the unquoted-ImagePath block. The four
    Stop-Service/Set-Service commands were therefore never linted here and never
    PowerShell-parsed by tools/verify_commands.py.

    Naming the NamedTuple fields is what fixes that — `collect_commands()`
    collects every `command=` keyword on any call. Revert those to positional
    arguments and the commands silently vanish again, which is what these tests
    exist to prevent.
    """

    _EXPECTED = {"RemoteRegistry", "TlntSvr", "Telnet", "SNMP"}

    def test_every_risky_service_command_is_collected(self) -> None:
        collected = [
            c for c in collect_commands()
            if c.module == "services.py" and "Stop-Service" in c.text
        ]
        named = {
            svc for svc in self._EXPECTED
            if any(f"'{svc}'" in c.text for c in collected)
        }
        assert named == self._EXPECTED, f"missing from the inventory: {self._EXPECTED - named}"

    def test_collected_text_matches_what_the_check_emits(self) -> None:
        # Not merely "a command mentioning the service" — the exact text the
        # module ships, so a drifting copy in the inventory is a failure.
        from apotrope.checks.services import _RISKY

        inventory = {c.text for c in collect_commands() if c.module == "services.py"}
        for svc, risky in _RISKY.items():
            assert risky.command in inventory, f"{svc}: emitted command is not in the inventory"

    def test_risky_service_commands_are_lint_clean(self) -> None:
        from apotrope.checks.services import _RISKY

        planted = [
            Command("services.py", 0, risky.command) for risky in _RISKY.values()
        ]
        assert lint_commands(planted) == []


class TestAuditpolEnableShapeRule:
    """Remediation exists to increase coverage, not reduce it.

    The disabling form reads almost identically to the enabling one, so a
    copy-edit slip produces a command that looks right and silences the log it
    was supposed to turn on.
    """

    _ENABLE = "auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable"
    _DISABLE = _ENABLE.replace("enable", "disable")

    def test_disabling_command_is_flagged(self) -> None:
        planted = [Command("fake.py", 1, self._DISABLE)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_quoted_disable_is_flagged(self, quote: str) -> None:
        # PowerShell strips quotes before invoking a native program, so this
        # disables auditing exactly as the bare form does — and a deny-list
        # looking for a literal ":disable" reads straight past it.
        quoted = self._ENABLE.replace(
            "/success:enable", f"/success:{quote}disable{quote}"
        )
        planted = [Command("fake.py", 1, quoted)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_quoted_set_token_does_not_hide_a_disable(self, quote: str) -> None:
        # Quote-stripping applies to every token, not only switch values:
        # `auditpol "/set"` executes exactly as `auditpol /set`. Matching the
        # raw text let a quoted "/set" carry a disable past the detector.
        cmd = self._DISABLE.replace("/set", f"{quote}/set{quote}")
        planted = [Command("fake.py", 1, cmd)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_quoted_set_token_with_the_enable_shape_is_clean(self) -> None:
        # Dequoted it IS the blessed form, and that is what executes.
        cmd = self._ENABLE.replace("/set", '"/set"')
        assert not lint_commands([Command("fake.py", 1, cmd)])

    def test_an_escaped_executable_name_does_not_hide_a_disable(self) -> None:
        # `u is not a named escape sequence, so a`uditpol executes exactly as
        # auditpol — detection must run on the unescaped text.
        cmd = self._DISABLE.replace("auditpol", "a`uditpol", 1)
        planted = [Command("fake.py", 1, cmd)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_a_backtick_inside_the_enable_shape_fails_closed(self) -> None:
        # Even when the unescaped form reads as the blessed enable, a line
        # containing a backtick is not the canonical shape — it is only
        # accepted verbatim, with nothing for an escape to smuggle past.
        cmd = self._ENABLE.replace("/success:enable", "/succe`ss:enable")
        planted = [Command("fake.py", 1, cmd)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_a_tab_escape_breaks_the_word_and_is_clean(self) -> None:
        # `t IS a tab: audi`tpol executes as "audi<TAB>pol", which is not
        # auditpol. Reading it as the word would be a false positive.
        cmd = "audi`t" + self._DISABLE.removeprefix("audit")
        assert not [
            v
            for v in lint_commands([Command("fake.py", 1, cmd)])
            if v.rule == "auditpol-not-the-enable-shape"
        ]

    def test_an_unrecognised_auditpol_set_line_is_flagged(self) -> None:
        # Fails closed: anything that is not exactly the enable shape.
        planted = [Command("fake.py", 1, "auditpol /set /category:* /success:enable")]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_partial_disable_is_flagged(self) -> None:
        half = self._ENABLE.replace("/failure:enable", "/failure:disable")
        planted = [Command("fake.py", 1, half)]
        assert [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_enabling_command_is_clean(self) -> None:
        assert not lint_commands([Command("fake.py", 1, self._ENABLE)])

    def test_commented_disable_is_not_flagged(self) -> None:
        planted = [Command("fake.py", 1, "# " + self._DISABLE)]
        assert not [v for v in lint_commands(planted) if v.rule == "auditpol-not-the-enable-shape"]

    def test_no_shipped_command_disables_auditing(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "auditpol-not-the-enable-shape"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestConstrainedLanguageRule:
    """Constrained Language Mode refuses .NET method invocation.

    Apotrope scores a machine in Constrained Language as a hardened PASS, so a
    remediation needing full language fails on exactly the hosts it praised.
    Static property reads remain legal — the distinction is the call, not the
    type: even `[Math]::Floor(1.5)` is refused, while
    `[System.Environment]::OSVersion.Version` is fine.
    """

    def test_method_call_is_flagged(self) -> None:
        planted = [Command(
            "fake.py", 1,
            r"[void][Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Foo')",
        )]
        assert [v for v in lint_commands(planted)
                if v.rule == "constrained-language-method-call"]

    def test_static_property_read_is_not_flagged(self) -> None:
        planted = [Command("fake.py", 1, "$v = [System.Environment]::OSVersion.Version")]
        assert not [v for v in lint_commands(planted)
                    if v.rule == "constrained-language-method-call"]

    def test_commented_method_call_is_not_flagged(self) -> None:
        planted = [Command("fake.py", 1, "# [System.IO.File]::ReadAllText('x')")]
        assert not lint_commands(planted)

    def test_no_shipped_command_invokes_a_dotnet_method(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "constrained-language-method-call"
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


class TestRemoteAccessLockoutRule:
    """Commands that can cut the wire the operator is standing on.

    A comment saying "skip this if RDP is in use" does not help: the line below
    it still runs when the block is pasted. On a headless host with no console
    or out-of-band access the result is unrecoverable, and inside a PSSession
    the shell dies mid-block so whether later lines ran is indeterminate.
    """

    def _fired(self, text):
        return [
            v for v in lint_commands([Command("fake.py", 1, text)])
            if v.rule == "remote-access-lockout"
        ]

    def test_active_rdp_disable_is_flagged(self) -> None:
        assert self._fired("Set-ItemProperty -Name 'fDenyTSConnections' -Value 1")

    def test_commented_rdp_disable_is_not_flagged(self) -> None:
        assert not self._fired("# Set-ItemProperty -Name 'fDenyTSConnections' -Value 1")

    def test_group_wide_firewall_teardown_is_flagged(self) -> None:
        # -Group flips every rule in a shared container, including rules another
        # product added, and records no prior state — so there is no valid undo.
        assert self._fired("Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'")

    def test_session_transport_teardown_is_flagged(self) -> None:
        for spelling in (
            "Stop-Service WinRM",
            "Set-Service TermService -StartupType Disabled",
            "Disable-PSRemoting -Force",
        ):
            assert self._fired(spelling), spelling

    def test_re_enabling_access_is_not_flagged(self) -> None:
        # Restoring access is the opposite of a lockout.
        assert not self._fired("Set-ItemProperty -Name 'fDenyTSConnections' -Value 0")

    def test_leaf_targeted_and_unrelated_services_are_not_flagged(self) -> None:
        for safe in (
            "Disable-NetFirewallRule -Name 'RemoteDesktop-In-TCP'",  # one rule, undoable
            "Stop-Service Spooler",                                   # not a transport
            "Restart-Service W32Time",
        ):
            assert not self._fired(safe), safe

    def test_no_shipped_command_actively_locks_the_operator_out(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "remote-access-lockout"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestDiscardedCimReturnValueRule:
    """WMI reports failure in a return value, not an exception.

    `-ErrorAction` and `$?` never see it, so piping to Out-Null leaves the
    operator a clean prompt whether the call worked on every adapter, some, or
    none. SetTcpipNetbios returns 1 for "succeeded, REBOOT REQUIRED" as often as
    0 — the common outcome is a host reported fixed that is not.
    """

    def _fired(self, text):
        return [
            v for v in lint_commands([Command("fake.py", 1, text)])
            if v.rule == "discarded-cim-returnvalue"
        ]

    def test_piping_to_out_null_is_flagged(self) -> None:
        assert self._fired("Invoke-CimMethod -MethodName SetTcpipNetbios | Out-Null")

    def test_voiding_is_flagged(self) -> None:
        assert self._fired("$null = Invoke-CimMethod -MethodName X")
        assert self._fired("[void](Invoke-CimMethod -MethodName X)")

    def test_capturing_and_testing_is_not_flagged(self) -> None:
        assert not self._fired(
            "$r = Invoke-CimMethod -MethodName X\nif ($r.ReturnValue -ne 0) { throw }"
        )

    def test_new_item_piped_to_out_null_is_not_flagged(self) -> None:
        # New-Item raises on failure, so Out-Null discards nothing diagnostic.
        # Flagging it would fire on every guarded registry create in the tree.
        assert not self._fired(
            r"if (-not (Test-Path 'HKLM:\SOFTWARE\X')) "
            r"{ New-Item -Path 'HKLM:\SOFTWARE\X' -Force | Out-Null }"
        )

    def test_no_shipped_command_discards_a_returnvalue(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "discarded-cim-returnvalue"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestSilencedRegistryMutationRule:
    """Silencing a write hides the only failure signal there is.

    An ACL-protected key, or a GPO Preference re-creating the values, produces
    output byte-identical to full success. Silencing a *read* is fine — a guard
    is supposed to be quiet — so only mutating cmdlets are listed.
    """

    _K = r"$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\X'" + "\n"

    def _fired(self, text):
        return [
            v for v in lint_commands([Command("fake.py", 1, text)])
            if v.rule == "silenced-registry-mutation"
        ]

    def test_silenced_removal_is_flagged(self) -> None:
        assert self._fired(self._K + "Remove-ItemProperty -Path $k -Name Foo -ErrorAction SilentlyContinue")

    def test_ignore_is_flagged_too(self) -> None:
        # -Ignore is worse: it does not even populate $Error.
        assert self._fired(self._K + "Set-ItemProperty -Path $k -Name Foo -Value 1 -EA Ignore")

    def test_silenced_read_is_not_flagged(self) -> None:
        assert not self._fired(
            self._K + "$v = (Get-ItemProperty -Path $k -Name Foo -ErrorAction SilentlyContinue).Foo"
        )

    def test_unsilenced_mutation_is_not_flagged(self) -> None:
        assert not self._fired(self._K + "Remove-ItemProperty -Path $k -Name Foo")

    def test_commented_line_is_not_flagged(self) -> None:
        assert not self._fired(
            self._K + "# Remove-ItemProperty -Path $k -Name Foo -ErrorAction SilentlyContinue"
        )

    def test_no_shipped_command_silences_a_registry_write(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "silenced-registry-mutation"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]


class TestUnguardedAdminRemovalRule:
    """Removing yourself from Administrators is not undoable from that shell."""

    def _fired(self, text):
        return [
            v for v in lint_commands([Command("fake.py", 1, text)])
            if v.rule == "unguarded-admin-removal"
        ]

    def test_active_removal_by_sid_is_flagged(self) -> None:
        assert self._fired("Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'X'")

    def test_active_removal_by_group_name_is_flagged(self) -> None:
        assert self._fired("Remove-LocalGroupMember -Group 'Administrators' -Member 'X'")

    def test_commented_removal_is_not_flagged(self) -> None:
        assert not self._fired("# Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'X'")

    def test_adding_and_other_groups_are_not_flagged(self) -> None:
        for safe in (
            "Add-LocalGroupMember -SID 'S-1-5-32-544' -Member 'X'",   # granting, not removing
            "Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member 'X'",
        ):
            assert not self._fired(safe), safe

    def test_no_shipped_command_actively_removes_an_admin(self) -> None:
        violations = [
            v for v in lint_commands(collect_commands())
            if v.rule == "unguarded-admin-removal"
        ]
        assert not violations, [f"{v.module}:{v.line}" for v in violations]
