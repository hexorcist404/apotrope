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
        target = node.targets[0]
        assert isinstance(target, ast.Name)  # guaranteed by the comprehension filter
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, (str, int, float, bool)):
            consts[target.id] = str(value.value)
        else:
            resolved = _resolve(value, consts)
            if resolved is not None:
                consts[target.id] = resolved
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
        exprs: list[ast.expr] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "command":
                        exprs.append(kw.value)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "command":
                        exprs.append(node.value)

        # Module-level `_CMD_*` constants are inventory members in their own
        # right, whether or not a `command=` reference resolves back to them.
        # A check that assembles its command at runtime — Audit Policy expands
        # one line per confirmed-disabled subcategory — would otherwise drop out
        # of the inventory entirely and ship unlinted and unparsed. Declaring the
        # template under this name keeps one representative form in scope.
        # Every existing `_CMD_*` is already reachable through a `command=`
        # reference, and collection dedupes on (module, text), so this adds no
        # duplicates.
        for node in tree.body:
            target: str | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                if isinstance(node.targets[0], ast.Name):
                    target, value = node.targets[0].id, node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target, value = node.target.id, node.value
            if target is not None and value is not None and target.startswith("_CMD_"):
                exprs.append(value)

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
# Destructive / unattended-impact commands that must never ship as copy-paste:
# a TPM clear can invalidate BitLocker protectors; a bare Restart-Computer can
# reboot the machine the moment the block is pasted. Reboots belong in comments.
#
# IGNORECASE is load-bearing, not tidiness: PowerShell resolves cmdlet names
# case-insensitively, so `restart-computer -Force` runs exactly as
# `Restart-Computer -Force` does while slipping past a case-sensitive rule.
_DESTRUCTIVE = re.compile(
    r"""
    \b(?:
        Clear-Tpm                    # wipes the TPM; invalidates BitLocker protectors
      | Restart-Computer             # immediate unattended reboot
      | Stop-Computer                # immediate unattended shutdown
      | Disable-BitLocker            # decrypts the volume
      | Clear-Disk | Format-Volume   # destroys a volume
      | Remove-Partition
      | Reset-ComputerMachinePassword
    )\b
  | -AllowClear\b | -AllowPhysicalPresence\b
  | \bshutdown(?:\.exe)?\b[^\n]*\s[/-][rsg]\b   # shutdown /r, /s, /g
  | \bInstall-WindowsUpdate\b[^\n]*-AutoReboot\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# `New-Item -Force` on the REGISTRY provider replaces an existing key: it deletes
# every value and subkey beneath it. That is harmless for a key we know is
# absent and destructive for a shared policy container — ...\Policies\Explorer
# carries NoRecentDocsHistory, NoActiveDesktop and friends alongside the value
# being set. `Set-ItemProperty -Force` cannot create a missing key, so the
# New-Item is legitimate — but `-Force` on it never is.
#
# A `Test-Path` guard is NOT an acceptable remedy, and this rule used to accept
# one. The test and the create are two operations: anything that creates the key
# in the window between them — a Group Policy refresh, an installer, another
# admin — is then replaced, losing exactly the values the guard existed to
# protect.
#
# Dropping -Force is no good either: on the registry provider New-Item cannot
# create a key whose parents are missing, and a policy key is absent precisely
# when its parents are too. Write the value with reg.exe instead, which creates
# the parents, touches only the named value, needs no separate create step, and
# runs under Constrained Language Mode:
#
#     reg.exe add "HKLM\<path>" /v <Name> /t REG_DWORD /d <n> /f
#     if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }
#
# reg.exe signals failure through the exit code, not a PowerShell error, so the
# check is what stops a denied write looking identical to a successful one.
#
# Filesystem New-Item is NOT flagged — there `-Force` creates parents and
# overwrites a file, which is the documented, expected behaviour. The registry
# gate below keys off the hive reference in the surrounding command.
#
# `[^\n]` would let a backtick line continuation carry -Force onto the next
# physical line and slip past; continuations are folded out before matching.
_NEW_ITEM_FORCE = re.compile(r"\bNew-Item\b.*?-Force\b", re.IGNORECASE | re.DOTALL)

# PowerShell Constrained Language Mode blocks .NET *method invocation* — the
# error is MethodInvocationNotSupportedInConstrainedLanguage — while still
# permitting static property reads, so `[System.Environment]::OSVersion.Version`
# is fine and `[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(...)` is
# not. Both were measured; the distinction is the call, not the type, and even
# `[Math]::Floor(1.5)` is refused.
#
# This matters more here than in ordinary code: Apotrope scores a machine in
# Constrained Language as a hardened PASS, so remediation that needs full
# language fails on exactly the hosts the tool has just praised.
_CLM_METHOD_CALL = re.compile(r"\[[\w.]+\]::[\w.]*\w+\s*\(")

# A BitLocker recovery password the operator never sees is worse than no
# encryption advice at all. Enable-BitLocker / Add-BitLockerKeyProtector return a
# BitLockerVolume whose default table renders the protector *types* — the 48-digit
# password lives in .KeyProtector[].RecoveryPassword and is never printed. So the
# operator gets a success-looking table, holds no copy, and the only surviving
# copy is in the volume's own metadata, which is unreachable from the recovery
# prompt. Any later TPM change strands them there.
#
# Creating the protector therefore obliges the command to also read it back or
# escrow it. Both are accepted: printing the password, or backing it up to AD DS
# / Entra ID.
# Commands that can sever the very connection the operator is running them over.
# These belong in comments with an explicit warning, not as active copy-paste:
# on a headless host with no console or out-of-band access the result is
# unrecoverable, and pasted inside a PSSession the shell dies mid-block so
# whether the following lines ran is indeterminate.
#
# Scoped to transports an operator plausibly arrives on. Leaf-targeted firewall
# edits (-Name/-DisplayName), RemoteRegistry/SNMP teardown, and anything
# RE-enabling access are all excluded by construction.
_SESSION_TRANSPORT = r"WinRM|WinRS|TermService|UmRdpService|SessionEnv|sshd"
_REMOTE_LOCKOUT = re.compile(
    r"""
    \bfDenyTSConnections\b[^\n]*-Value\s+1\b          # blocks RDP + drops the session
  | \b(?:Disable|Remove)-NetFirewallRule\b[^\n]*-(?:Display)?Group\b   # group-wide teardown
  | \bSet-NetFirewallRule\b[^\n]*-(?:Display)?Group\b[^\n]*-Enabled\s+\$?False\b
  | \bStop-Service\b[^\n]*\b(?:""" + _SESSION_TRANSPORT + r""")\b
  | \bSet-Service\b[^\n]*\b(?:""" + _SESSION_TRANSPORT + r""")\b[^\n]*
        -StartupType\s+Disabled\b
  | \bDisable-PSRemoting\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# WMI reports failure through a uint32 ReturnValue, not a PowerShell error, so
# -ErrorAction and $? never see it. Discarding that value leaves the operator
# with a clean prompt whether the call succeeded on every adapter, some, or none
# — and SetTcpipNetbios returns 1 for "succeeded, REBOOT REQUIRED" as routinely
# as 0, so the common outcome is a host that is reported fixed and is not.
# New-Item/New-ItemProperty | Out-Null is deliberately NOT flagged: those raise
# on failure, so nothing diagnostic is being thrown away.
_DISCARDED_CIM_RETURN = re.compile(
    r"\b(?:Invoke-CimMethod|Invoke-WmiMethod)\b[^\n|]*\|\s*Out-Null\b"
    r"|(?:\$null\s*=|\[void\]\s*\(?)\s*(?:Invoke-CimMethod|Invoke-WmiMethod)\b",
    re.IGNORECASE,
)

# Silencing errors on a registry cmdlet that MUTATES destroys the only signal the
# operator gets: an ACL-protected key, or a GPO Preference re-creating the values,
# produces output byte-identical to full success. Silencing a *read* is fine and
# often correct — a guard is supposed to be quiet — so only mutations are listed.
# -Ignore is strictly worse than SilentlyContinue: it does not even populate
# $Error, so nothing survives for a later check to find.
_SILENCED_REGISTRY_MUTATION = re.compile(
    r"\b(?:Remove|Set|New|Rename|Clear)-Item(?:Property)?\b[^\n]*"
    r"-(?:ErrorAction|EA)\s+(?:SilentlyContinue|Ignore|0)\b",
    re.IGNORECASE,
)

# Removing someone from Administrators is not reversible from a shell you no
# longer have. The operator substituting their own account into the example is
# the expected mistake, not an exotic one, so this belongs behind a comment and
# a "check who you are first" step.
_ADMIN_GROUP_REMOVAL = re.compile(
    r"\bRemove-LocalGroupMember\b[^\n]*(?:S-1-5-32-544|Administrators)", re.IGNORECASE
)

_CREATES_RECOVERY_PASSWORD = re.compile(r"-RecoveryPasswordProtector\b", re.IGNORECASE)
_SURFACES_RECOVERY_PASSWORD = re.compile(
    r"\bRecoveryPassword\b(?!Protector)"          # reads the property back
    r"|\bBackup(?:ToAAD)?-BitLockerKeyProtector\b"  # escrows to AD DS / Entra ID
    r"|\bmanage-bde\b[^\n]*-protectors\b",
    re.IGNORECASE,
)
_REGISTRY_HIVE = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\s*:|Registry::|\bHKEY_", re.IGNORECASE)
# -DisplayGroup selects an EXISTING firewall rule by its resolved MUI string
# ('Remote Desktop' is @FirewallAPI.dll,-28752 rendered in the display
# language), so it matches nothing on non-English Windows and the cmdlet
# no-ops with a non-terminating error — the worst outcome for a copy-paste
# block, since the earlier lines did run and the operator sees no failure.
# Select by the locale-neutral -Group indirect resource string instead.
#
# -DisplayName is deliberately NOT flagged: on New-NetFirewallRule it *names*
# the rule being created (and is mandatory — see firewall-rule-no-displayname),
# and it is also the correct way to manage a rule Apotrope itself created.
_LOCALIZED_FW_SELECTOR = re.compile(
    r"\b(?:Get|Set|Enable|Disable|Remove|Copy|Rename|Show)-NetFirewallRule\b"
    r"[^\n|]*?\s-DisplayGroup\b"
)
# A literal "{expr}" in collected text is always an extraction failure, never a
# real command: _resolve could not statically resolve the expression, so the
# lint rules below (and tools/verify_commands.py) are inspecting a placeholder
# rather than the command that actually ships.
_UNRESOLVED_EXPR = re.compile(r"\{expr\}")


def _uncommented_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


# A trailing backtick continues a PowerShell statement onto the next physical
# line, so `New-Item -Path $k `\n  -Force` is one command wearing two lines.
# Per-line rules must see the joined statement or a continuation hides the
# argument they exist to find.
_CONTINUATION = re.compile(r"`[ \t]*\r?\n[ \t]*")


def _logical_lines(text: str) -> list[str]:
    """Uncommented lines with backtick continuations folded into one line each."""
    return _uncommented_lines(_CONTINUATION.sub(" ", text))


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
        if _DESTRUCTIVE.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "destructive-command",
                "destructive/unattended command (TPM clear, reboot, shutdown, volume "
                "or BitLocker teardown) must be a commented manual step, not copy-paste",
                text,
            ))
        if _REMOTE_LOCKOUT.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "remote-access-lockout",
                "actively severs a remote-access path the operator may be connected "
                "over (RDP, WinRM, SSH). Ship it as a commented manual step with an "
                "explicit warning, as rdp.py and network.py do — pasted in a live "
                "session this is unrecoverable on a headless host",
                text,
            ))
        if _DISCARDED_CIM_RETURN.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "discarded-cim-returnvalue",
                "discards a WMI method's ReturnValue. WMI signals failure through "
                "ReturnValue, not a PowerShell error, so -ErrorAction and $? see "
                "nothing and the operator gets a clean prompt whether it worked or "
                "not. Capture the result and report a non-zero value",
                text,
            ))
        if (
            _CREATES_RECOVERY_PASSWORD.search(active)
            and not _SURFACES_RECOVERY_PASSWORD.search(active)
        ):
            violations.append(Violation(
                cmd.module, cmd.line, "bitlocker-no-key-escrow",
                "creates a BitLocker recovery password the operator never sees. The "
                "cmdlets print the protector types, not the 48-digit password, and it "
                "cannot be read back from the recovery prompt. Read it back "
                "(.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword') "
                "or escrow it (Backup-BitLockerKeyProtector / BackupToAAD-...)",
                text,
            ))
        if _ADMIN_GROUP_REMOVAL.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "unguarded-admin-removal",
                "actively removes a member of Administrators. The operator "
                "substituting their own account is the expected mistake, and it is "
                "not reversible from a shell they no longer have — ship it commented, "
                "after a step that shows the current membership and `whoami`",
                text,
            ))
        for line in _logical_lines(text):
            if _CLM_METHOD_CALL.search(line):
                violations.append(Violation(
                    cmd.module, cmd.line, "constrained-language-method-call",
                    "invokes a .NET method, which PowerShell Constrained Language Mode "
                    "refuses (MethodInvocationNotSupportedInConstrainedLanguage). "
                    "Apotrope scores a machine in Constrained Language as a hardened "
                    "PASS, so this fails on exactly the hosts it has just praised. Use "
                    "a cmdlet or a native tool such as reg.exe. Static property reads "
                    "like [System.Environment]::OSVersion.Version are still fine",
                    text,
                ))
                break
        if _REGISTRY_HIVE.search(active):
            for line in _uncommented_lines(text):
                if _SILENCED_REGISTRY_MUTATION.search(line):
                    violations.append(Violation(
                        cmd.module, cmd.line, "silenced-registry-mutation",
                        "silences errors on a registry cmdlet that mutates state, so a "
                        "denied or re-created value produces output identical to "
                        "success. Silencing a read is fine; test the value and report "
                        "instead of hiding the write's only failure signal",
                        text,
                    ))
                    break
            for line in _logical_lines(text):
                if _NEW_ITEM_FORCE.search(line):
                    violations.append(Violation(
                        cmd.module, cmd.line, "registry-new-item-force",
                        "New-Item -Force on a registry key REPLACES it, deleting every "
                        "value and subkey under it. A Test-Path guard does not fix this "
                        "— the test and the create are two operations, and a key created "
                        "in between is still replaced — and dropping -Force cannot "
                        "create missing parents. Write the value with reg.exe instead: "
                        '`reg.exe add \"HKLM\\<path>\" /v <Name> /t REG_DWORD /d <n> /f` '
                        'followed by `if ($LASTEXITCODE -ne 0) { throw ... }`',
                        text,
                    ))
                    break
        if _LOCALIZED_FW_SELECTOR.search(active):
            violations.append(Violation(
                cmd.module, cmd.line, "localized-firewall-selector",
                "-DisplayGroup selects an existing firewall rule by its localized MUI "
                "string — it matches nothing on non-English Windows and silently no-ops; "
                "use -Group '@FirewallAPI.dll,-NNNNN' or a stable -Name rule ID",
                text,
            ))
        # Checked against the raw text, not `active`: an extraction failure in a
        # commented line is still an extraction failure.
        if _UNRESOLVED_EXPR.search(text):
            violations.append(Violation(
                cmd.module, cmd.line, "unresolved-expression",
                "command text contains the literal '{expr}' — the AST extractor could "
                "not resolve this expression, so the real command is unlinted. Keep any "
                "conditional as `A if cond else B` at the root of the command= value",
                text,
            ))
    return violations


if __name__ == "__main__":
    cmds = collect_commands()
    print(f"collected {len(cmds)} commands from {CHECKS_DIR}")
    for v in lint_commands(cmds):
        print(f"  [{v.rule}] {v.module}:{v.line} — {v.detail}")
