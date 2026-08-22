"""Guard: the shipped registry writes behave, and run where operators run them.

``tools/verify_commands.py`` parses every remediation command and resolves the
cmdlets it invokes — it proves nothing about what those cmdlets *do*, and
nothing about the language mode they need. Both gaps have bitten this command:

* ``New-Item -Force`` parses perfectly and silently deletes a shared policy key.
* ``[Registry]::…CreateSubKey()`` parses perfectly and is refused outright by
  Constrained Language Mode — which Apotrope itself scores as a hardened PASS.

These tests run the **real command text** against a throwaway ``HKCU`` path,
with only the hive and key retargeted. Windows-only, and they reach a real
PowerShell — hence ``allow_subprocess``.
"""

from __future__ import annotations

import subprocess
import sys
import uuid

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "tools"))

from command_audit import collect_commands

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="registry semantics are Windows-only"),
    pytest.mark.allow_subprocess,
]

#: Every shipped command that writes a registry value, by (module, first key path).
REGISTRY_COMMANDS = [
    pytest.param(c.text, id=f"{c.module}:{c.line}")
    for c in collect_commands()
    if "reg.exe add" in c.text
]


def _powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, check=False,
    )


def _retarget(command: str, root: str) -> str:
    """The shipped command with its hive and path swapped for a throwaway one.

    Only ``"HKLM\\`` is rewritten, so the value names, types, data and the
    exit-code checks are exactly what ships.
    """
    return command.replace('"HKLM\\', f'"HKCU\\{root}\\')


@pytest.fixture
def temp_root():
    root = f"Software\\ApotropeTest\\{uuid.uuid4().hex}"
    try:
        yield root
    finally:
        _powershell(
            f"Remove-Item -Path 'HKCU:\\{root}' -Recurse -Force -ErrorAction SilentlyContinue"
        )


def test_every_registry_command_was_collected():
    # Four commands, five writes. If this drops to zero the whole module is
    # asserting nothing.
    assert len(REGISTRY_COMMANDS) == 4, REGISTRY_COMMANDS


@pytest.mark.parametrize("command", REGISTRY_COMMANDS)
def test_writes_value_and_creates_missing_parents(command, temp_root):
    # The parents genuinely do not exist: a policy key is absent exactly when
    # its parents are. `New-Item` without -Force fails outright here, which is
    # why simply dropping -Force was not a fix.
    result = _powershell(_retarget(command, temp_root))
    assert result.returncode == 0, result.stderr
    assert _powershell(f"Test-Path 'HKCU:\\{temp_root}'").stdout.strip() == "True"


@pytest.mark.parametrize("command", REGISTRY_COMMANDS)
def test_runs_under_constrained_language_mode(command, temp_root):
    # Apotrope scores a Constrained Language machine as a hardened PASS. A
    # remediation that needs full language fails on the hosts it just praised —
    # which is what [Registry]::…CreateSubKey() did.
    script = (
        "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n"
        + _retarget(command, temp_root)
    )
    result = _powershell(script)
    assert result.returncode == 0, (
        f"blocked under ConstrainedLanguage:\n{result.stderr}"
    )


@pytest.mark.parametrize("command", REGISTRY_COMMANDS)
def test_neighbouring_state_survives(command, temp_root):
    # -Force would delete all three of these. They stand in for the unrelated
    # Explorer policies (NoRecentDocsHistory, NoActiveDesktop, ...) that share
    # the AutoPlay key.
    key = f"HKCU:\\{temp_root}"
    assert _powershell(_retarget(command, temp_root)).returncode == 0

    seed = (
        f"Set-ItemProperty -Path '{key}' -Name Neighbour -Value 'keepme'\n"
        f"Set-ItemProperty -Path '{key}' -Name '(default)' -Value 'defaultkeep'\n"
        f"New-Item -Path '{key}\\ChildKey' -Force | Out-Null\n"
        f"Set-ItemProperty -Path '{key}\\ChildKey' -Name Inner -Value 'innerkeep'"
    )
    assert _powershell(seed).returncode == 0

    # Run it a second time, over the now-populated key.
    assert _powershell(_retarget(command, temp_root)).returncode == 0

    probe = _powershell(
        f"$p = Get-ItemProperty '{key}'\n"
        f"$c = Get-ItemProperty '{key}\\ChildKey' -ErrorAction SilentlyContinue\n"
        "$p.Neighbour; $p.'(default)'; $c.Inner"
    )
    assert probe.stdout.split() == ["keepme", "defaultkeep", "innerkeep"], (
        f"the write destroyed neighbouring state: {probe.stdout!r}"
    )


def test_new_item_force_would_have_destroyed_them(temp_root):
    # The counter-example, so the test above cannot pass vacuously: the form
    # this command used to ship really does delete neighbouring state.
    key = f"HKCU:\\{temp_root}\\Probe"
    setup = (
        f"New-Item -Path '{key}' -Force | Out-Null\n"
        f"Set-ItemProperty -Path '{key}' -Name Neighbour -Value 'keepme'"
    )
    assert _powershell(setup).returncode == 0

    result = _powershell(
        f"New-Item -Path '{key}' -Force | Out-Null\n"
        f"$v = (Get-ItemProperty -Path '{key}' -ErrorAction SilentlyContinue).Neighbour\n"
        "if ($null -eq $v) { 'GONE' } else { $v }"
    )
    assert result.stdout.strip() == "GONE", (
        "New-Item -Force preserved the value — the premise of this fix no longer holds"
    )


@pytest.mark.parametrize("command", REGISTRY_COMMANDS)
def test_a_real_failure_is_not_swallowed(command):
    # An invalid root fails identically for every identity and cannot mutate any
    # hive. Targeting a real-but-protected key such as HKLM:\SECURITY would
    # succeed under LocalSystem and leave a machine-wide key behind.
    result = _powershell(command.replace('"HKLM\\', '"HKXX\\'))
    assert result.returncode != 0, "a failed write exited 0"
    assert "reg.exe add failed" in (result.stderr + result.stdout), (
        "the exit-code check did not fire; a denied write would look like success"
    )


# ── Unquoted-service-path reader ─────────────────────────────────────────────

#: The shipped Unquoted Service Paths command — the only remediation that READS
#: a REG_EXPAND_SZ. It must do so unexpanded (writing an expanded value back
#: bakes the resolved path in) and under Constrained Language Mode (the
#: .GetValue() form it replaced was refused exactly there).
UNQUOTED_PATH_COMMAND = next(
    c.text for c in collect_commands()
    if "reg.exe query" in c.text and "ImagePath" in c.text
)


def test_unquoted_path_reader_runs_under_constrained_language():
    # Schedule ships on every supported Windows with an unexpanded
    # %SystemRoot% ImagePath, and the command only prints — its writes are
    # commented — so running it against the real key is a read.
    script = (
        "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n"
        + UNQUOTED_PATH_COMMAND.replace("$svc = 'ExampleService'", "$svc = 'Schedule'")
    )
    result = _powershell(script)
    assert result.returncode == 0, result.stderr
    assert "current: %" in result.stdout.lower(), (
        f"expected the unexpanded value; the read expanded it or failed: {result.stdout!r}"
    )


def test_the_getvalue_form_it_replaced_is_refused_there():
    # Counter-example so the test above cannot pass vacuously: the .NET method
    # call this command used to make really is blocked under Constrained
    # Language — RegistryKey is not an allowed type.
    script = (
        "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n"
        r"(Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Schedule')"
        ".GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames')"
    )
    result = _powershell(script)
    assert result.returncode != 0
    assert "MethodInvocationNotSupportedInConstrainedLanguage" in result.stderr
