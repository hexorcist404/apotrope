"""The autouse hermeticity guard (conftest) must block unmocked subprocess calls."""

from __future__ import annotations

import subprocess
import sys

import pytest

import apotrope.utils as u


def test_guard_blocks_unmocked_subprocess():
    # Unmarked test → the conftest guard patches subprocess.run to raise.
    assert getattr(u.subprocess.run, "_apotrope_guard", False), (
        "the autouse hermeticity guard is not installed for an unmarked test"
    )
    with pytest.raises(RuntimeError, match="unmocked subprocess"):
        u.subprocess.run(["powershell.exe", "-Command", "echo hi"])


@pytest.mark.allow_subprocess
def test_marker_opts_out_of_guard():
    """With the marker the guard must NOT be installed.

    Asserted from both directions. The previous check —
    ``not getattr(u.subprocess.run, "_mock_name", None)`` — was vacuous: the
    guard is a plain function, not a Mock, so it has no ``_mock_name`` either
    and the assertion passed whether or not the marker plumbing worked. An
    identity check against ``subprocess.run`` proves nothing on its own either,
    since ``apotrope.utils`` imports the very same module object this test sees.
    """
    assert u.subprocess is subprocess
    assert not getattr(u.subprocess.run, "_apotrope_guard", False)
    assert u.subprocess.run.__module__ == "subprocess"
    assert u.subprocess.run.__qualname__ == "run"


@pytest.mark.allow_subprocess
def test_marker_reaches_the_real_boundary():
    """End-to-end proof the opt-out works, not just that the guard is absent.

    Spawns this interpreter rather than powershell.exe so the test is identical
    on the Linux and Windows matrix legs.
    """
    proc = u.subprocess.run(
        [sys.executable, "-c", "print('hermeticity-optout-ok')"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert "hermeticity-optout-ok" in proc.stdout
