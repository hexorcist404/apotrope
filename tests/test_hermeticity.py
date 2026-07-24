"""The autouse hermeticity guard (conftest) must block unmocked subprocess calls."""

from __future__ import annotations

import pytest


def test_guard_blocks_unmocked_subprocess():
    # Unmarked test → the conftest guard patches subprocess.run to raise.
    import apotrope.utils as u

    with pytest.raises(RuntimeError, match="unmocked subprocess"):
        u.subprocess.run(["powershell.exe", "-Command", "echo hi"])


@pytest.mark.allow_subprocess
def test_marker_opts_out_of_guard():
    # With the opt-out marker the guard does not patch, so subprocess.run is the
    # real callable (we don't invoke it — just assert it wasn't replaced).
    import apotrope.utils as u

    assert not getattr(u.subprocess.run, "_mock_name", None)
