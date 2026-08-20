"""WORKSTATION-07, reconstructed: the sample machine the published reports show.

``sample_machine.json`` holds, per check module, the mocked Windows inputs —
PowerShell/WMI payloads on the module-level names each check imports — that make
the *real* check code emit exactly the rows in
``tools/fixtures/sample_report.json``. The two modules that read the clock
(``os_info``, ``updates``) additionally carry a ``frozen_datetime`` patch
pinning "now" to the persona's own ``scan_timestamp``
(2026-07-13T15:30:00+00:00), so their time-derived text reproduces exactly.

This file is the drift alarm's other half: ``tests/test_sample_reports.py``
runs every module against these inputs and requires the published rows to equal
the output. Change what a check emits and the guard fails naming the field;
regenerate the sample and it passes again. The payloads only need touching when
a check starts *consuming* different machine data.

Each patch spec is ``{"target": <module-level name>, "kind": ..., "value": ...,
"calls": [...]}`` where kind is ``return_value``, ``side_effect`` (payloads in
call order), or ``frozen_datetime`` (an ISO instant the harness turns into a
pinned datetime class).

``calls`` pins the exact arguments the module passed on every call — the
PowerShell query text itself — captured from the source at reconstruction time.
The harness requires the recorded calls to match them, in order, completely
(an empty list means "must never be called"). Without that, a check whose
*query* rots would keep generating perfect rows: the mock answers any question
with the same canned data. A pinned-call mismatch is query drift; update this
spec deliberately, the same as any other drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MACHINE: dict[str, list[dict[str, Any]]] = json.loads(
    (Path(__file__).parent / "sample_machine.json").read_text(encoding="utf-8")
)
