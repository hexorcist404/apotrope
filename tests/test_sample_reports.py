"""Guard: the published sample reports stay reproducible and stay current.

``docs/report.html`` and ``docs/exec-report.html`` are the samples linked from
apotrope.sh. They were once hand-made from a real scan with no tracked input, so
when the package version moved they could not be regenerated and sat advertising
v0.1.12 two releases later. ``tools/fixtures/sample_report.json`` is now their
source and ``tools/generate_sample_reports.py`` renders them.

Three failure modes are guarded here:

* **Branding drift** — a committed asset naming a version the package no longer
  is. Covers ``docs/index.html`` too, whose demo terminal and JSON-LD carry the
  same version by hand.
* **Source drift** — the committed assets no longer being what the fixture
  renders, which would put the reproducible path back where it started.
* **Content drift** — the fixture publishing rows the check modules no longer
  emit. Guarded by *generation*, not matching: ``tests/sample_machine.py``
  holds the reconstructed inputs of the sample machine, the real check
  functions run against them, and every published row must equal a generated
  row exactly. An earlier version of this guard statically re-derived what the
  checks could emit from their AST; six review rounds each found ways to slip
  text past that partial interpreter. Running the real code leaves no matcher
  to fool.

``sample_machine.py`` *is* the machine. Everything else on a row — status,
severity, description, details, remediation, command, ``cis_reference`` — is
whatever the current source produces from it, so any source change that moves a
published field fails here, naming the field.
"""

from __future__ import annotations

import contextlib
import importlib
import pkgutil
import json
import re
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from unittest import mock

import pytest

import apotrope
from apotrope import checks as checks_pkg
from apotrope import cis_map
from apotrope.checks import misc
from apotrope.compare import load_baseline
from apotrope.scoring import calculate_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Imported in-process, not spawned: conftest's autouse guard patches
# subprocess.run process-wide, so shelling out to the generator would raise.
import command_audit

from generate_sample_reports import (
    EXECUTIVE_NAME,
    EXPECTED_COUNTS,
    EXPECTED_HOSTNAME,
    EXPECTED_SCORE,
    FIXTURE,
    TECHNICAL_NAME,
    main,
)
from sample_machine import MACHINE

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REGENERATE = "python tools/generate_sample_reports.py"

#: The exact checks the published sample shows. Pinned so one vanishing is a
#: failure rather than a quietly shorter report.
EXPECTED_CHECK_NAMES = (
    'Audit Policy',
    'AutoPlay Disabled',
    'BitLocker — C:',
    'BitLocker — G:',
    'Built-in Administrator Account',
    'Defender Real-Time Protection',
    'Defender Signature Age',
    'Defender Tamper Protection',
    'Domain Membership',
    'Firewall — Domain Default Inbound Action',
    'Firewall — Domain Profile Enabled',
    'Firewall — Private Default Inbound Action',
    'Firewall — Private Profile Enabled',
    'Firewall — Public Default Inbound Action',
    'Firewall — Public Profile Enabled',
    'Guest Account',
    'IPv6 Status',
    'LLMNR Disabled',
    'Last Windows Update',
    'Listening Ports — Summary',
    'Local Administrators',
    'NetBIOS over TCP/IP',
    'OS End-of-Support Status',
    'OS Version',
    'Password Policy — Account Lockout',
    'Password Policy — Complexity',
    'Password Policy — Minimum Length',
    'Pending Windows Updates',
    'PowerShell Constrained Language Mode',
    'PowerShell Execution Policy',
    'PowerShell Module Logging',
    'PowerShell Script Block Logging',
    'PowerShell v2',
    'RDP Enabled',
    'Registered AV Products',
    'Risky Services',
    'SMB Encryption',
    'SMB Signing Required',
    'SMBv1 Disabled',
    'Scheduled Tasks',
    'Screen Lock Timeout',
    'Secure Boot',
    'Speculative Execution Mitigations',
    'Startup Programs',
    'System Uptime',
    'TPM Status',
    'UAC Admin Consent Behavior',
    'UAC Enabled',
    'UAC Secure Desktop',
    'UAC Standard User Behavior',
    'Unquoted Service Paths',
    'WinRM Status',
    'Windows Update Service',
)


@lru_cache(maxsize=1)
def _category_to_module() -> dict[str, str]:
    """Map each check category to the single module that emits it."""
    mapping: dict[str, str] = {}
    for info in pkgutil.iter_modules(checks_pkg.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"apotrope.checks.{info.name}")
        category = getattr(module, "CATEGORY", None)
        if category:
            mapping[category] = info.name
    return mapping


# ── The generation core ─────────────────────────────────────────────────────
#
# sample_machine.MACHINE holds, per check module, the mocked Windows inputs of
# the sample machine. The real run() executes against them; nothing about the
# emitted rows is re-derived, matched, or approximated here.

#: Every field a published row is compared on. check_duration is excluded —
#: the scanner stamps it at scan time and both sides carry 0.0.
_COMPARED_FIELDS = (
    "category",
    "check_name",
    "status",
    "severity",
    "description",
    "details",
    "remediation",
    "command",
    "cis_reference",
)


def _frozen_datetime(iso: str) -> type:
    """A datetime class pinned to *iso*, for modules that read the clock.

    os_info and updates render durations from "now"; frozen at the persona's
    own scan instant, their time-derived text reproduces exactly.
    """
    frozen = datetime.fromisoformat(iso)

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            if tz is not None:
                return frozen.astimezone(tz)
            return frozen.replace(tzinfo=None)

        @classmethod
        def today(cls):
            return frozen.replace(tzinfo=None)

        @classmethod
        def utcnow(cls):
            return frozen.astimezone(timezone.utc).replace(tzinfo=None)

    return _Frozen


@lru_cache(maxsize=None)
def _generated_rows(module_name: str) -> tuple[dict[str, str], ...]:
    """Run the real check module against the reconstructed machine.

    The mocked helpers do not merely hand back canned data — every spec pins
    the exact call arguments the module made when the spec was captured, and
    the recorded calls must match them, in order, completely. Without that, a
    check whose *query* rots (asks the machine the wrong question) would keep
    generating perfect rows: the mock answers any question with the same data,
    so the guard would stay green while every real scan changed behaviour.
    A pinned-call mismatch is query drift; update sample_machine.json
    deliberately, the same as any other drift.
    """
    module = importlib.import_module(f"apotrope.checks.{module_name}")
    recorded: list[tuple[dict, mock.Mock]] = []
    with contextlib.ExitStack() as stack:
        for spec in MACHINE[module_name]:
            target, kind, value = spec["target"], spec["kind"], spec["value"]
            if kind == "frozen_datetime":
                stack.enter_context(mock.patch(target, _frozen_datetime(value)))
                continue
            if kind == "side_effect":
                stub = mock.Mock(side_effect=list(value))
            elif kind == "return_value":
                stub = mock.Mock(return_value=value)
            else:
                raise ValueError(
                    f"unknown mock kind {kind!r} for {target} — the harness "
                    "must fail on a spec it does not understand, not improvise"
                )
            if "calls" not in spec:
                raise ValueError(
                    f"{target} has no pinned calls — every mocked helper must "
                    "declare the exact arguments the module is expected to pass"
                )
            if kind == "side_effect" and len(spec["calls"]) != len(value):
                raise ValueError(
                    f"{target} supplies {len(value)} payload(s) for "
                    f"{len(spec['calls'])} pinned call(s) — every supplied "
                    "response must be consumed"
                )
            stack.enter_context(mock.patch(target, stub))
            recorded.append((spec, stub))
        rows = module.run()

    for spec, stub in recorded:
        expected = [
            mock.call(*c["args"], **c["kwargs"]) for c in spec["calls"]
        ]
        assert stub.call_args_list == expected, (
            f"{spec['target']} was not called with the pinned arguments.\n"
            f"  expected: {expected}\n"
            f"  recorded: {stub.call_args_list}\n"
            "A mismatch means the check's query changed (or calls were added, "
            "dropped, or reordered) — update tests/sample_machine.json "
            "deliberately, the same as any other drift."
        )

    generated = []
    for r in rows:
        generated.append({
            "category": r.category,
            "check_name": r.check_name,
            "status": r.status.value,
            "severity": r.severity.value,
            "description": r.description,
            "details": r.details,
            "remediation": r.remediation,
            "command": r.command,
            # The scanner attaches CIS references after the modules run
            # (scanner.py:376-384); replicate it so generated rows are complete.
            "cis_reference": r.cis_reference or cis_map.lookup(r.check_name),
        })
    return tuple(generated)


def _verify_row(row: dict) -> str | None:
    """None if the row is exactly what the real check emits; otherwise why not."""
    module_name = _category_to_module()[row["category"]]
    mine = {field: row[field] for field in _COMPARED_FIELDS}
    generated = _generated_rows(module_name)
    if any(mine == g for g in generated):
        return None

    named = [g for g in generated if g["check_name"] == row["check_name"]]
    if not named:
        return f"the real {module_name} module emits no row named {row['check_name']!r}"
    diffs = [
        f"{field}: fixture {mine[field]!r} != generated {named[0][field]!r}"
        for field in _COMPARED_FIELDS
        if mine[field] != named[0][field]
    ]
    return "; ".join(diffs)


def test_the_machine_covers_every_module() -> None:
    """A module missing from sample_machine.py is a module nothing verifies."""
    assert set(MACHINE) == set(_category_to_module().values())


@pytest.mark.parametrize("module_name", sorted(MACHINE))
def test_the_real_checks_reproduce_every_published_row(module_name: str) -> None:
    """The core guard: real code, reconstructed machine, exact equality.

    Any source change that moves a published field — wording, severity, a
    command, the CIS mapping — fails here naming the module, and the fix is to
    regenerate the sample rather than to argue with a matcher.
    """
    category = next(
        cat for cat, mod in _category_to_module().items() if mod == module_name
    )
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixture_rows = sorted(
        ({field: r[field] for field in _COMPARED_FIELDS}
         for r in report["results"] if r["category"] == category),
        key=lambda g: g["check_name"],
    )
    generated = sorted(_generated_rows(module_name), key=lambda g: g["check_name"])

    # Check names are unique (pinned below), so comparing name-sorted lists is
    # a multiset comparison. Emission order and document order differ by
    # design; the reporter re-sorts for rendering.
    assert generated == fixture_rows, (
        f"docs/ rows for {category!r} are not what {module_name}.run() emits. "
        f"Refresh the fixture from source, then regenerate: {REGENERATE}"
    )


@contextlib.contextmanager
def _uncached_generation():
    """Clear the generation cache around a test that perturbs its inputs."""
    _generated_rows.cache_clear()
    try:
        yield
    finally:
        _generated_rows.cache_clear()


def test_a_corrupted_query_fails_generation() -> None:
    """The mocks answer questions; the guard must check which question was asked.

    Without pinned call arguments, a check whose PowerShell query rots keeps
    generating perfect rows — the mock hands back the canned data whatever the
    module asks — and the guard stays green while every real scan changes
    behaviour.
    """
    from apotrope.checks import encryption

    with _uncached_generation():
        with mock.patch.object(encryption, "_PS_BITLOCKER", "CORRUPT QUERY"):
            with pytest.raises(AssertionError, match="pinned arguments"):
                _generated_rows("encryption")


def test_an_unknown_mock_kind_is_rejected() -> None:
    """A spec the harness does not understand must fail, not improvise."""
    bogus = [{"target": "apotrope.checks.uac.run_powershell_json",
              "kind": "bogus", "value": {}, "calls": []}]
    with _uncached_generation():
        with mock.patch.dict(MACHINE, {"uac": bogus}):
            with pytest.raises(ValueError, match="unknown mock kind"):
                _generated_rows("uac")


def test_an_unconsumed_payload_is_rejected() -> None:
    """Supplying answers nothing asks for is the same rot in the other direction."""
    spec = [dict(s) for s in MACHINE["services"]]
    spec[0] = {**spec[0], "value": [*spec[0]["value"], {"extra": "payload"}]}
    with _uncached_generation():
        with mock.patch.dict(MACHINE, {"services": spec}):
            with pytest.raises(ValueError, match="must be consumed"):
                _generated_rows("services")


# ── Branding, rendering, persona ────────────────────────────────────────────

# Anchors are deliberately narrow. All three files also contain CIS benchmark
# strings ("v5.0.0", "v4.0.0"), so a loose r"v\d+\.\d+\.\d+" sweep captures those
# and fails. Each capture group starts *after* the literal "v" the templates
# render, because apotrope.__version__ is bare ("0.2.0", not "v0.2.0").
VERSION_ANCHORS: list[tuple[str, str, int]] = [
    (TECHNICAL_NAME, r'<span class="ver">v([0-9][^<]*)</span>', 1),
    (EXECUTIVE_NAME, r"Apotrope v([0-9][^ <·]*)", 2),
    ("index.html", r'"softwareVersion":\s*"([^"]+)"', 1),
    ("index.html", r'class="g-dim">v([0-9][^<]*)</span>', 1),
]


@pytest.mark.parametrize(("filename", "pattern", "expected_hits"), VERSION_ANCHORS)
def test_published_assets_name_the_current_version(
    filename: str, pattern: str, expected_hits: int
) -> None:
    """Every tool version printed in docs/ must equal the packaged version."""
    text = (DOCS / filename).read_text(encoding="utf-8")
    found = re.findall(pattern, text)

    # A pattern that stops matching is the same silent failure as a stale
    # version: the guard would pass while covering nothing.
    assert len(found) == expected_hits, (
        f"{filename}: expected {expected_hits} match(es) for {pattern!r}, got {found}. "
        "The template changed — update the anchor rather than deleting the check."
    )
    for value in found:
        assert value == apotrope.__version__, (
            f"{filename} advertises {value!r} but the package is "
            f"{apotrope.__version__!r}. Regenerate with: {REGENERATE}"
        )


def test_committed_reports_match_what_the_fixture_renders(tmp_path: Path) -> None:
    """The committed assets must be exactly what the generator produces today."""
    assert main(["--output-dir", str(tmp_path)]) == 0, "the generator did not succeed"

    for name in (TECHNICAL_NAME, EXECUTIVE_NAME):
        # read_text, not read_bytes. The reporter writes through
        # Path.write_text with newline=None, so a render on Windows is CRLF while
        # the committed asset is LF (.gitattributes: * text=auto eol=lf). A byte
        # comparison would fail on the Windows CI legs only. Universal newlines
        # collapse both sides to "\n" and compare the content that matters.
        rendered = (tmp_path / name).read_text(encoding="utf-8")
        committed = (DOCS / name).read_text(encoding="utf-8")
        assert rendered == committed, (
            f"docs/{name} is not what tools/fixtures/sample_report.json renders. "
            f"If the template or the fixture changed on purpose, regenerate: {REGENERATE}"
        )


def test_fixture_holds_the_sanitized_persona() -> None:
    """The fixture must keep describing the published sample machine."""
    report = load_baseline(str(FIXTURE))

    assert report.hostname == EXPECTED_HOSTNAME
    # Not rendered anywhere in the technical report, so it cannot be recovered by
    # re-parsing it. A silent False flips the executive report's Privileges field
    # to "Standard user" and rewrites its scope paragraph.
    assert report.is_admin is True

    assert len(report.results) == sum(EXPECTED_COUNTS.values())
    for status, expected in EXPECTED_COUNTS.items():
        assert len(report.by_status(status)) == expected, f"{status.value} count changed"

    # The stored score is what renders in the gauge — load_baseline trusts it and
    # never recomputes — so both it and the derived value are pinned.
    assert report.score == EXPECTED_SCORE
    assert calculate_score(report.results) == EXPECTED_SCORE
    assert report.error_count == 0, "the published sample must not show failed checks"


def test_the_sample_contains_exactly_the_expected_checks() -> None:
    """Status totals do not prove the right checks are present.

    Swapping one row for a duplicate of another leaves 53 rows, the same
    per-status counts, and every row individually verifiable — the sample would
    simply stop showing a check while every guard stayed green.
    """
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    names = [r["check_name"] for r in report["results"]]

    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"the sample repeats a check: {duplicates}"
    assert len(names) == sum(EXPECTED_COUNTS.values())

    # Pinned so a check disappearing from the sample is a failure, not a
    # silently shorter report.
    assert sorted(names) == sorted(EXPECTED_CHECK_NAMES), {
        "missing": sorted(set(EXPECTED_CHECK_NAMES) - set(names)),
        "unexpected": sorted(set(names) - set(EXPECTED_CHECK_NAMES)),
    }


def _fixture_commands() -> list[command_audit.Command]:
    """Fixture rows carrying a command, shaped for the shipped lint."""
    report = load_baseline(str(FIXTURE))
    return [
        command_audit.Command(module=r.check_name, line=0, text=r.command)
        for r in report.results
        if r.command
    ]


def test_fixture_commands_pass_the_shipped_lint() -> None:
    """The sample's commands must clear the same lint the check modules do.

    ``tests/test_remediation_commands.py`` runs this over the source inventory.
    Running it over the fixture as well is what stops the published sample
    advertising a command the source has already fixed — which is exactly how a
    BitLocker block with no recovery-password readback reached apotrope.sh under
    a v0.2.0 banner.
    """
    violations = command_audit.lint_commands(_fixture_commands())
    assert violations == [], (
        "the published sample carries remediation the lint rejects:\n"
        + "\n".join(f"  {v.module}: {v.rule}" for v in violations)
    )


def test_fixture_cis_references_match_the_benchmark_map() -> None:
    """``cis_reference`` is code-owned too — it comes from cis_map, not the scan."""
    report = load_baseline(str(FIXTURE))
    wrong = [
        (r.check_name, r.cis_reference, cis_map.lookup(r.check_name))
        for r in report.results
        if r.cis_reference != cis_map.lookup(r.check_name)
    ]
    assert not wrong, f"fixture CIS references disagree with cis_map: {wrong}"


# ── Mutation coverage ───────────────────────────────────────────────────────
#
# A guard with no evidence it can fail is the failure mode this whole file
# exists to prevent. Under generation every mutation is rejected by
# construction — a mutated row cannot equal what the real code emits — but the
# corpus stays: it is the accumulated exploit history of six review rounds
# against the previous matcher, and it keeps any future verifier honest.


def _row(name: str) -> dict:
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return next(r for r in report["results"] if r["check_name"] == name)


def _swap_within_module(row: dict) -> dict:
    # AutoPlay and Audit Policy both live in misc.py, so a module-scoped guard
    # accepts each other's commands.
    row["command"] = _row("Audit Policy")["command"]
    return row


def _blank_a_field(row: dict) -> dict:
    row["remediation"] = ""
    return row


def _wrong_runtime_value(row: dict) -> dict:
    # A BitLocker G: row carrying a command that targets C:.
    row["command"] = row["command"].replace("'G:'", "'C:'")
    return row


def _fabricated_threshold(row: dict) -> dict:
    row["description"] = row["description"].replace("15 minutes", "999 minutes")
    return row


def _invented_text(row: dict) -> dict:
    row["remediation"] = "Totally invented remediation text."
    return row


def _audit_targets_the_wrong_subcategory(row: dict) -> dict:
    # The exact defect PR #123 fixed: details report one subcategory, the
    # command enables another. This is its standing regression guard.
    row["command"] = row["command"].replace("Sensitive Privilege Use", "Logon")
    return row


def _audit_drops_a_line(row: dict) -> dict:
    row["command"] = ""
    return row


def _audit_duplicates_a_line(row: dict) -> dict:
    row["command"] = row["command"] + "\n" + row["command"]
    return row


def _pass_row_takes_a_warn_branch(row: dict) -> dict:
    # Direct-conditional form (accounts.py): a PASS row carrying the branch that
    # only a FAIL produces.
    row["remediation"] = "Disable the built-in Guest account."
    return row


def _assigned_status_row_takes_another_branch(row: dict) -> dict:
    # Assigned-status form (smb.py): status comes from an if/elif/else chain.
    row["remediation"] = _row("SMB Signing Required")["remediation"] or "x"
    return row


def _risky_service_row_gains_text(row: dict) -> dict:
    row["remediation"] = "Totally invented remediation text."
    return row


def _fail_row_takes_the_pass_pair(row: dict) -> dict:
    # accounts.py binds status in an if-chain, then keys remediation and command
    # off `status is Status.PASS`. A FAIL outcome carrying the PASS blank pair
    # is something the runtime cannot produce.
    row["remediation"] = ""
    row["command"] = ""
    return row


def _outcome_swapped_within_one_status(row: dict) -> dict:
    # AutoPlay has three WARN outcomes with different remediation (key absent,
    # value NOTSET, partial 158). The sample machine's is the partial one; take
    # the NOTSET outcome's text from the real code so this can never drift.
    with mock.patch("apotrope.checks.misc.run_powershell", return_value="NOTSET"):
        other = misc._check_autoplay()[0].remediation
    assert other != row["remediation"], "the two outcomes no longer differ"
    row["remediation"] = other
    return row


def _audit_command_disables_instead_of_enabling(row: dict) -> dict:
    # Names the right subcategory and silences its auditing.
    row["command"] = row["command"].replace(
        "/success:enable /failure:enable", "/success:disable /failure:disable"
    )
    return row


def _severity_swapped(row: dict) -> dict:
    # encryption.py picks HIGH for the OS drive and MEDIUM otherwise; swapping
    # them leaves the score untouched for a PASS row, so only row-level
    # verification can see it.
    row["severity"] = "MEDIUM" if row["severity"] == "HIGH" else "HIGH"
    return row


def _status_flipped_pass_to_info(row: dict) -> dict:
    # Paired PASS→INFO / INFO→PASS flips preserve every global total.
    row["status"] = "INFO"
    return row


def _status_flipped_info_to_pass(row: dict) -> dict:
    row["status"] = "PASS"
    return row


def _pass_fields_under_warn_details(row: dict) -> dict:
    # The PASS outcome's (empty) fields presented alongside details only the
    # WARN outcome produces.
    row["status"] = "PASS"
    row["remediation"] = ""
    row["command"] = ""
    return row


def _details_gain_a_trailing_entry(row: dict) -> dict:
    row["details"] = row["details"].replace(
        ". Security-relevant", ", . Security-relevant"
    )
    return row


def _details_in_an_unrenderable_order(row: dict) -> dict:
    # misc.py renders subcategories in _EXPECTED_AUDIT order, where Logon
    # precedes Sensitive Privilege Use.
    row["details"] = row["details"].replace(
        "Sensitive Privilege Use", "Sensitive Privilege Use, Logon"
    )
    row["command"] = (
        row["command"] + "\n" + misc._CMD_AUDITPOL_ENABLE.format(subcategory="Logon")
    )
    return row


MUTATIONS = [
    pytest.param("AutoPlay Disabled", _swap_within_module, id="swap-command-within-module"),
    pytest.param("BitLocker — G:", _blank_a_field, id="blank-a-field"),
    pytest.param("BitLocker — G:", _wrong_runtime_value, id="placeholder-bound-to-wrong-value"),
    pytest.param("Screen Lock Timeout", _fabricated_threshold, id="fabricated-threshold"),
    pytest.param("BitLocker — G:", _invented_text, id="invented-text"),
    pytest.param("Audit Policy", _audit_targets_the_wrong_subcategory, id="audit-wrong-subcategory"),
    pytest.param("Audit Policy", _audit_drops_a_line, id="audit-missing-line"),
    pytest.param("Audit Policy", _audit_duplicates_a_line, id="audit-duplicate-line"),
    pytest.param("Guest Account", _pass_row_takes_a_warn_branch, id="branch-correlation-direct"),
    pytest.param("SMB Encryption", _assigned_status_row_takes_another_branch,
                 id="branch-correlation-assigned"),
    pytest.param("Risky Services", _risky_service_row_gains_text, id="risky-service-row"),
    pytest.param("Password Policy — Minimum Length", _fail_row_takes_the_pass_pair,
                 id="impossible-branch-combination"),
    pytest.param("AutoPlay Disabled", _outcome_swapped_within_one_status,
                 id="outcome-swapped-within-one-status"),
    pytest.param("Audit Policy", _audit_command_disables_instead_of_enabling,
                 id="audit-command-disables"),
    pytest.param("BitLocker — C:", _severity_swapped, id="bitlocker-c-severity-swapped"),
    pytest.param("BitLocker — G:", _severity_swapped, id="bitlocker-g-severity-swapped"),
    pytest.param("Guest Account", _status_flipped_pass_to_info, id="status-flip-pass-to-info"),
    pytest.param("PowerShell v2", _status_flipped_info_to_pass, id="status-flip-info-to-pass"),
    pytest.param("Audit Policy", _pass_fields_under_warn_details,
                 id="pass-fields-under-warn-details"),
    pytest.param("Audit Policy", _details_gain_a_trailing_entry,
                 id="details-trailing-entry"),
    pytest.param("Audit Policy", _details_in_an_unrenderable_order,
                 id="details-unrenderable-order"),
]


@pytest.mark.parametrize(("check_name", "mutate"), MUTATIONS)
def test_guard_rejects(check_name: str, mutate) -> None:
    row = _row(check_name)
    assert _verify_row(row) is None, f"{check_name} does not verify before mutation"
    assert _verify_row(mutate(row)) is not None, "the guard accepted a mutated row"


# ── Audit Policy wording ────────────────────────────────────────────────────

_AUDIT_SUFFIX = (
    " This can also be configured via Group Policy "
    "(secpol.msc → Advanced Audit Policy Configuration)."
)


@pytest.mark.parametrize(
    ("label", "remediation"),
    [
        ("fabricated policy path",
         misc._FIX_AUDIT_DISABLED + " TOTALLY WRONG POLICY AREA secpol.msc"),
        ("appended instructions", None),   # filled in below
        ("wrong outcome wording", misc._FIX_AUDIT_UNREPORTED + _AUDIT_SUFFIX),
    ],
)
def test_audit_remediation_must_equal_the_wording_for_its_outcome(
    label: str, remediation: str | None
) -> None:
    """Anything but the exact wording the real outcome produces is rejected."""
    row = _row("Audit Policy")
    row["remediation"] = (
        row["remediation"] + " Also, email the auditor."
        if remediation is None else remediation
    )
    assert _verify_row(row) is not None, label
