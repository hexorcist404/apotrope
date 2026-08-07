"""Guard: every external GitHub Action this repo runs must be pinned to a commit SHA.

A Git tag is a mutable pointer, not a version. ``actions/checkout@v4`` resolves to
whatever commit ``v4`` names *at the moment the job starts*, and the upstream owner can
repoint it at any time — every consumer picks that up on the next run with no diff and
no review. That is how the ``tj-actions/changed-files`` compromise propagated in March
2025. A 40-character SHA is the only ref form that commits to *content* rather than to
a name.

The stakes are not uniform across these four files. ``publish.yml``'s final job holds
``id-token: write`` for PyPI trusted publishing, so code running there can mint a fresh
OIDC identity and publish as apotrope without stealing any stored secret.
``release.yml`` holds ``attestations: write`` — a compromise there ships a bad artifact
carrying *valid* provenance, which is worse than shipping none.

Scanning is regex over lines, deliberately, and not a YAML parse: PyYAML is not a
declared dependency, and ``pyproject.toml``'s dev extras carry an explicit argument for
keeping that set tight and exactly pinned. A workflow lint is not what should spend
that budget.

Two bounds of the line-based approach, recorded rather than left implicit:

* A line *inside* a ``run: |`` block that exactly matches the anchored ``uses:`` shape
  below would be a false positive. No workflow contains one, and it would fail loudly
  and legibly if one were ever added — cheaper than the indentation tracking a real
  block-scalar parse needs.
* Commented lines are skipped, the same view ``_uncommented_lines()`` in
  ``tools/command_audit.py`` takes, because a commented ref executes nothing. Note the
  direction of that convention: the defect recorded in issue #108 was an assertion that
  read *dead* lines as though they were live — a false negative about real code.
  Skipping comments here applies that principle rather than contradicting it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# A floor, not an exact count: adding a step must not require editing this number, but
# a scanner that silently stops matching must not be able to pass by finding nothing.
MIN_EXPECTED_REFS = 18

# Anchored to the structural shape of a YAML key rather than searching for the substring
# "uses:" anywhere on the line. That anchoring is what keeps a `uses:` mentioned inside
# a run: block or a prose comment from registering as configuration.
#
# The mandatory whitespace before "#" is YAML's own rule for an inline comment, so
# `foo@abcdef#v1` is correctly read as one scalar with no comment rather than as a ref
# plus a version.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?:\s+#\s*(?P<comment>.*?))?\s*$")

_SHA = re.compile(r"^[0-9a-f]{40}$")

# Dependabot and Renovate both write and rewrite this comment when they bump a pin. It
# is the machine contract that keeps future diffs readable — without it a version bump
# is two indistinguishable hex strings.
_VERSION_COMMENT = re.compile(r"^v\d")

# Refs that name something other than a mutable upstream tag: a local action in this
# repo, or a container image resolved by the registry rather than by Git.
_UNPINNABLE_PREFIXES = ("./", "docker://")


@dataclass(frozen=True)
class ActionRef:
    """One `uses:` reference, located well enough to fix without searching."""

    path: str
    line: int
    ref: str
    comment: str | None


def _collect_refs(text: str, path: str) -> list[ActionRef]:
    """Extract every executing `uses:` reference from *text*."""
    refs: list[ActionRef] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        match = _USES.match(raw)
        if match is None:
            continue
        refs.append(ActionRef(
            path=path,
            line=lineno,
            ref=match.group("ref").strip("\"'"),
            comment=match.group("comment"),
        ))
    return refs


def _violation(ref: ActionRef) -> str | None:
    """Return why *ref* is unacceptable, or None if it is correctly pinned."""
    if ref.ref.startswith(_UNPINNABLE_PREFIXES):
        return None

    _, sep, rev = ref.ref.partition("@")
    if not sep:
        return "no ref at all — expected owner/repo@<40-character commit SHA>"
    if not _SHA.match(rev):
        return f"moving ref {rev!r} — expected a 40-character lowercase commit SHA"
    if ref.comment is None or not _VERSION_COMMENT.match(ref.comment):
        return "pinned, but missing the trailing '# vX.Y.Z' comment that keeps the diff readable"
    return None


def _workflow_files() -> list[Path]:
    return sorted(p for pattern in ("*.yml", "*.yaml") for p in WORKFLOW_DIR.glob(pattern))


def _all_refs() -> list[ActionRef]:
    return [
        ref
        for path in _workflow_files()
        for ref in _collect_refs(
            path.read_text(encoding="utf-8"),
            path.relative_to(ROOT).as_posix(),
        )
    ]


def test_all_external_actions_are_sha_pinned() -> None:
    """No workflow may reference an external action by anything but a commit SHA."""
    problems = [(ref, why) for ref in _all_refs() if (why := _violation(ref)) is not None]
    if problems:
        report = "\n".join(
            f"  {ref.path}:{ref.line} — {why}\n      {ref.ref}"
            for ref, why in problems
        )
        raise AssertionError(
            f"{len(problems)} workflow action reference(s) not pinned to a commit SHA:\n{report}\n\n"
            "Resolve the tag with `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha` "
            "and pin it as `owner/repo@<sha> # <tag>`."
        )


def test_scanner_finds_the_full_inventory() -> None:
    """The scanner must extract every ref, or the guard above passes vacuously.

    Zero refs found reads identically to zero violations. This repo has shipped that
    exact failure twice: the ``_mock_name`` probe in ``test_hermeticity.py`` that passed
    whether or not the guard was installed, and the substring assertions recorded in
    issue #108, which matched a commented line as happily as an active one and let
    session-severing commands through roughly a thousand tests for seven weeks.
    """
    files = _workflow_files()
    assert files, f"no workflow files found under {WORKFLOW_DIR} — has the layout moved?"

    refs = _all_refs()
    assert len(refs) >= MIN_EXPECTED_REFS, (
        f"expected at least {MIN_EXPECTED_REFS} action references across {len(files)} "
        f"workflow file(s), extracted only {len(refs)} — did the _USES pattern stop matching?"
    )


# (workflow line, is it expected to be reported as a violation)
_PLANTED_LINES: tuple[tuple[str, bool], ...] = (
    # Correctly pinned, in both the "- uses:" and bare "uses:" positions.
    ("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0", False),
    ("        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0", False),
    # Quoted, but still pinned — the quotes are YAML syntax, not part of the ref.
    ('      - uses: "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" # v4.4.0', False),
    # Not pinnable by SHA, and not expected to be.
    ("      - uses: ./.github/actions/local-thing", False),
    ("      - uses: docker://alpine:3.19", False),
    # Moving refs — the whole point of the guard. A branch ref is the weakest of these.
    ("      - uses: actions/checkout@v4", True),
    ("      - uses: pypa/gh-action-pypi-publish@release/v1", True),
    ("      - uses: actions/checkout@main", True),
    # 39 hex: a truncated paste is the realistic way a SHA pin goes wrong.
    ("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af67726 # v4.4.0", True),
    # Uppercase hex resolves fine in Git, but is not the form Dependabot reads or writes.
    ("      - uses: actions/checkout@11D5960A326750D5838078E36CF38B85AF677262 # v4.4.0", True),
    # Pinned but unreadable: no version comment at all, and a non-version comment.
    ("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262", True),
    ("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # latest", True),
    # No ref whatsoever.
    ("      - uses: actions/checkout", True),
)

# Lines that must not register as configuration at all.
_IGNORED_LINES: tuple[str, ...] = (
    "# - uses: actions/cache@v4",
    "      # - uses: actions/cache@v4",
    "      # Historically this step used actions/checkout@v2.",
    "      - name: Run tests",
    "        run: pytest tests/ -q",
    "          echo 'the upstream docs say uses: foo/bar@v1'",
)


@pytest.mark.parametrize(("line", "expected_violation"), _PLANTED_LINES)
def test_scanner_verdict_on_planted_lines(line: str, expected_violation: bool) -> None:
    """The detector must fire on planted defects, independent of the tree being clean.

    ``test_all_external_actions_are_sha_pinned`` passing proves the workflows are clean
    *if* the detector works. These planted lines are what prove the second half.
    """
    refs = _collect_refs(line, "planted.yml")
    assert len(refs) == 1, f"expected exactly one ref parsed from {line!r}, got {len(refs)}"

    why = _violation(refs[0])
    assert (why is not None) is expected_violation, (
        f"{line!r} was {'not ' if why is None else ''}reported "
        f"but should have been {'reported' if expected_violation else 'accepted'}"
        + (f" — {why}" if why else "")
    )


@pytest.mark.parametrize("line", _IGNORED_LINES)
def test_scanner_ignores_non_configuration_lines(line: str) -> None:
    """Commented refs and prose must not register — only what actually executes does."""
    assert _collect_refs(line, "planted.yml") == []
