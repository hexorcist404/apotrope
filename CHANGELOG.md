# Changelog

All notable changes to Apotrope are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.0] - 2026-07-27

### Security

- **The report's ⧉ Copy button now puts CRLF on the clipboard, and can report a
  failed copy.** Multi-line remediation pasted into an elevated PowerShell window
  executed **in reverse order** — last line first — which for the LLMNR command
  meant the `$key` assignment ran last and the two lines depending on it failed.
  The cause was the line endings: the HTML parser normalises CRLF to bare LF
  inside attribute values, so `getAttribute('data-cmd')` handed the script
  LF-only text no matter what the file contained, and Windows clipboard text is
  conventionally CRLF. Confirmed by controlled A/B on Windows Terminal 1.24 with
  pwsh 7.6 / PSReadLine 2.4: the same three lines pasted 3-2-1 as LF and 1-2-3 as
  CRLF, while Notepad accepted either form correctly — so the clipboard content
  was never wrong, only its line endings. The button also announced `✓ Copied`
  unconditionally, with no fallback when `navigator.clipboard` is unavailable
  (these reports are built to be emailed and opened over `file://`, where it is
  not guaranteed) and no handler for a rejected write. It now falls back to
  `execCommand` and shows a distinct failure state, so a failed copy can never
  again be mistaken for a good one.


- **The BitLocker remediation now hands the operator the recovery password.**
  Both commands created a recovery-password protector and never showed the
  48-digit key. `Enable-BitLocker` and `Add-BitLockerKeyProtector` return a
  volume object whose default table renders the protector *types*; the password
  lives in `.KeyProtector[].RecoveryPassword` and was never printed. So the
  operator pasted an elevated block, saw a success-looking table, and kept no
  copy — while the only surviving copy sat in volume metadata that the recovery
  prompt cannot read. Any later TPM change (firmware update, board swap,
  boot-order change) would have stranded them at a recovery screen they could
  not pass. Both commands now read the password back before the operator can
  reboot, and carry commented `Backup-BitLockerKeyProtector` /
  `BackupToAAD-BitLockerKeyProtector` steps for domain- and Entra-joined hosts.
  A new `bitlocker-no-key-escrow` lint rule keeps it from regressing.

- **Account remediations no longer risk the operator's own access.** Disabling
  the built-in Administrator shipped as an active line — and that finding fires
  precisely when RID-500 is *enabled*, which on a standalone or freshly imaged
  host is often because it is the account in use. It also renamed first, so the
  account could not afterwards be found by name, and hardcoded `RenamedAdmin`,
  which gives up the only thing renaming buys you. The rename now takes a name
  the operator chooses, the block lists every administrator and whether each is
  enabled, and the disable is commented behind that check. Likewise the
  "too many administrators" remediation shipped an active
  `Remove-LocalGroupMember` against a fabricated `CORP\svc_backup`; it is now
  commented, preceded by `whoami`, and no longer presents an invented account as
  though it were real.

- **The Spectre/Meltdown remediation no longer hides a failed write.**
  `-ErrorAction SilentlyContinue` on `Remove-ItemProperty` meant an ACL-protected
  key — or a GPO Preference re-creating the values — produced output identical to
  success. It now tests for each value, removes only what is present, reports
  what it did, and lets a real failure surface.

- **Remediations that could cut the operator's own connection are now commented
  manual steps.** Disabling RDP (`fDenyTSConnections=1`), tearing down the whole
  Remote Desktop firewall group, and stopping or disabling WinRM all shipped as
  *active* lines under a comment that merely said "if it is not required" — the
  line below still ran when the block was pasted. On a headless host with no
  console or out-of-band access that is unrecoverable; inside a PSSession the
  shell dies mid-block, so whether the remaining lines ran is indeterminate. The
  WinRM block additionally ran *both* halves of an either/or: it stopped the
  service and then tried to configure it, which fails. Basic-auth hardening is
  now the active step and the teardown is commented, matching the treatment
  `network.py` already used for port-3389 scoping.

- **The NetBIOS remediation no longer hides its own failure.** It piped
  `Invoke-CimMethod` to `Out-Null`. WMI reports failure through a `ReturnValue`,
  not a PowerShell error, so `-ErrorAction` and `$?` never see it —
  `SetTcpipNetbios` returns 1 for "succeeded, REBOOT REQUIRED" as routinely as 0.
  The operator got a clean prompt, never rebooted, NBT-NS kept answering, and
  Apotrope reported the host remediated while Responder-style relay still
  worked. The result is now captured and each outcome reported per adapter.

- **The unquoted-`ImagePath` remediation no longer writes.** It overwrote a
  boot-critical registry value with `-Force` and no backup, driven by a
  heuristic that cannot be correct in general — an unquoted path is ambiguous by
  definition, so which token is the executable is not decidable from the string.
  It also read the value with `Get-ItemProperty`, which *expands* a
  `REG_EXPAND_SZ`, so `%SystemRoot%\...` came back as `C:\WINDOWS\...` and
  writing it back baked the resolved path in permanently — the opposite of what
  the block's own comment promised. It now reads with
  `DoNotExpandEnvironmentNames`, prints the current and proposed values, and
  ships the write commented behind a backup step.

- **Removed two machine-damaging remediations from copy-paste output.** The "TPM
  present but not ready" finding shipped `Initialize-Tpm -AllowClear
  -AllowPhysicalPresence`, where `-AllowClear` can wipe the TPM, invalidate
  BitLocker protectors and force recovery; it is now a read-only `Get-Tpm`. The
  uptime and `EnableLUA` remediations ended in a bare `Restart-Computer`, so
  pasting either block restarted the machine unattended; both are now commented
  manual steps. A new `destructive-command` lint rule in `tools/command_audit.py`
  fails the build if any of them come back.
- **`powershell.exe` is resolved by absolute path.** Invoking it by bare name let
  Windows search the application directory and CWD first, so an elevated
  `apotrope.exe` sitting beside a malicious `powershell.exe` would execute
  attacker code elevated. The path now comes from `GetSystemWindowsDirectoryW`
  (not `%SystemRoot%`, which the parent process controls), and `SystemRoot`,
  `windir` and `PATH` are pinned in the child environment.
- **The AutoPlay remediation no longer destroys unrelated policy.** It led with
  `New-Item -Path '...\Policies\Explorer' -Force`, which on the registry provider
  replaces the key and deletes every value under it — including
  `NoRecentDocsHistory`, `NoActiveDesktop` and friends. The create is now guarded
  by `Test-Path`.

### Changed

- **Exit code 2 now means "the result is not trustworthy"**, not merely "a fatal
  scan error". It additionally covers zero controls evaluated, one or more checks
  errored, and a requested output file that could not be written. Treat 2 as *do
  not gate on this run* rather than as a failing posture.
- **`--profile` fails closed.** A profile requested explicitly that is missing or
  unparseable now exits 2 instead of silently falling back to defaults and
  scanning a different set of checks than asked for. An auto-discovered
  `apotrope.toml` still warns and falls back.
- **`--baseline` is skipped, with a warning, when the scan was not trustworthy**,
  so a good baseline is never overwritten by a scan we are about to reject.
- **All four output paths are validated before the scan**, for collisions and for
  writability, instead of failing after the work is done.
- **Password policy is reported per control when it cannot be read.** A failed
  `secedit` export previously collapsed Minimum Length, Account Lockout and
  Complexity into one differently-named result, which removed three CIS-mapped
  rows from the report instead of degrading them to ERROR.

### Fixed

- **Password policy is evaluated on non-elevated scans again.** `secedit /export`
  reads a database ACL'd to SYSTEM and Administrators, so the documented
  run-without-admin invocation could not read password policy and reported all
  three controls as ERROR. ERROR is score-neutral, so a machine with a minimum
  password length of 0 lost a HIGH FAIL and scored *higher* for being
  unmeasurable — biased so that weak machines were the ones told they were fine.
  Minimum length and account lockout now come from `NetUserModalsGet`, which a
  standard user can read and which returns integers rather than the localized
  text `net accounts` prints, so it does not reintroduce the locale dependence
  that moving to `secedit` removed. Measured on a Windows 11 host: a non-elevated
  scan went from 87/B back to 77/C, matching the elevated result. Password
  complexity is an LSA setting with no unprivileged equivalent and is still
  reported as requiring elevation rather than guessed.

- **Security principals are identified by SID, not by localized display name.**
  The built-in Administrator/Guest are matched on RID suffix (`-500`/`-501`) and
  the Administrators group by `S-1-5-32-544`, so a renamed account or a
  non-English install is no longer reported as "not found". An empty
  Administrators group is an ERROR rather than a reassuring "0 administrators"
  PASS, since that group always has at least one member.
- **Checks fail closed on uncertainty.** Unreadable or access-denied state across
  TPM, Secure Boot, PowerShell v2, audit policy, UAC, RDP and firewall now
  reports INFO or ERROR instead of a confident PASS or a scored WARN that
  penalises a healthy machine.
- **Firewall profiles cannot silently vanish** — a missing profile is a
  HIGH-severity ERROR (`Firewall — Profiles Present`) rather than an absent row.
- **Policy-managed RDP findings point at the controlling GPO** instead of emitting
  a local-registry command the policy overrides on its next refresh.
- **Locale-neutral firewall selectors** — `-Group '@FirewallAPI.dll,-28752'`
  replaces the localized `-DisplayGroup 'Remote Desktop'`, which matched nothing
  on non-English Windows and no-opped without a visible error.
- Duplicate entries in the `checks.MODULES` registry were imported twice and
  their FAIL/WARN results double-deducted from the score.
- Several verdict bugs: BitLocker mid-encryption is a WARN rather than a PASS,
  the Int32/UInt32 join that made every listening port report "Unknown", a
  dropped DHCP adapter, and an unbounded OS end-of-life fallback.

### Dev/CI

- **`requirements.txt` removed; `pyproject.toml` is the only dependency source.**
  Nothing installed from it — every CI job, the release build and the publish
  workflow all use `pip install -e ".[dev]"` — but GitHub's dependency graph read
  it as a manifest, so it double-counted every package and filed alerts against
  pins that determined nothing. It had also drifted: it pinned `pytest==9.0.3`
  against a `>=8.0` floor and `markupsafe==2.1.5` against a resolve that produces
  3.x, and it omitted `ruff` and `mypy` entirely, so it could not reproduce a CI
  environment even if someone had installed from it.
- **Dependency floors now sit at the highest advisory-patched version.** Those
  stale pins were masking the fact that the declared ranges still permitted
  vulnerable builds: `jinja2>=3.1` allowed every 3.1.x below 3.1.6, and
  `pillow>=12.0` allowed the versions patched in 12.3.0. A range that permits a
  vulnerable build is one a constrained or offline resolve can pick, and it is
  what Dependabot alerts against. Now `jinja2>=3.1.6,<4` and `pillow>=12.3`;
  `rich` has no known advisories and keeps its API-based floor.
- `ruff` and `mypy` are now enforced CI gates, at exact pinned versions rather
  than floors, with a repo-owned rule set so upstream default churn cannot turn
  the build red without a code change.
- Tests are hermetic: an autouse guard fails any test that reaches the real
  `subprocess` boundary (opt out with `@pytest.mark.allow_subprocess`). The
  mocked suite dropped from ~22s to ~4s.
- Publishing is gated on the tag matching `pyproject`'s version and on a Windows
  job that installs the built wheel and smoke-tests it against the check registry
  and the packaged templates.

---

## [0.1.12] - 2026-07-16

### Added
- **Executive report (`--exec-report FILE`) — the Security Posture Assessment.** A
  plain-English, print-first HTML document for non-technical decision makers: cover
  with grade box and generated verdict, executive-summary narrative built strictly
  from scan data, posture-at-a-glance tiles and result distribution, a P1/P2/P3
  prioritized remediation roadmap, detailed findings with per-category business-impact
  context, a passed-controls attestation appendix, and a remediation-commands appendix.
  Self-contained, script-free, letter-size print CSS (editorial serif direction from
  the design system). When `--html` and `--exec-report` are generated in the same run,
  the technical report's header links to the executive report ("Executive Report ↗").
- **`brand/tokens.json` — single source of truth for the brand palette.** Codifies the
  two canonical layers from the design system (the `mark` — cyan/mint/ember on void
  ground `#0B0D0E` — and the `product` CRT/status palette) with the rules that travel
  with them (never recolor the ember iris; the status scale must not drift). New
  `tests/test_brand_assets.py` fails CI if the icon SVGs drift from these tokens.
- **Vector icon masters `assets/icon.svg` + `assets/icon-16.svg`.** The eye-mark on its
  void ground, with a small-size variant (spokes dropped, strokes thickened) for
  legibility at 16–24 px.
- **Top-Issues remediation toggle carries a full ARIA disclosure contract.** The
  "show remediation command" control in the HTML report's Top Issues panel now exposes
  `aria-expanded`/`aria-controls` (pointing at the command block) with an `aria-hidden`
  chevron, kept in sync by the toggle script, so assistive technology announces the
  disclosure correctly.
- **The CLI rejects `--html` and `--exec-report` resolving to the same file.** Passing
  the same path — or two paths that resolve to one file — for the technical and
  executive reports now fails fast with an argument error before any scan runs, instead
  of letting one report silently overwrite the other.

### Changed
- **Executable icon is now the official Apotrope brand mark.** `apotrope.exe` ships with
  the eye-mark logo (cyan hexagon, orbital ring, ember core) on a rounded tile,
  replacing the procedurally generated blue "A"-on-shield. `build_exe.py` composites the
  brand mark into the multi-resolution `assets/icon.ico` (16→256 px); the tile color is
  read from `brand/tokens.json` (`mark.ground` `#0B0D0E`) rather than hardcoded, so it
  can't drift from the palette, and the 16 px frame uses the simplified `icon-16.svg`
  master so it stays crisp instead of muddying the intricate mark.
- **The technical HTML report (`--html`) is redesigned to the design-system prototype.**
  Finding rows now lead with a solid status pill and a status-colored left-accent bar
  instead of a single glyph; severity is shown only on FAIL/WARN; PASS and INFO rows are
  de-emphasized (dimmed, no bar) until you hover or expand them, while ERROR rows stay at
  full strength.
- **Remediation commands render in a cyan "Elevated PowerShell · run as Administrator"
  console** with per-line `PS>` prompts and muted `#` comment lines. The copy button now
  reads the raw command from a `data-cmd` attribute, so the prompt and markup never reach
  the clipboard.
- **The Top Issues panel surfaces critical- and high-severity findings only** (cap raised
  from 5 to 8), each with an inline, expandable remediation command and a "+ N additional
  open findings" link to the full breakdown.
- **Category Scores switched from animated bars to a plain numeric "N / 100" list.**
- **The report header shows an animated glitch wordmark**, and the CRT scanline/glow
  atmosphere now defaults to calm (only the wordmark glitch stays on) and honors
  `prefers-reduced-motion`; print styles were updated for the new row accents and command
  syntax.
- **The executive report's scope line now says Apotrope "attempted" N controls** (was
  "evaluated"), so the wording stays accurate when some checks error out.
  
### Fixed
- **Baseline comparison no longer reports errored checks as resolved.** A check that was
  FAIL/WARN in the baseline but could not be evaluated in the current scan (status ERROR)
  was miscounted as remediated. Such checks now appear in a dedicated "Errored (could not
  evaluate)" category — indeterminate, never resolved — mirroring how checks that drop out
  of coverage are already handled.
- **HTML report footer now reads "No data leaves this machine"** (was the
  grammatically-off "No data left this machine").
- **The executive report can no longer claim "all clear" when checks errored.** The cover
  verdict, executive summary, bottom line, and findings section now state that the
  assessment is incomplete and name how many controls could not be evaluated; a category
  is credited as passing only when every one of its results is PASS.
- **Baseline comparison (`--compare`) flags an indeterminate score delta when coverage is
  incomplete.** Any check with status ERROR, or any check that dropped out of coverage,
  now renders the delta in yellow as "±N raw · indeterminate" instead of a confident
  green/red change.
- **Remediation commands now run on a stock elevated shell.** An audit of every
  copy-paste command Apotrope emits corrected four that failed outright and seven that
  ran without achieving the fix. NetBIOS uses `Invoke-CimMethod` (was a method call on an
  inert `Get-CimInstance` object); the risky-port firewall rule supplies the mandatory
  `-DisplayName` (was hanging on a prompt); the built-in Administrator fix targets the
  RID-500 SID (was renaming the account then disabling it by its old name); Windows Update
  leads with the built-in `ms-settings:windowsupdate` path (was a bare `Install-WindowsUpdate`
  from a module absent by default). Password complexity now sets the policy via
  `secedit /configure`; PowerShell script-block and module logging write typed REG_DWORD
  values and module logging creates the required `ModuleNames\*` subkey; BitLocker guards
  the OS edition and adds a recovery-password protector; the Telnet and unquoted-service-path
  fixes guard for absent services and preserve `REG_EXPAND_SZ`. The sample reports were
  re-rendered to show the corrected commands.

### Dev/CI
- **Brand-asset drift guards expanded across every palette consumer.**
  `tests/test_brand_assets.py` now validates the committed multi-frame `assets/icon.ico`
  (frame sizes and mark-ground coverage, via Pillow), both SVG masters' visible colors,
  and the reporter terminal constants plus the report/site CSS variables against
  `brand/tokens.json`. Adds a `pillow>=12.0` dev dependency and a dedicated CI step that
  validates the committed brand assets; the exe-build CI step now builds with the real
  icon. `.superpowers/` is gitignored.
- **Remediation commands are linted so a broken one can't ship again.** The per-check
  tests only assert command substrings, which cannot catch a command that fails to run.
  `tools/command_audit.py` + `tests/test_remediation_commands.py` statically extract every
  emitted command and reject the shipped failure classes (CIM-object method calls,
  `New-NetFirewallRule` without `-DisplayName`, a bare `Install-WindowsUpdate`, `<…>`
  placeholders); a Windows-only `tools/verify_commands.py` harness additionally
  PowerShell-parses each command and resolves every cmdlet it invokes.

## [0.1.11] - 2026-07-06

### Added
- **Clickable executive-summary counters in the HTML report.** The passed / failed /
  warnings / info counters are now real buttons: clicking one (or focusing it and
  pressing Enter) applies the matching results filter and jumps to the results list.
  They reuse the existing filter-tab logic and carry hover and focus affordances.

### Fixed
- **Report expand/collapse actually hides row details.** Clicking a finding's header
  (or the EXPAND ALL / COLLAPSE controls) now toggles the detail body — previously the
  caret rotated but the body never hid, because no CSS rule beat the grid display on
  `[hidden]` rows. FAIL/WARN findings render expanded by default; PASS/INFO collapsed.
- **TPM firmware version no longer carries NUL bytes.** `Get-Tpm`'s
  `ManufacturerVersion` can include trailing NUL characters from the firmware WMI
  string; they are now stripped before the value reaches report output, falling back
  to "Unknown" when nothing printable remains.

### Docs
- **README terminal screenshots recaptured with v0.1.10.** Both `assets/screenshots/`
  captures now show the current release (75/100 C demo) and the same WORKSTATION-07
  machine as the site's sample report and homepage demo.
- **Sample report refreshed to v0.1.10.** `docs/report.html` is now a real (sanitized)
  v0.1.10 scan — 53 checks, 75/100 (C) — showcasing the remediation-caution and
  share-safely banners added in this release. The homepage terminal demo is aligned
  to the same scan (score, check counts, top failures).
- **COMPARE nav dropdown.** The three comparison pages (vs CIS-CAT, vs Harden Windows
  Security, Lynis for Windows) now live under a single COMPARE dropdown in the site
  nav instead of three separate links.
- **pip vs release-exe integrity channels clarified.** The README and the homepage
  download steps now explain which integrity guarantees apply to each install channel:
  SHA-256 + CI build provenance for the release exe, PEP 740 attestations on PyPI for
  pip installs.
- **Security contact email updated** in `SECURITY.md`.

## [0.1.10] - 2026-07-04

### Added
- **Report-sharing safety guidance.** The README gains a "Sharing reports safely" note,
  and the HTML report footer now warns that a report embeds the host's name, account
  names, services, and configuration — review/redact before sharing it outside your
  organization. Apotrope still never uploads anything; this is about the saved file.
- **Caution banner on remediation commands.** Each copy-paste PowerShell command in the
  HTML report now carries a "review before running — runs elevated and can change system
  settings or require a reboot/maintenance window" note next to its copy button.

### Changed
- **`psutil` removed from runtime dependencies.** It was declared in `pyproject.toml`
  but imported nowhere, needlessly inflating the install and the PyInstaller bundle.
  `build` and `twine` (used by the release workflow) are now declared in the `[dev]`
  extra so the dev toolchain is described where it is used.
- **PyInstaller no longer writes a top-level `build/` directory.** `build_exe.py` nests
  its work directory and generated spec under `.pyinstaller/`, so a local exe build no
  longer shadows the PyPA `build` package when running `python -m build` from the repo
  root.

### Fixed
- **OS End-of-Support check is now edition- and SKU-aware and uses the correct
  consumer (Home/Pro) lifecycle dates.** The build→lifecycle table previously
  carried Enterprise/Education end-of-servicing dates under a "Home/Pro" label,
  so a Windows 11 24H2 Home/Pro machine was reported supported until 2027-10-12
  instead of 2026-10-13, and 23H2 was shown supported roughly a year past its
  actual consumer end of servicing. It also mapped any build ≥ 26100 to "Windows
  11 24H2", mislabelling Windows 11 25H2 (build 26200), 26H1 (28000), and Windows
  Server 2025 (build 26100, which shares 24H2's build). The check now resolves a
  `(client|server, build)` key using `Win32_OperatingSystem.ProductType`, carries
  Home/Pro dates for client releases and extended-support dates for server
  releases, and adds 25H2, 26H1, and Windows Server 2025. Builds newer than the
  known table now WARN ("verify on the Microsoft release-health page") instead of
  silently inheriting the newest known release's support date.
- **Profile update-age thresholds no longer leak between scans in one process.**
  `updates.configure()` mutated module-level globals that were never restored, so a
  `Scanner` reused as library code (or a second `Scanner` with a different profile) could
  silently keep a previous scan's thresholds. The scanner now restores a module's
  thresholds after each run via a new `updates.reset()`.
- **Imported baseline timestamps with a non-UTC offset are converted, not relabeled.**
  `compare.load_baseline()` used `.replace(tzinfo=utc)`, which preserved the wall-clock
  and shifted the instant (e.g. `10:00-04:00` became `10:00Z` instead of `14:00Z`).
  Offset-aware timestamps are now converted with `astimezone(utc)`; naive timestamps are
  still assumed UTC.
- **Shared PowerShell helpers escape interpolated string arguments.** `read_registry()`
  and `get_wmi_object()` now double single quotes in registry paths/value names and WMI
  class/namespace/property names before building the command, so a quote in a (future,
  dynamic) argument cannot break out of the PowerShell string literal.
- **Windows Defender / AV status now distinguishes "unknown" from "disabled."** When
  `Get-MpComputerStatus` is unavailable (Server Core without the Defender module, the
  module fails to load, or access is denied) the check reports a single INFO "status could
  not be determined" instead of a synthetic all-disabled result that surfaced as a CRITICAL
  real-time-protection failure. Defender running in **passive mode** (a third-party AV is
  the active provider, detected via `AMRunningMode`) is likewise reported as INFO, not a
  CRITICAL fail. And an empty Windows Security Center result on a **Server SKU** — where
  `root\SecurityCenter2` is a client-only feature — now reports INFO rather than a spurious
  "no antivirus registered" CRITICAL. A genuinely disabled Defender (the cmdlet succeeds and
  reports protection off) still correctly fails CRITICAL.

### Docs
- **README: Harden Windows Security (HotCakeX) joins the comparison table,** which
  also gains an Automation row, plus a new FAQ section ("How is this different from
  Harden Windows Security?", download verification, CIS affiliation) and a "Verify
  Your Download" section documenting build-provenance attestations, SHA-256
  checking, and the PyPI trusted-publishing channel as the exe-free alternative.
- **SECURITY.md explains why PowerShell subprocesses use `-ExecutionPolicy Bypass`**
  (read-only queries, nothing written to disk, machine policy unchanged),
  cross-referencing the README's "How Apotrope queries your system" section.

### CI
- **Version-tag releases are now built, attested, and drafted by CI.** A new
  `release.yml` builds `apotrope.exe` on `windows-latest` for every `v*` tag, runs
  the test suite, generates `SHA256SUMS`, attaches a GitHub build-provenance
  attestation (`actions/attest-build-provenance`, verifiable with
  `gh attestation verify`), and creates a **draft** GitHub release with both files
  attached. The maintainer performs the on-hardware rendering check against the exe
  downloaded from the draft, then publishes it — the published exe is always the
  CI-built artifact, never a local build, and the workflow refuses to modify a
  release once it has been published.
- **PyPI attestations pinned on.** `publish.yml` now passes `attestations: true`
  explicitly (PEP 740 provenance was already the Trusted Publishing default; now it
  cannot silently change with an upstream default).
- **A `build-exe` job builds and smoke-tests `apotrope.exe` on `windows-latest`**
  (`build_exe.py --no-icon`, then `--version` and `--dry-run`) and uploads the exe as a
  workflow artifact. This catches a broken or empty frozen build on every PR; it
  complements — and does not replace — the manual on-hardware check before a release,
  which CI cannot perform (console color/glyph rendering).

### Tests
- The HTML XSS-escaping regression test now also covers the `remediation` and `command`
  fields and an attribute-context (quote-breakout) payload, not just hostname/details.

---

## [0.1.9] - 2026-06-25

### Fixed
- **Terminal output now renders the brand colors and wordmark correctly in
  cmd.exe and PowerShell.** The packaged exe puts the console into UTF-8 +
  virtual-terminal mode and emits true 24-bit color instead of falling back to
  Rich's legacy 16-color Windows path, which downsampled the brand green
  (`#2bff88`) into cyan and could leave the wordmark glyph as a missing-glyph
  box under a legacy console code page. The live terminal now matches the
  generated screenshots.
- **The Windows Update Service check is deterministic.** It keys off the
  service *start type* rather than its momentary run state: a normally-idle
  (Stopped) Automatic/Manual `wuauserv` reports PASS, and only a **Disabled**
  start type is a WARN. Previously the service's normal idle-stop produced a
  shell- and timing-dependent WARN that changed the overall score between runs.

### Changed
- The terminal brand wordmark uses the filled-circle glyph (U+25CF), which is
  present in the default Windows console font (Consolas) so it renders without
  relying on font fallback; the ASCII fallback for legacy terminals is unchanged.

---

## [0.1.8] - 2026-06-24

### Added
- **Windows Server 2019 and 2016 are now detected via `ProductType`.** Builds
  shared by client and server SKUs — 17763 (Win10 1809 / Server 2019) and 14393
  (Win10 1607 / Server 2016) — previously always fell back to the Windows 10
  baseline. The scanner now reads `Win32_OperatingSystem.ProductType`
  (1 = Workstation, 2 = Domain Controller, 3 = Server) and threads it into
  `cis_map.family_for_build`, so these builds classify correctly. Server 2022
  (build 20348) still short-circuits and resolves even when WMI is unavailable.
  Backed by a new `OSFamily.SERVER_2016` and a `_SHARED_SERVER_BUILDS` table.

### Changed
- **Brand mark.** The ◈ diamond glyph is replaced by the transparent eye-mark
  logo across the website nav, the terminal banner, and the HTML report header.
  Reports embed the mark as a base64 data URI so they stay fully self-contained,
  with a graceful fallback to the ◈ glyph if the asset is missing.
- **OS family detection refactor.** The `is_win10` boolean is replaced by an
  `OSFamily` enum and an additive family registry. Server 2016/2019/2022 now
  carry an honest best-effort caveat noting they ride the Windows 10 v4.0.0 CIS
  baseline, rather than being silently stamped as a Windows 10 edition. Server
  2022's dedicated CIS mapping stays deferred — the official benchmark is
  registration-gated, so no control IDs were fabricated.
- **Scan comparison distinguishes remediated checks from lost coverage.** A
  baseline-only FAIL/WARN that is absent from the current scan now lands in a new
  `ScanDiff.missing_findings` bucket ("Not scanned (coverage lost)") instead of
  being mislabeled "Resolved".

### Fixed
- **`run_powershell_json` no longer treats empty output as fatal.** A PowerShell
  pipeline that matches zero rows now returns `[]` (mirroring `get_wmi_object`),
  so checks' "none found" paths are reachable. Renaming the built-in
  Administrator account (a CIS hardening step) now reports INFO instead of a
  confusing ERROR.

### CI
- **`publish.yml` runs the test suite before building and uploading.** Because
  `test.yml` does not run on tags, a `v*` tag could previously publish untested
  code; publication is now gated on the tagged commit passing tests.

### Docs
- SEO/GEO content, JSON-LD structured data, and accuracy fixes for apotrope.sh;
  added Open Graph / Twitter Card meta tags and a favicon.
- Standardized the check-count claim on "50+ checks across 14 categories" across
  all copy; dropped an outdated WinPosture repo-slug note from the changelog.

---

## [0.1.7] - 2026-06-12

### Changed
- **Triage view is now the default terminal output.** Every category with
  issues gets its own box listing each FAIL/WARN finding with its fix and a
  ready-to-paste PowerShell command — no flag needed. `--fix` is retired and
  kept only as a hidden no-op so existing scripts don't error; `--verbose`
  shows the same boxes for every category and check, passing ones included.
- **Error messages no longer tell elevated users to "run as Administrator".**
  When a check errors during an already-elevated scan, the terminal footer,
  scanner warning, and report summaries now point to `--log-level DEBUG` /
  per-check detail instead of suggesting elevation that wouldn't help.

### Fixed
- **PowerShell Execution Policy check no longer errors when Apotrope is
  launched from PowerShell 7.** pwsh 7 leaves its own Core-only module paths
  in `PSModulePath`; the Windows PowerShell 5.1 subprocesses then resolved
  `Microsoft.PowerShell.Security` to the PS7 copy and failed to load it.
  Apotrope now strips `PSModulePath` from check subprocesses so Windows
  PowerShell rebuilds its correct default.
- **`build_exe.py` can no longer ship an exe with zero check modules.**
  PyInstaller's `--collect-submodules` silently collected nothing unless
  apotrope was pip-installed in the build Python; the build script now puts
  `src` on `PYTHONPATH` for the build and probes the finished exe with
  `--dry-run`, failing loudly if no check modules are bundled.

### Docs
- All PowerShell run examples now use `.\apotrope.exe` (bare `apotrope.exe`
  fails in PowerShell, which doesn't run programs from the current folder by
  name) and `cd $env:USERPROFILE\Downloads` for navigation.
- README terminal screenshots regenerated for the triage-box output.

### Tests
- Rich terminal rendering paths in the reporter are now covered end-to-end,
  including the new admin-aware error hints and build-probe behaviors.

---

## [0.1.6] - 2026-06-06

### Added
- **Copy-paste-ready remediation commands.** Every failing/warning check now
  carries an exact, paste-ready PowerShell command alongside its plain-English
  explanation, split into a new `CheckResult.command` field.
  - **HTML report:** each FAIL/WARN finding shows the explanation plus a labeled
    "Windows PowerShell · run as Administrator" code block with a copy button
    that copies only the command. The findings filter also matches command text.
  - **Terminal:** new `--fix` flag prints a `TOP FIXES` block whose command
    lines are bare and paste-valid (no glyphs, rails, or prompts); `--verbose`
    prints every command verbatim under its finding. Honors `--no-color`.
  - **JSON:** the `command` field serializes automatically for SIEM/pipeline use
    and round-trips through `--compare` baselines.

### Changed
- Remediation strings are now pure prose (the *what & why*); the PowerShell to
  run lives in the new `command` field. Manual/firmware fixes (Secure Boot, OS
  upgrade) ship a commented note plus the closest verification cmdlet so the
  block is always safe to paste.

---

## [0.1.5] - 2026-06-02

### Changed
- First release published to PyPI through the automated trusted-publishing
  workflow (`pip install apotrope`). No functional changes from 0.1.4 — this
  release exists to exercise the OIDC publishing pipeline end to end.

---

## [0.1.4] - 2026-06-02

### Fixed
- **HTML reports now work when installed from PyPI.** The Jinja2 template
  (`report.html.j2`) shipped outside the package with no `package-data`, so
  wheels/sdists contained no template and `apotrope --html` failed on any
  `pip install`. The template now lives in `apotrope/templates/` and is
  packaged as package data; `reporter.py` loads it relative to the module.

### Changed
- First release published to **PyPI** (`pip install apotrope`).
- Renamed the PyInstaller build script `build.py` → `build_exe.py` so it no
  longer shadows the PyPA `build` package (`python -m build` was invoking
  PyInstaller instead of producing the sdist/wheel).

---

## [0.1.3] - 2026-06-02

### Changed
- **Renamed the project from WinPosture to Apotrope.** The Python package is now
  `apotrope`, the console script and bundled executable are `apotrope` / `apotrope.exe`,
  and all documentation, templates, and tests reference the new name. No functional
  audit logic changed.
- Build icon now renders an "A" glyph to match the new name.

---

## [0.1.2] - 2026-04-21

### Security
- Fixed Jinja2 autoescape silently disabled for HTML reports — `select_autoescape(["html"])` checks the last file extension, so `report.html.j2` resolved to `.j2` and autoescape was `False`. Changed to `autoescape=True`. Regression test added to catch future regressions.
- Locked GitHub Actions `claude.yml` to `author_association == 'OWNER'` only — previously had no `if:` guard, allowing any GitHub user to invoke Claude with `contents: write` permissions via an issue comment.

### Changed
- HTML report: score gauge enlarged (130 → 160 px) with larger typography for improved readability
- HTML report: category sections now collapse by default when all checks pass; only sections with failures, warnings, or errors expand automatically
- HTML report: ERROR stat box added (purple) — shown when any checks could not complete
- HTML report: `"Segoe UI"` moved to front of font stack (Windows-native tool, Segoe UI is always available on target systems)
- HTML report: executive summary now notes how many checks could not complete when `error_count > 0`
- README: added "How Apotrope queries your system" section explaining `-ExecutionPolicy Bypass` usage

### Fixed
- HTML report: categories containing only ERROR-status results no longer render collapsed (looked like passing categories)

---

## [0.1.1] - 2026-03-27

### Fixed
- Fixed Defender Tamper Protection check using wrong property (`TamperProtectionEnabled` → `IsTamperProtected`)
- Fixed Unquoted Service Paths check returning ERROR when no unquoted paths found (now correctly returns PASS)
- Fixed CIS benchmark version references (updated to current CIS Windows 11 v5.0.0 and Windows 10 v4.0.0)
- Corrected CIS control ID mappings against latest benchmark PDFs
- Removed non-existent `pip install apotrope` from README (not yet on PyPI)

### Changed
- Updated README checks table to include all 53 checks (was missing ~20)
- Added CIS Benchmark Mapping section to README
- Updated scoring table in README to match actual code deductions
- Added admin privilege note to "Why Apotrope?" section
- WARN deductions now broken out by severity level in documentation

---

## [0.1.0] - 2026-03-17

Initial public release.

### Added

**Core engine**
- `Scanner` orchestrates all check modules; auto-discovers `checks/*.py`
- `REQUIRES_ADMIN` module flag — scanner skips and emits an INFO result when
  not elevated, rather than failing or erroring
- Per-check timing (`check_duration`) recorded on every `CheckResult`
- `AuditReport.error_count` property for post-scan summaries
- `is_admin` flag propagated from scanner through to the report

**Check modules** (27 individual checks across 14 categories)
- Firewall: Domain / Private / Public profiles
- Antivirus: Windows Defender real-time protection and signature age
- Patching: Last hotfix date, Windows Update service, pending update count
- Encryption: BitLocker status per fixed drive (requires admin)
- Accounts: Local admin count, guest account, password policy
- Services: Risky/unnecessary running services (Telnet, SNMP, FTP, …)
- Network: Unexpected listening ports
- Startup: Startup program inventory
- SMB: SMBv1, SMB signing (requires admin)
- RDP: RDP state and NLA enforcement
- UAC: UAC consent prompt level
- PowerShell: Execution policy, script block logging, constrained language mode
- OS: Windows version and build info
- Misc: LLMNR, AutoPlay, Remote Registry, audit policy

**Scoring engine**
- 0–100 score with CRITICAL/HIGH/MEDIUM/LOW/WARN deductions
- Grade A–F with labels (Excellent → Critical)
- Per-category scores for the HTML report

**Terminal reporter** (Rich)
- Animated progress bar with module names, elapsed time, ETA
- Score bar with grade
- Pass/Fail/Warn/Info/Error summary counts
- Top issues panel (critical/high failures)
- Full verbose table on `--verbose`
- Non-admin warning banner when running without elevation
- Error count summary in footer
- ASCII fallbacks for legacy cp1252 terminals (cmd.exe)

**HTML report** (Jinja2, fully self-contained)
- CSS conic-gradient score gauge
- Executive summary paragraph (auto-generated)
- Per-category collapsible breakdown tables
- Detailed findings cards with inline remediation
- Appendix A: INFO inventory
- Appendix B: full check list
- Print-friendly CSS (`@media print`)
- Zero external dependencies (no CDN, no `<script src>`)

**JSON export**
- Full `AuditReport` serialization including all `CheckResult` fields

**CLI** (`apotrope`)
- `--html`, `--json`, `--category`, `--verbose`, `--no-color`, `--log-level`
- Exits 0 on clean scan, 1 if any failures
- `--version` flag

**Distribution**
- `pip install apotrope` via `pyproject.toml` (setuptools, src layout)
- Standalone `apotrope.exe` via `python build.py` (PyInstaller `--onefile`)
- `assets/icon.ico` — shield icon (generated by Pillow)
- GitHub Actions CI: pytest on Python 3.12 and 3.13, `windows-latest`

**Tests**
- 511 tests across 20 test files
- Full mock coverage for all PowerShell/registry/WMI calls
- Scanner, CLI, reporter, and scenario integration tests
