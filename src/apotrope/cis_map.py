"""CIS Benchmark reference mapping for Apotrope check results.

Maps check_name values to CIS Microsoft Windows Benchmark control IDs.
The base map (_PREFIX_MAP) uses CIS Microsoft Windows 11 Enterprise Benchmark
v5.0.0 IDs.  For Windows 10 / Server families, pass the matching ``OSFamily``
to ``lookup`` and the IDs that differ in CIS Microsoft Windows 10 Enterprise
Benchmark v4.0.0 are substituted from ``_WIN10_OVERRIDES`` automatically.

References are approximate — always verify against the current official
benchmark for your specific OS version and edition before use in a formal
compliance assessment.

─────────────────────────────────────────────────────────────────────────────
CIS MAPPING VERIFICATION SUMMARY (verified against Win11 v5.0.0)
─────────────────────────────────────────────────────────────────────────────
Key structural change between v3.0.0 and v5.0.0: many Administrative Template
sections under 18.9.x were renumbered to 18.10.x, and section 10 changed from
Malware Defenses to Network List Manager Policies. Defender controls are now
under 18.10.42.

VERIFIED CORRECT (unchanged):
  9.1.1   Firewall Domain Profile Enabled
  9.1.2   Firewall Domain Default Inbound
  9.2.1   Firewall Private Profile Enabled
  9.2.2   Firewall Private Default Inbound
  9.3.1   Firewall Public Profile Enabled
  9.3.2   Firewall Public Default Inbound
  1.1.4   Password Policy — Minimum Length
  1.1.5   Password Policy — Complexity
  1.2.1   Password Policy — Account Lockout (duration)
  2.3.1.1 Guest Account
  2.3.1.3 Built-in Administrator Account (Rename administrator account)
  2.3.17.2 UAC Admin Consent Behavior
  17.1.1  Audit Policy (Credential Validation)

UPDATED (old v3.0.0 ID → new v5.0.0 ID):
  10.3         → 18.10.42.10.3  Defender Real-Time Protection
  10.2         → 18.10.42.14    Defender Signature Age (Security Intelligence Updates)
  18.9.11.1.1  → 18.10.10       BitLocker Drive Encryption
  18.9.11.2    → 18.10.10.2.2   Secure Boot (Allow Secure Boot for integrity validation)
  18.4.11.2    → 18.4.2         SMBv1 Disabled (Configure SMB v1 client driver)
  2.3.8.3      → 2.3.9.2        SMB Signing Required (network server signing)
  2.3.8.5      → 18.6.8.7       SMB Encryption (Require Encryption)
  18.9.59.2.1  → 18.10.57.3.2.1 RDP Enabled
  18.9.59.2.2  → 18.10.57.3.9.4 RDP Network Level Authentication
  2.3.17.1     → 2.3.17.6       UAC Enabled (Run all admins in Admin Approval Mode)
  2.3.17.4     → 2.3.17.7       UAC Secure Desktop (Switch to secure desktop)
  2.3.17.5     → 2.3.17.3       UAC Standard User Behavior
  18.9.95.1.2  → 18.10.88.1     PowerShell Script Block Logging
  18.5.4.2     → 18.6.4.4       LLMNR Disabled (Turn off multicast name resolution)
  18.9.8.2     → 18.10.8.3      AutoPlay Disabled (Turn off Autoplay: All drives)
  18.9.102.1   → 18.10.90.2.2   WinRM Status
  18.9.101.1   → 18.10.94.2.1   Windows Update Service
  18.9.101.2   → 18.10.94.2.1   Last / Pending Windows Updates

NEEDS MANUAL REVIEW (no direct CIS admin template control in v5.0.0):
  Defender Tamper Protection  — Windows Security settings (18.10.93); no specific tamper control
  TPM Status                  — WMI/hardware check; no CIS admin template
  Local Administrators        — 2.3.1.4 is "Rename guest account", not local admin count
  RDP Port                    — non-standard port is a network check, not an admin template
  PowerShell Execution Policy — no admin template control in v5.0.0
  PowerShell Module Logging   — not in v5.0.0 (was 18.9.95.1.1 in v3.0.0)
  PowerShell Constrained LM   — not in v5.0.0
  PowerShell v2               — not in v5.0.0
  Speculative Exec Mitigations— section 18.3 (MS Security Guide) absent from v5.0.0 TOC
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from enum import Enum

# CIS Benchmark editions these IDs are verified against, by OS family.
# Windows 11 uses the v5.0.0 benchmark; Windows 10 / Server 2019 uses v4.0.0.
CIS_VERSION_WIN11 = "v5.0.0"
CIS_VERSION_WIN10 = "v4.0.0"


class OSFamily(Enum):
    """Operating-system family used to select a CIS Benchmark edition + ID set."""

    WIN10 = "Windows 10"
    WIN11 = "Windows 11"
    SERVER_2019 = "Windows Server 2019"
    SERVER_2022 = "Windows Server 2022"


def family_for_build(build: int) -> OSFamily:
    """Classify a Windows build number into an :class:`OSFamily`.

    Note: build numbers do NOT uniquely identify server vs client. Build 17763
    is shared by Windows 10 1809 and Server 2019, and 14393 by Win10 1607 and
    Server 2016 — so those server editions cannot be told apart from client
    Windows 10 by build alone (that needs ``Win32_OperatingSystem.ProductType``).
    Build 20348 is unambiguous (no client Windows uses it) → Server 2022.
    Anything else below 22000 is treated as the Windows 10 / v4.0.0 family.
    """
    if build == 20348:
        return OSFamily.SERVER_2022
    if build >= 22000:
        return OSFamily.WIN11
    return OSFamily.WIN10


# Win10 v4.0.0 IDs that differ from the Win11 v5.0.0 base map.
# Section offsets that changed: Defender (42→43), PowerShell (88→87),
# WinRM (90→89), Windows Update (94→93).  SMB Encryption (18.6.8.7)
# is Win11-only and has no equivalent in v4.0.0.
_WIN10_OVERRIDES: dict[str, str] = {
    "Defender Real-Time Protection":    "CIS 18.10.43.10.3",
    "Defender Signature Age":           "CIS 18.10.43.14",
    "PowerShell Script Block Logging":  "CIS 18.10.87.1",
    "WinRM Status":                     "CIS 18.10.89.2.2",
    "Last Windows Update":              "CIS 18.10.93.2.1",
    "Windows Update Service":           "CIS 18.10.93.2.1",
    "Pending Windows Updates":          "CIS 18.10.93.2.1",
    "SMB Encryption":                   "",   # not present in Win10 v4.0.0
}

# Additive family → benchmark registry: (cis_version, overrides_map, caveat).
# Each family is one self-contained entry. To support a real CIS Server 2022
# Benchmark later, swap that one tuple for
# ``(CIS_VERSION_SERVER_2022, _SERVER2022_OVERRIDES, "")`` — no call site changes.
# Server 2019/2022 ride the Windows 10 v4.0.0 ID set as a best-effort baseline;
# Server 2022 also carries a caveat so its report is honest about the approximation.
_SERVER2022_CAVEAT = (
    "Windows 10 v4.0.0 baseline — Server 2022 control IDs are best-effort; "
    "verify against the CIS Microsoft Windows Server 2022 Benchmark."
)
_FAMILY_BENCHMARKS: dict[OSFamily, tuple[str, dict[str, str], str]] = {
    OSFamily.WIN11:       (CIS_VERSION_WIN11, {},               ""),
    OSFamily.WIN10:       (CIS_VERSION_WIN10, _WIN10_OVERRIDES, ""),
    OSFamily.SERVER_2019: (CIS_VERSION_WIN10, _WIN10_OVERRIDES, ""),
    OSFamily.SERVER_2022: (CIS_VERSION_WIN10, _WIN10_OVERRIDES, _SERVER2022_CAVEAT),
}


def benchmark_version(family: OSFamily = OSFamily.WIN11) -> str:
    """Return the CIS Benchmark edition string for an OS *family*."""
    return _FAMILY_BENCHMARKS[family][0]


def benchmark_caveat(family: OSFamily = OSFamily.WIN11) -> str:
    """Return a best-effort caveat for *family*, or ``""`` when the mapping is exact."""
    return _FAMILY_BENCHMARKS[family][2]


# Maps check_name prefix → CIS control ID.
# Prefix matching allows one entry to cover dynamically-named checks
# (e.g. "BitLocker — C:" is matched by the "BitLocker" key).
_PREFIX_MAP: dict[str, str] = {
    # ── Firewall (CIS Section 9) ──────────────────────────────────────────
    "Firewall — Domain Profile Enabled":        "CIS 9.1.1",
    "Firewall — Private Profile Enabled":       "CIS 9.2.1",
    "Firewall — Public Profile Enabled":        "CIS 9.3.1",
    "Firewall — Domain Default Inbound":        "CIS 9.1.2",
    "Firewall — Private Default Inbound":       "CIS 9.2.2",
    "Firewall — Public Default Inbound":        "CIS 9.3.2",

    # ── Antivirus / Microsoft Defender (CIS Section 18.10.42) ─────────────
    # NOTE: Section 10 in v5.0.0 is "Network List Manager Policies",
    #       not Malware Defenses. Defender controls are under 18.10.42.
    "Defender Real-Time Protection":            "CIS 18.10.42.10.3",
    "Defender Signature Age":                   "CIS 18.10.42.14",
    # Tamper Protection: no direct CIS admin template in v5.0.0 — needs manual review
    "Defender Tamper Protection":               "",

    # ── Encryption (CIS Section 18.10.10 — BitLocker) ─────────────────────
    # NOTE: In v3.0.0 these were 18.9.11.x; section 18.9.11 in v5.0.0 is
    #       "Distributed COM" — completely different content.
    "BitLocker":                                "CIS 18.10.10",
    "Secure Boot":                              "CIS 18.10.10.2.2",
    # TPM Status: WMI/hardware check; no direct CIS admin template — needs manual review
    "TPM Status":                               "",

    # ── Accounts (CIS Sections 1 & 2.3.1) ────────────────────────────────
    "Guest Account":                            "CIS 2.3.1.1",
    "Built-in Administrator Account":           "CIS 2.3.1.3",
    # Local Administrators count: 2.3.1.4 in v5.0.0 is "Rename guest account",
    # not a local admin membership check — needs manual review
    "Local Administrators":                     "",
    "Password Policy — Minimum Length":         "CIS 1.1.4",
    "Password Policy — Account Lockout":        "CIS 1.2.1",
    "Password Policy — Complexity":             "CIS 1.1.5",

    # ── File Sharing / SMB ────────────────────────────────────────────────
    # NOTE: In v3.0.0, SMBv1 was 18.4.11.2; v5.0.0 uses 18.4.2 (client driver).
    #       SMB signing was 2.3.8.3; section 2.3.8 in v5.0.0 only has 2 entries
    #       (2.3.8.1–2.3.8.2). Server signing is now 2.3.9.2.
    #       SMB encryption was 2.3.8.5; it is now 18.6.8.7.
    "SMBv1 Disabled":                           "CIS 18.4.2",
    "SMB Signing Required":                     "CIS 2.3.9.2",
    "SMB Encryption":                           "CIS 18.6.8.7",

    # ── Remote Access / RDP (CIS Section 18.10.57) ────────────────────────
    # NOTE: In v3.0.0 these were 18.9.59.2.x; renumbered to 18.10.57.x in v5.0.0.
    "RDP Enabled":                              "CIS 18.10.57.3.2.1",
    "RDP Network Level Authentication":         "CIS 18.10.57.3.9.4",
    # RDP Port check: non-standard port is a network audit, not a CIS admin template
    # — needs manual review
    "RDP Port":                                 "",

    # ── Access Control / UAC (CIS Section 2.3.17) ─────────────────────────
    # NOTE: Several IDs shifted in v5.0.0:
    #   "UAC Enabled"  was 2.3.17.1; 2.3.17.6 is "Run all admins in Admin Approval Mode"
    #   "UAC Secure Desktop" was 2.3.17.4; 2.3.17.7 is "Switch to secure desktop"
    #   "UAC Standard User Behavior" was 2.3.17.5; 2.3.17.3 is the standard user prompt
    "UAC Enabled":                              "CIS 2.3.17.6",
    "UAC Admin Consent Behavior":               "CIS 2.3.17.2",
    "UAC Secure Desktop":                       "CIS 2.3.17.7",
    "UAC Standard User Behavior":               "CIS 2.3.17.3",
    "UAC Configuration":                        "CIS 2.3.17.1",

    # ── PowerShell (CIS Section 18.10.88) ─────────────────────────────────
    # NOTE: In v3.0.0 these were 18.9.95.x. Section 18.10.88 in v5.0.0
    #       only specifies Script Block Logging (18.10.88.1) and Transcription
    #       (18.10.88.2). Module Logging, Execution Policy, Constrained Language
    #       Mode, and v2 checks have no direct CIS admin template in v5.0.0.
    # Execution Policy: no CIS admin template in v5.0.0 — needs manual review
    "PowerShell Execution Policy":              "",
    "PowerShell Script Block Logging":          "CIS 18.10.88.1",
    # Module Logging: not in v5.0.0 — needs manual review
    "PowerShell Module Logging":                "",
    # Constrained Language Mode: not in v5.0.0 — needs manual review
    "PowerShell Constrained Language Mode":     "",
    # PowerShell v2: not in v5.0.0 — needs manual review
    "PowerShell v2":                            "",

    # ── Misc ──────────────────────────────────────────────────────────────
    # NOTE: LLMNR was 18.5.4.2 in v3.0.0; 18.5.4 in v5.0.0 is
    #       "MSS: (DisableSavePassword)". LLMNR/mDNS is now 18.6.4.4.
    #       AutoPlay was 18.9.8.2; 18.9.8 in v5.0.0 is "Disk NV Cache".
    #       AutoPlay is now 18.10.8.3.
    #       WinRM was 18.9.102.1; it is now 18.10.90.2.2.
    "LLMNR Disabled":                           "CIS 18.6.4.4",
    "AutoPlay Disabled":                        "CIS 18.10.8.3",
    "WinRM Status":                             "CIS 18.10.90.2.2",
    "Audit Policy":                             "CIS 17.1.1",

    # ── Patching (CIS Section 18.10.94) ───────────────────────────────────
    # NOTE: In v3.0.0 these were 18.9.101.x; renumbered to 18.10.94.x in v5.0.0.
    "Last Windows Update":                      "CIS 18.10.94.2.1",
    "Windows Update Service":                   "CIS 18.10.94.2.1",
    "Pending Windows Updates":                  "CIS 18.10.94.2.1",

    # ── OS / Hardening ────────────────────────────────────────────────────
    # Speculative Execution: was 18.3.5 (MS Security Guide) in v3.0.0.
    # Section 18.3 does not appear in v5.0.0 TOC — needs manual review.
    "Speculative Execution Mitigations":        "",
}


def lookup(check_name: str, family: OSFamily = OSFamily.WIN11) -> str:
    """Return the CIS Benchmark control ID for *check_name*, or ``''`` if unknown.

    Matching is done by prefix so that dynamically-named checks (e.g.
    ``"BitLocker — C:"``) are covered by a single map entry (``"BitLocker"``).

    Args:
        check_name: The ``check_name`` field from a ``CheckResult``.
        family:     The audited :class:`OSFamily`.  Families on the v4.0.0
                    baseline (Win10 / Server 2019 / Server 2022) substitute IDs
                    from their override map where v4.0.0 and v5.0.0 differ.

    Returns:
        CIS control ID string (e.g. ``"CIS 9.1.1"``), or empty string.
    """
    overrides = _FAMILY_BENCHMARKS[family][1]
    for prefix, cis_id in overrides.items():
        if check_name.startswith(prefix):
            return cis_id
    for prefix, cis_id in _PREFIX_MAP.items():
        if check_name.startswith(prefix):
            return cis_id
    return ""
