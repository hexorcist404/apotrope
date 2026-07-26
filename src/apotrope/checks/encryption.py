"""Check: BitLocker disk encryption status per fixed drive."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Encryption"
REQUIRES_ADMIN = True  # Get-BitLockerVolume requires administrator privileges

# Get-BitLockerVolume requires admin; the outer try/catch returns an empty JSON
# array so run() can produce a graceful WARN instead of crashing.
_PS_BITLOCKER = (
    "try { "
    "Get-BitLockerVolume "
    "| Select-Object MountPoint, VolumeType, VolumeStatus, "
    "ProtectionStatus, EncryptionMethod, EncryptionPercentage "
    "| ConvertTo-Json -Compress "
    "} catch { '[]' }"
)

# ProtectionStatus values from Get-BitLockerVolume
_PROTECTION_ON = 1

# PowerShell 5.1 serialises these enums as integers; PowerShell 7 as strings.
_VOLUME_TYPE_NAMES = {0: "OperatingSystem", 1: "FixedData", 2: "Removable"}
_VOLUME_STATUS_NAMES = {
    0: "FullyDecrypted", 1: "FullyEncrypted", 2: "EncryptionInProgress",
    3: "DecryptionInProgress", 4: "EncryptionPaused", 5: "DecryptionPaused",
}


def _enum_name(raw: object, table: dict[int, str]) -> str:
    """Map a PS 5.1 integer enum to its name; pass a PS 7 string enum through."""
    if isinstance(raw, bool) or raw is None:
        return "Unknown"
    if isinstance(raw, int):
        return table.get(raw, str(raw))
    return str(raw)


def _coerce_int(raw: object) -> int:
    """Best-effort int from an int or numeric string; None/unparseable -> 0."""
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw).split(".")[0])
    except (TypeError, ValueError):
        return 0


def run() -> list[CheckResult]:
    """Return BitLocker encryption status checks.

    Returns:
        list[CheckResult]: One result per detected volume, or a single WARN/ERROR
        result when BitLocker data is unavailable.
    """
    try:
        data = run_powershell_json(_PS_BITLOCKER)
    except ApotropeError as exc:
        return [CheckResult(
            category=CATEGORY,
            check_name="BitLocker Status",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Checks BitLocker drive encryption status.",
            details=str(exc),
            remediation=(
                "Run Apotrope as Administrator for full BitLocker status. "
                "Run with --log-level DEBUG for more detail."
            ),
        )]

    volumes = data if isinstance(data, list) else ([data] if data else [])

    if not volumes:
        return [CheckResult(
            category=CATEGORY,
            check_name="BitLocker Status",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks BitLocker drive encryption status.",
            details=(
                "No BitLocker volumes returned. "
                "BitLocker may be unavailable, or elevated privileges are required."
            ),
            remediation=(
                "Run Apotrope as Administrator to retrieve BitLocker status, then "
                "encrypt the system drive with BitLocker using the TPM protector."
            ),
            command=(
                "# BitLocker requires Windows Pro/Enterprise/Education (absent on Home).\n"
                "if (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue) {\n"
                "    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 "
                "-UsedSpaceOnly -TpmProtector -SkipHardwareTest\n"
                "    Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector\n"
                "} else {\n"
                "    Write-Warning 'BitLocker is unavailable on this Windows edition; "
                "on Home, use Device Encryption.'\n"
                "}"
            ),
        )]

    results: list[CheckResult] = []
    for vol in volumes:
        results.extend(_check_volume(vol))
    return results


def _check_volume(vol: dict) -> list[CheckResult]:
    """Evaluate a single BitLocker volume dict and return a CheckResult."""
    mount = str(vol.get("MountPoint", "?:"))
    vol_type = _enum_name(vol.get("VolumeType"), _VOLUME_TYPE_NAMES)
    vol_status = _enum_name(vol.get("VolumeStatus"), _VOLUME_STATUS_NAMES)
    method = str(vol.get("EncryptionMethod") or "None")
    pct = _coerce_int(vol.get("EncryptionPercentage"))

    # Identify OS drive by VolumeType; fall back to drive letter heuristic
    is_os = "OperatingSystem" in vol_type or mount.upper().startswith("C:")
    # ProtectionStatus is 1/On when protectors are active — accept PS5 int and PS7 string.
    is_protected = str(vol.get("ProtectionStatus")).lower() in ("1", "on")
    is_full = pct >= 100 or vol_status.replace(" ", "").lower() == "fullyencrypted"
    severity = Severity.HIGH if is_os else Severity.MEDIUM

    if is_protected and is_full:
        return [CheckResult(
            category=CATEGORY,
            check_name=f"BitLocker — {mount}",
            status=Status.PASS,
            severity=severity,
            description=f"Checks BitLocker encryption status for drive {mount}.",
            details=(
                f"Drive: {mount} | Type: {vol_type} | "
                f"Status: {vol_status} | Method: {method} | "
                f"Encrypted: {pct}% | Protection: On"
            ),
            remediation="",
        )]

    if is_protected and not is_full:
        # Protection is on but encryption has not finished — the drive is not yet
        # fully protected, so this is not a PASS.
        return [CheckResult(
            category=CATEGORY,
            check_name=f"BitLocker — {mount}",
            status=Status.WARN,
            severity=severity,
            description=f"Checks BitLocker encryption status for drive {mount}.",
            details=(
                f"Drive: {mount} | Type: {vol_type} | "
                f"Status: {vol_status} | Method: {method} | "
                f"Encrypted: {pct}% | Protection: On (encryption in progress — "
                "not yet fully protected)"
            ),
            remediation="Leave BitLocker encryption running until the drive reports 100%.",
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name=f"BitLocker — {mount}",
        status=Status.FAIL,
        severity=severity,
        description=f"Checks BitLocker encryption status for drive {mount}.",
        details=(
            f"Drive: {mount} | Type: {vol_type} | "
            f"Status: {vol_status} | "
            f"Encrypted: {pct}% | Protection: Off"
        ),
        remediation=(
            f"Encrypt drive {mount} with BitLocker using the TPM protector."
        ),
        command=(
            "# BitLocker requires Windows Pro/Enterprise/Education (absent on Home).\n"
            "if (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue) {\n"
            "    Enable-BitLocker -MountPoint '" + mount + "' -EncryptionMethod "
            "XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector -SkipHardwareTest\n"
            "    if ('" + mount + "' -eq $env:SystemDrive) { "
            "Add-BitLockerKeyProtector -MountPoint '" + mount + "' -TpmProtector } "
            "else { Enable-BitLockerAutoUnlock -MountPoint '" + mount + "' }\n"
            "} else {\n"
            "    Write-Warning 'BitLocker is unavailable on this Windows edition.'\n"
            "}"
        ),
    )]
