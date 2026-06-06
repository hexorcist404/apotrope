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
            command="Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
        )]

    results: list[CheckResult] = []
    for vol in volumes:
        results.extend(_check_volume(vol))
    return results


def _check_volume(vol: dict) -> list[CheckResult]:
    """Evaluate a single BitLocker volume dict and return a CheckResult."""
    mount = str(vol.get("MountPoint", "?:"))
    vol_type = str(vol.get("VolumeType") or "Unknown")
    vol_status = str(vol.get("VolumeStatus") or "Unknown")
    protection = int(vol.get("ProtectionStatus") or 0)
    method = str(vol.get("EncryptionMethod") or "None")
    pct = int(vol.get("EncryptionPercentage") or 0)

    # Identify OS drive by VolumeType; fall back to drive letter heuristic
    is_os = "OperatingSystem" in vol_type or mount.upper().startswith("C:")
    is_protected = protection == _PROTECTION_ON
    severity = Severity.HIGH if is_os else Severity.MEDIUM

    if is_protected:
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
            f"Enable-BitLocker -MountPoint '{mount}' "
            f"-EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
        ),
    )]
