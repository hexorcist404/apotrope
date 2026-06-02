"""Check: Antivirus and Windows Defender status."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Antivirus"

_SIGNATURE_WARN_DAYS = 7

# Try Defender first; catch handles Server SKUs where Get-MpComputerStatus is absent.
_PS_DEFENDER = (
    "try { "
    "Get-MpComputerStatus | Select-Object "
    "AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, "
    "IsTamperProtected, AntivirusSignatureAge "
    "| ConvertTo-Json -Compress "
    "} catch { '{\"AMServiceEnabled\":false,\"RealTimeProtectionEnabled\":false,"
    "\"AntivirusEnabled\":false,\"IsTamperProtected\":false,\"AntivirusSignatureAge\":999}' }"
)

# SecurityCenter2 lists all registered AV products (requires desktop SKU).
_PS_SECURITY_CENTER = (
    "Get-CimInstance -Namespace root\\SecurityCenter2 "
    "-ClassName AntiVirusProduct "
    "| Select-Object displayName, productState "
    "| ConvertTo-Json -Compress"
)


def run() -> list[CheckResult]:
    """Return antivirus status checks.

    Returns:
        list[CheckResult]: Results for Defender RTP, signature age, tamper
        protection, and registered AV products.
    """
    results: list[CheckResult] = []
    results.extend(_check_defender())
    results.extend(_check_security_center())
    return results


def _check_defender() -> list[CheckResult]:
    """Check Windows Defender via Get-MpComputerStatus."""
    try:
        data = run_powershell_json(_PS_DEFENDER)
    except ApotropeError as exc:
        return [_error("Windows Defender", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    am_enabled = bool(data.get("AMServiceEnabled", False))
    rtp_enabled = bool(data.get("RealTimeProtectionEnabled", False))
    av_enabled = bool(data.get("AntivirusEnabled", False))
    tamper = bool(data.get("IsTamperProtected", False))
    sig_age = int(data.get("AntivirusSignatureAge") or 0)

    results: list[CheckResult] = []

    # Real-time protection (most critical AV check)
    results.append(CheckResult(
        category=CATEGORY,
        check_name="Defender Real-Time Protection",
        status=Status.PASS if rtp_enabled else Status.FAIL,
        severity=Severity.CRITICAL,
        description="Checks whether Windows Defender real-time protection is active.",
        details=(
            f"RealTimeProtectionEnabled: {rtp_enabled} | "
            f"AMServiceEnabled: {am_enabled} | "
            f"AntivirusEnabled: {av_enabled}"
        ),
        remediation=(
            "" if rtp_enabled else
            "Enable real-time protection: "
            "Set-MpPreference -DisableRealtimeMonitoring $false. "
            "Or: Windows Security → Virus & threat protection → Real-time protection: On"
        ),
    ))

    # Signature age
    sig_ok = sig_age <= _SIGNATURE_WARN_DAYS
    results.append(CheckResult(
        category=CATEGORY,
        check_name="Defender Signature Age",
        status=Status.PASS if sig_ok else Status.WARN,
        severity=Severity.HIGH,
        description=(
            f"Checks whether Defender virus definitions are less than "
            f"{_SIGNATURE_WARN_DAYS} days old."
        ),
        details=f"Antivirus signature age: {sig_age} day(s).",
        remediation=(
            "" if sig_ok else
            "Update Defender signatures immediately: Update-MpSignature. "
            "Or: Windows Security → Virus & threat protection → Check for updates"
        ),
    ))

    # Tamper protection
    results.append(CheckResult(
        category=CATEGORY,
        check_name="Defender Tamper Protection",
        status=Status.PASS if tamper else Status.WARN,
        severity=Severity.MEDIUM,
        description=(
            "Checks whether Tamper Protection is enabled to prevent "
            "unauthorised changes to Defender settings."
        ),
        details=f"IsTamperProtected: {tamper}",
        remediation=(
            "" if tamper else
            "Enable Tamper Protection: "
            "Windows Security → Virus & threat protection → "
            "Manage settings → Tamper Protection: On"
        ),
    ))

    return results


def _check_security_center() -> list[CheckResult]:
    """List antivirus products registered with Windows Security Center."""
    try:
        data = run_powershell_json(_PS_SECURITY_CENTER)
    except ApotropeError as exc:
        return [_error("Registered AV Products", str(exc))]

    products = data if isinstance(data, list) else ([data] if data else [])

    if not products:
        return [CheckResult(
            category=CATEGORY,
            check_name="Registered AV Products",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Lists antivirus products registered with Windows Security Center.",
            details=(
                "No antivirus product is registered with Windows Security Center "
                "(root\\SecurityCenter2)."
            ),
            remediation=(
                "Install and enable a supported antivirus product, "
                "or ensure Windows Defender is enabled and not suppressed by policy."
            ),
        )]

    names = [str(p.get("displayName", "Unknown")) for p in products]
    return [CheckResult(
        category=CATEGORY,
        check_name="Registered AV Products",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Lists antivirus products registered with Windows Security Center.",
        details=f"Registered AV product(s): {', '.join(names)}",
        remediation="",
    )]


def _error(check_name: str, details: str) -> CheckResult:
    """Return a synthetic ERROR result for a failed sub-check."""
    return CheckResult(
        category=CATEGORY,
        check_name=check_name,
        status=Status.ERROR,
        severity=Severity.INFO,
        description="An error occurred while running this check.",
        details=details,
        remediation="Run with --log-level DEBUG for more detail.",
    )
