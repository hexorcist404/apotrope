"""Check: Antivirus and Windows Defender status."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import get_wmi_object, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Antivirus"

_SIGNATURE_WARN_DAYS = 7

# Query Windows Defender via Get-MpComputerStatus. The catch fires when the cmdlet is
# unavailable — Server Core without the Defender module, the module failing to load, or
# access denied — and emits a distinct {"_QueryError":true} marker, so the Python layer
# reports "status unknown" instead of mistaking an unreadable provider for a genuinely
# disabled Defender. AMRunningMode further distinguishes passive mode (a third-party AV
# is the active provider) from Defender actually being off.
_PS_DEFENDER = (
    "try { "
    "Get-MpComputerStatus | Select-Object "
    "AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, "
    "IsTamperProtected, AntivirusSignatureAge, AMRunningMode "
    "| ConvertTo-Json -Compress "
    "} catch { '{\"_QueryError\":true}' }"
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
    """Check Windows Defender via Get-MpComputerStatus.

    Distinguishes three states the build previously conflated into a CRITICAL fail:
    the provider being unreadable (status unknown), Defender running passively behind
    a third-party AV (expected, not a finding), and Defender being the active AV (the
    real-time-protection / signature / tamper checks).
    """
    try:
        data = run_powershell_json(_PS_DEFENDER)
    except ApotropeError as exc:
        return [_error("Windows Defender", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    if not data or data.get("_QueryError"):
        return [CheckResult(
            category=CATEGORY,
            check_name="Windows Defender",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Reports Windows Defender real-time protection, signatures, and tamper protection.",
            details=(
                "Windows Defender status could not be determined — Get-MpComputerStatus "
                "is unavailable on this system (e.g. Server Core without the Defender "
                "module, the module failed to load, or access was denied). This is not "
                "the same as Defender being disabled; see Registered AV Products below "
                "for whether another antivirus is active."
            ),
            remediation="",
        )]

    running_mode = str(data.get("AMRunningMode") or "").strip()
    if "passive" in running_mode.lower():
        return [CheckResult(
            category=CATEGORY,
            check_name="Windows Defender",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Reports Windows Defender real-time protection, signatures, and tamper protection.",
            details=(
                f"Microsoft Defender is in passive mode ({running_mode}); a third-party "
                "antivirus is the active provider, so Defender's own real-time protection "
                "is expected to be off. See Registered AV Products for the active product."
            ),
            remediation="",
        )]

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
            "Turn Microsoft Defender real-time protection back on immediately."
        ),
        command=(
            "" if rtp_enabled else
            "Set-MpPreference -DisableRealtimeMonitoring $false"
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
            "Update Defender's antivirus definitions now."
        ),
        command=(
            "" if sig_ok else
            "Update-MpSignature"
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
            "Enable Tamper Protection so Defender settings can't be changed by malware or scripts."
        ),
        command=(
            "" if tamper else
            "# Enable in Windows Security -> Virus & threat protection ->\n"
            "# Manage settings -> Tamper Protection: On. Verify the current state:\n"
            "(Get-MpComputerStatus).IsTamperProtected"
        ),
    ))

    return results


def _is_server_sku() -> bool:
    """Return True if this looks like a server SKU (ProductType 2 or 3).

    Windows Security Center (root\\SecurityCenter2) is a client-only feature, so an
    empty result there is expected on servers and must not be reported as "no AV". When
    ProductType is unreadable this returns False, falling back to the stricter client
    behaviour (better a false CRITICAL prompting investigation than a silent miss).
    """
    rows = get_wmi_object("Win32_OperatingSystem", properties=["ProductType"])
    if not rows:
        return False
    product_type = rows[0].get("ProductType")
    return isinstance(product_type, int) and product_type in (2, 3)


def _check_security_center() -> list[CheckResult]:
    """List antivirus products registered with Windows Security Center."""
    try:
        data = run_powershell_json(_PS_SECURITY_CENTER)
    except ApotropeError as exc:
        return [_error("Registered AV Products", str(exc))]

    products = data if isinstance(data, list) else ([data] if data else [])

    if not products:
        if _is_server_sku():
            return [CheckResult(
                category=CATEGORY,
                check_name="Registered AV Products",
                status=Status.INFO,
                severity=Severity.INFO,
                description="Lists antivirus products registered with Windows Security Center.",
                details=(
                    "Windows Security Center (root\\SecurityCenter2) is a client-only "
                    "feature and is not present on Server SKUs, so registered antivirus "
                    "products cannot be enumerated here. Check the Windows Defender status "
                    "above for this machine's protection state."
                ),
                remediation="",
            )]
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
