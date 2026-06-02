"""Check: System information — OS version, end-of-life status, uptime, domain, Secure Boot, TPM."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "System"

# Build number → (friendly name, end-of-support date)
# Uses Home/Pro dates (most restrictive). Server editions noted where the build overlaps.
# Source: https://learn.microsoft.com/en-us/windows/release-health/
_EOL_TABLE: dict[int, tuple[str, datetime]] = {
    10240: ("Windows 10 1507",               datetime(2017,  5,  9, tzinfo=timezone.utc)),
    10586: ("Windows 10 1511",               datetime(2017, 10, 10, tzinfo=timezone.utc)),
    14393: ("Windows 10 1607 / Server 2016", datetime(2027,  1, 12, tzinfo=timezone.utc)),
    15063: ("Windows 10 1703",               datetime(2018, 10,  9, tzinfo=timezone.utc)),
    16299: ("Windows 10 1709",               datetime(2019,  4,  9, tzinfo=timezone.utc)),
    17134: ("Windows 10 1803",               datetime(2019, 11, 12, tzinfo=timezone.utc)),
    17763: ("Windows 10 1809 / Server 2019", datetime(2029,  1,  9, tzinfo=timezone.utc)),
    18362: ("Windows 10 1903",               datetime(2020, 12,  8, tzinfo=timezone.utc)),
    18363: ("Windows 10 1909",               datetime(2021,  5, 11, tzinfo=timezone.utc)),
    19041: ("Windows 10 2004",               datetime(2021, 12, 14, tzinfo=timezone.utc)),
    19042: ("Windows 10 20H2",               datetime(2022,  5, 10, tzinfo=timezone.utc)),
    19043: ("Windows 10 21H1",               datetime(2022, 12, 13, tzinfo=timezone.utc)),
    19044: ("Windows 10 21H2",               datetime(2023,  6, 13, tzinfo=timezone.utc)),
    19045: ("Windows 10 22H2",               datetime(2025, 10, 14, tzinfo=timezone.utc)),
    20348: ("Windows Server 2022",           datetime(2031, 10, 14, tzinfo=timezone.utc)),
    22000: ("Windows 11 21H2",               datetime(2024, 10,  8, tzinfo=timezone.utc)),
    22621: ("Windows 11 22H2",               datetime(2025, 10, 14, tzinfo=timezone.utc)),
    22631: ("Windows 11 23H2",               datetime(2026, 11, 10, tzinfo=timezone.utc)),
    26100: ("Windows 11 24H2",               datetime(2027, 10, 12, tzinfo=timezone.utc)),
}

# Cumulative updates can push build numbers past the base release build.
# These ranges catch e.g. 26200 (post-24H2 CU) mapping to "Windows 11 24H2".
# Sorted descending so the first match wins.
_EOL_RANGES: list[tuple[int, tuple[str, datetime]]] = [
    (26100, ("Windows 11 24H2",               datetime(2027, 10, 12, tzinfo=timezone.utc))),
    (22631, ("Windows 11 23H2",               datetime(2026, 11, 10, tzinfo=timezone.utc))),
    (22621, ("Windows 11 22H2",               datetime(2025, 10, 14, tzinfo=timezone.utc))),
    (22000, ("Windows 11 21H2",               datetime(2024, 10,  8, tzinfo=timezone.utc))),
    (20348, ("Windows Server 2022",           datetime(2031, 10, 14, tzinfo=timezone.utc))),
    (19041, ("Windows 10 20xx",               datetime(2025, 10, 14, tzinfo=timezone.utc))),
]


def _lookup_eol(build: int) -> tuple[str, datetime] | None:
    """Return (friendly_name, eol_date) for a build number, using range fallback.

    Tries exact match first, then falls back to the largest known base build
    that is <= the given build (handles post-GA cumulative update builds).
    """
    if build in _EOL_TABLE:
        return _EOL_TABLE[build]
    for min_build, entry in _EOL_RANGES:
        if build >= min_build:
            return entry
    return None

_UPTIME_WARN_DAYS = 30

_PS_OS = (
    "Get-CimInstance Win32_OperatingSystem "
    "| Select-Object Caption, BuildNumber, Version "
    "| ConvertTo-Json -Compress"
)
_PS_UPTIME = (
    "[int](New-TimeSpan "
    "-Start (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays"
)
_PS_DOMAIN = (
    "Get-CimInstance Win32_ComputerSystem "
    "| Select-Object PartOfDomain, Domain, Workgroup "
    "| ConvertTo-Json -Compress"
)
_PS_SECUREBOOT = "try { Confirm-SecureBootUEFI } catch { 'UNSUPPORTED' }"
_PS_TPM = (
    "try { Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerVersion "
    "| ConvertTo-Json -Compress } "
    "catch { '{\"TpmPresent\":false,\"TpmReady\":false,\"ManufacturerVersion\":null}' }"
)


def _now() -> datetime:
    """Return current UTC time. Exists as a separate function to allow mocking in tests."""
    return datetime.now(tz=timezone.utc)


def run() -> list[CheckResult]:
    """Return system information checks.

    Returns:
        list[CheckResult]: Results for OS build, uptime, domain, Secure Boot, and TPM.
    """
    results: list[CheckResult] = []
    results.extend(_check_os_build())
    results.extend(_check_uptime())
    results.extend(_check_domain())
    results.extend(_check_secure_boot())
    results.extend(_check_tpm())
    return results


def _check_os_build() -> list[CheckResult]:
    """Check OS version and end-of-support status."""
    try:
        data = run_powershell_json(_PS_OS)
    except ApotropeError as exc:
        return [_error("OS Version", str(exc)), _error("OS End-of-Support Status", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    caption = str(data.get("Caption", "Unknown"))
    build_str = str(data.get("BuildNumber", "0"))
    version = str(data.get("Version", ""))

    try:
        build = int(build_str)
    except ValueError:
        build = 0

    version_result = CheckResult(
        category=CATEGORY,
        check_name="OS Version",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Reports the installed Windows version and build number.",
        details=f"{caption}  (Build {build_str}, Version {version})",
        remediation="",
    )

    now = _now()
    eol_entry = _lookup_eol(build)
    if eol_entry is not None:
        friendly_name, eol_date = eol_entry
        if now > eol_date:
            eol_result = CheckResult(
                category=CATEGORY,
                check_name="OS End-of-Support Status",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Checks whether the installed Windows build is still supported by Microsoft.",
                details=(
                    f"{friendly_name} reached end of support on "
                    f"{eol_date.strftime('%Y-%m-%d')}. "
                    f"This build no longer receives security updates."
                ),
                remediation=(
                    "Upgrade to a supported Windows release. "
                    "See: https://learn.microsoft.com/en-us/windows/release-health/"
                ),
            )
        else:
            days_remaining = (eol_date - now).days
            eol_result = CheckResult(
                category=CATEGORY,
                check_name="OS End-of-Support Status",
                status=Status.PASS,
                severity=Severity.HIGH,
                description="Checks whether the installed Windows build is still supported by Microsoft.",
                details=(
                    f"{friendly_name} is supported until "
                    f"{eol_date.strftime('%Y-%m-%d')} "
                    f"({days_remaining} days remaining)."
                ),
                remediation="",
            )
    else:
        eol_result = CheckResult(
            category=CATEGORY,
            check_name="OS End-of-Support Status",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks whether the installed Windows build is still supported by Microsoft.",
            details=(
                f"Build {build_str} is not in the known support table. "
                "Verify this is a current supported release."
            ),
            remediation=(
                "Check the Microsoft support lifecycle page: "
                "https://learn.microsoft.com/en-us/windows/release-health/"
            ),
        )

    return [version_result, eol_result]


def _check_uptime() -> list[CheckResult]:
    """Check system uptime — long uptime suggests reboots are being skipped after patches."""
    try:
        output = run_powershell(_PS_UPTIME)
        days = int(output.strip())
    except (ApotropeError, ValueError) as exc:
        return [_error("System Uptime", str(exc))]

    if days > _UPTIME_WARN_DAYS:
        return [CheckResult(
            category=CATEGORY,
            check_name="System Uptime",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description=f"Warns when uptime exceeds {_UPTIME_WARN_DAYS} days (suggests pending patch reboots).",
            details=f"System has been running for {days} days without a reboot.",
            remediation=(
                "Reboot the system to apply pending patches. "
                "Review Windows Update history for updates that require a restart."
            ),
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="System Uptime",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        description=f"Warns when uptime exceeds {_UPTIME_WARN_DAYS} days (suggests pending patch reboots).",
        details=f"System uptime is {days} day(s).",
        remediation="",
    )]


def _check_domain() -> list[CheckResult]:
    """Report domain vs workgroup membership (informational)."""
    try:
        data = run_powershell_json(_PS_DOMAIN)
    except ApotropeError as exc:
        return [_error("Domain Membership", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    part_of_domain = bool(data.get("PartOfDomain", False))
    domain_name = str(data.get("Domain") or data.get("Workgroup") or "UNKNOWN")
    label = "Domain" if part_of_domain else "Workgroup"

    return [CheckResult(
        category=CATEGORY,
        check_name="Domain Membership",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Reports whether this machine is joined to an Active Directory domain.",
        details=f"{'Domain-joined' if part_of_domain else 'Workgroup member'}. {label}: {domain_name}",
        remediation="",
    )]


def _check_secure_boot() -> list[CheckResult]:
    """Check UEFI Secure Boot status."""
    try:
        output = run_powershell(_PS_SECUREBOOT).strip()
    except ApotropeError as exc:
        return [_error("Secure Boot", str(exc))]

    if output.upper() == "UNSUPPORTED":
        return [CheckResult(
            category=CATEGORY,
            check_name="Secure Boot",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether UEFI Secure Boot is enabled.",
            details="Secure Boot is not supported or the system is running in legacy BIOS mode.",
            remediation=(
                "Enable UEFI mode in firmware settings if the hardware supports it. "
                "Secure Boot requires UEFI firmware."
            ),
        )]

    enabled = output.lower() == "true"
    return [CheckResult(
        category=CATEGORY,
        check_name="Secure Boot",
        status=Status.PASS if enabled else Status.FAIL,
        severity=Severity.MEDIUM,
        description="Checks whether UEFI Secure Boot is enabled.",
        details=f"Secure Boot is {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if enabled else
            "Enable Secure Boot in UEFI/BIOS firmware settings. "
            "Note: may require reinstalling Windows in UEFI mode if currently using legacy BIOS."
        ),
    )]


def _check_tpm() -> list[CheckResult]:
    """Check TPM chip presence, readiness, and version."""
    try:
        data = run_powershell_json(_PS_TPM)
    except ApotropeError as exc:
        return [_error("TPM Status", str(exc))]

    if isinstance(data, list):
        data = data[0] if data else {}

    present = bool(data.get("TpmPresent", False))
    ready = bool(data.get("TpmReady", False))
    version = str(data.get("ManufacturerVersion") or "Unknown")

    if not present:
        return [CheckResult(
            category=CATEGORY,
            check_name="TPM Status",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether a TPM chip is present and functional.",
            details="No TPM chip detected.",
            remediation=(
                "A TPM 2.0 chip is required for BitLocker and is mandatory for Windows 11. "
                "Enable TPM in UEFI/BIOS settings if available."
            ),
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="TPM Status",
        status=Status.PASS if ready else Status.WARN,
        severity=Severity.MEDIUM,
        description="Checks whether a TPM chip is present and functional.",
        details=f"TPM present. Ready: {ready}. Firmware version: {version}.",
        remediation=(
            "" if ready else
            "Check TPM status in tpm.msc or Device Manager. "
            "Clear and re-initialize the TPM if it reports errors."
        ),
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
