"""Check: System information — OS version, end-of-life status, uptime, domain, Secure Boot, TPM."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "System"

# Windows lifecycle data, reconciled against Microsoft release-health on the date
# below. Client rows carry Home/Pro (consumer) end-of-servicing dates — the most
# conservative choice for a posture auditor; the Enterprise/Education date is kept
# alongside (unused today) so switching policy or going SKU-aware later is a one-line
# change. Server rows carry the extended-support end date (when security updates stop).
# Builds shared by a client and a server release (14393, 17763, 26100) appear under
# BOTH channels and are disambiguated by ProductType, so a server is never labelled a
# client edition (and vice versa).
# Source: https://learn.microsoft.com/en-us/windows/release-health/
_LAST_VERIFIED = datetime(2026, 6, 26, tzinfo=timezone.utc)

# Win32_OperatingSystem.ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server.
_SERVER_PRODUCT_TYPES = frozenset({2, 3})


def _d(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _Release:
    """A Windows release and the date it stops receiving security updates."""

    name: str
    eol: datetime
    is_server: bool = False
    eol_enterprise: datetime | None = None  # client-only; reserved for a SKU-aware policy

    def eol_date(self) -> datetime:
        return self.eol


# (channel, base build) -> release. channel is "client" or "server".
_RELEASES: dict[tuple[str, int], _Release] = {
    # Windows 10 client (Home/Pro end of servicing)
    ("client", 10240): _Release("Windows 10 1507", _d(2017, 5, 9)),
    ("client", 10586): _Release("Windows 10 1511", _d(2017, 10, 10)),
    ("client", 14393): _Release("Windows 10 1607", _d(2018, 4, 10)),
    ("client", 15063): _Release("Windows 10 1703", _d(2018, 10, 9)),
    ("client", 16299): _Release("Windows 10 1709", _d(2019, 4, 9)),
    ("client", 17134): _Release("Windows 10 1803", _d(2019, 11, 12)),
    ("client", 17763): _Release("Windows 10 1809", _d(2020, 11, 10)),
    ("client", 18362): _Release("Windows 10 1903", _d(2020, 12, 8)),
    ("client", 18363): _Release("Windows 10 1909", _d(2021, 5, 11)),
    ("client", 19041): _Release("Windows 10 2004", _d(2021, 12, 14)),
    ("client", 19042): _Release("Windows 10 20H2", _d(2022, 5, 10)),
    ("client", 19043): _Release("Windows 10 21H1", _d(2022, 12, 13)),
    ("client", 19044): _Release("Windows 10 21H2", _d(2023, 6, 13)),
    ("client", 19045): _Release("Windows 10 22H2", _d(2025, 10, 14)),
    # Windows 11 client (Home/Pro end of servicing; Enterprise/Education kept for reference)
    ("client", 22000): _Release("Windows 11 21H2", _d(2023, 10, 10), eol_enterprise=_d(2024, 10, 8)),
    ("client", 22621): _Release("Windows 11 22H2", _d(2024, 10, 8), eol_enterprise=_d(2025, 10, 14)),
    ("client", 22631): _Release("Windows 11 23H2", _d(2025, 11, 11), eol_enterprise=_d(2026, 11, 10)),
    ("client", 26100): _Release("Windows 11 24H2", _d(2026, 10, 13), eol_enterprise=_d(2027, 10, 12)),
    ("client", 26200): _Release("Windows 11 25H2", _d(2027, 10, 12), eol_enterprise=_d(2028, 10, 10)),
    ("client", 28000): _Release("Windows 11 26H1", _d(2028, 3, 14), eol_enterprise=_d(2029, 3, 13)),
    # Windows Server (extended-support end = security updates stop)
    ("server", 14393): _Release("Windows Server 2016", _d(2027, 1, 12), is_server=True),
    ("server", 17763): _Release("Windows Server 2019", _d(2029, 1, 9), is_server=True),
    ("server", 20348): _Release("Windows Server 2022", _d(2031, 10, 14), is_server=True),
    ("server", 26100): _Release("Windows Server 2025", _d(2034, 11, 14), is_server=True),
}

# Highest known base build per channel, used by the "newer than anything we know" guard.
_KNOWN_BUILDS: dict[str, list[int]] = {
    "client": sorted(b for (ch, b) in _RELEASES if ch == "client"),
    "server": sorted(b for (ch, b) in _RELEASES if ch == "server"),
}


class _NewerThanKnown:
    """Sentinel type: a build newer than every known release on its channel."""


# A build newer than the whole table must NOT be silently mapped to the newest known
# release (that would report an unsupported future build as "supported"); callers WARN.
_NEWER_THAN_KNOWN = _NewerThanKnown()


def _channel_for(product_type: int | None, build: int) -> str:
    """Pick the client/server lifecycle track for a build.

    A build that exists only as a server release always resolves as server. Otherwise
    ProductType decides; when it is unavailable we assume client, which both matches the
    historical desktop-only behaviour and fails closed — a server briefly mislabelled as
    a client reports the *earlier* client EOL rather than a false "supported".
    """
    if ("server", build) in _RELEASES and ("client", build) not in _RELEASES:
        return "server"
    if product_type in _SERVER_PRODUCT_TYPES:
        return "server"
    return "client"


def _lookup_eol(
    build: int,
    product_type: int | None = None,
    edition: str | None = None,
) -> tuple[str, datetime] | _NewerThanKnown | None:
    """Resolve a build to (friendly_name, eol_date), a sentinel, or None.

    Returns ``(name, date)`` for a known release; ``_NEWER_THAN_KNOWN`` when the build is
    newer than every known release on its channel (caller should WARN rather than assume
    support); or ``None`` when it is below all known releases. Exact base-build hits win;
    otherwise the nearest lower base on the same channel resolves it (post-GA cumulative
    update tolerance). ``edition`` is accepted for a future SKU-aware policy but unused today.
    """
    channel = _channel_for(product_type, build)
    known = _KNOWN_BUILDS[channel]  # always non-empty: both channels are populated
    if (channel, build) in _RELEASES:
        rel = _RELEASES[(channel, build)]
        return (rel.name, rel.eol_date())
    if build > known[-1]:
        return _NEWER_THAN_KNOWN
    base = max((b for b in known if b <= build), default=None)
    if base is None:
        return None
    rel = _RELEASES[(channel, base)]
    return (rel.name, rel.eol_date())

_UPTIME_WARN_DAYS = 30

_PS_OS = (
    "Get-CimInstance Win32_OperatingSystem "
    "| Select-Object Caption, BuildNumber, Version, ProductType "
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

    product_type = data.get("ProductType")
    if not isinstance(product_type, int) or isinstance(product_type, bool):
        product_type = None

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
    eol_entry = _lookup_eol(build, product_type)
    description = "Checks whether the installed Windows build is still supported by Microsoft."
    confirm_command = (
        "[System.Environment]::OSVersion.Version\n"
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion"
    )

    if isinstance(eol_entry, tuple):
        friendly_name, eol_date = eol_entry
        if now > eol_date:
            eol_result = CheckResult(
                category=CATEGORY,
                check_name="OS End-of-Support Status",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description=description,
                details=(
                    f"{friendly_name} reached end of support on "
                    f"{eol_date.strftime('%Y-%m-%d')}. "
                    f"This build no longer receives security updates."
                ),
                remediation=(
                    "Upgrade to a currently supported Windows release — the upgrade "
                    "itself has no single command. Confirm the current build first, "
                    "then run Windows Update or the Installation Assistant."
                ),
                command=(
                    "# There is no in-place command for the upgrade — use Windows Update or the\n"
                    "# Windows Installation Assistant. Confirm the current build first:\n"
                    f"{confirm_command}"
                ),
            )
        else:
            days_remaining = (eol_date - now).days
            eol_result = CheckResult(
                category=CATEGORY,
                check_name="OS End-of-Support Status",
                status=Status.PASS,
                severity=Severity.HIGH,
                description=description,
                details=(
                    f"{friendly_name} is supported until "
                    f"{eol_date.strftime('%Y-%m-%d')} "
                    f"({days_remaining} days remaining)."
                ),
                remediation="",
            )
    elif eol_entry is _NEWER_THAN_KNOWN:
        eol_result = CheckResult(
            category=CATEGORY,
            check_name="OS End-of-Support Status",
            status=Status.WARN,
            severity=Severity.HIGH,
            description=description,
            details=(
                f"Build {build_str} is newer than Apotrope's known Windows lifecycle "
                f"table (last verified {_LAST_VERIFIED.strftime('%Y-%m-%d')}). Confirm "
                "its support status on the Microsoft release-health page."
            ),
            remediation=(
                "Update Apotrope, or confirm this build's support status on the "
                "Microsoft release-health page."
            ),
            command=confirm_command,
        )
    else:
        eol_result = CheckResult(
            category=CATEGORY,
            check_name="OS End-of-Support Status",
            status=Status.WARN,
            severity=Severity.HIGH,
            description=description,
            details=(
                f"Build {build_str} is not in the known support table. "
                "Verify this is a current supported release."
            ),
            remediation=(
                "Confirm the current build and verify it is a supported release on the "
                "Microsoft support lifecycle page."
            ),
            command=confirm_command,
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
            remediation="Schedule a reboot to apply deferred updates.",
            command="Restart-Computer",
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
                "Secure Boot requires UEFI firmware — enable UEFI mode in firmware "
                "settings if the hardware supports it, then confirm the state from Windows."
            ),
            command=(
                "# Secure Boot is a UEFI/firmware setting — reboot into firmware setup to enable it.\n"
                "# Verify Secure Boot state (returns True once enabled in UEFI):\n"
                "Confirm-SecureBootUEFI"
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
            "Secure Boot is a UEFI/firmware setting — reboot into firmware setup to "
            "enable it, then confirm the state from Windows afterwards. May require "
            "reinstalling Windows in UEFI mode if currently using legacy BIOS."
        ),
        command=(
            "" if enabled else
            "# Secure Boot is a UEFI/firmware setting — reboot into firmware setup to enable it.\n"
            "# Verify Secure Boot state (returns True once enabled in UEFI):\n"
            "Confirm-SecureBootUEFI"
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
    # Get-Tpm's ManufacturerVersion can carry trailing NUL bytes from the
    # firmware WMI string; strip them so they don't leak into report output.
    version = str(data.get("ManufacturerVersion") or "").replace("\x00", "").strip() or "Unknown"

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
                "Enable the TPM in UEFI/BIOS firmware settings if the hardware supports it, "
                "then confirm it is detected from Windows."
            ),
            command="Get-Tpm",
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
            "Initialize the TPM and take ownership so it is ready for use."
        ),
        command=(
            "" if ready else
            "Get-Tpm\n"
            "Initialize-Tpm -AllowClear -AllowPhysicalPresence"
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
