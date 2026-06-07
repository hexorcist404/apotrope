"""Check: SMB server configuration — SMBv1, signing, and encryption."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "File Sharing"
REQUIRES_ADMIN = True  # Get-SmbServerConfiguration requires administrator privileges

_PS_SMB = (
    "try { "
    "Get-SmbServerConfiguration "
    "| Select-Object EnableSMB1Protocol, RequireSecuritySignature, "
    "EnableSecuritySignature, EncryptData "
    "| ConvertTo-Json -Compress "
    "} catch { "
    "'{\"EnableSMB1Protocol\":null,\"RequireSecuritySignature\":null,"
    "\"EnableSecuritySignature\":null,\"EncryptData\":null}' "
    "}"
)


def run() -> list[CheckResult]:
    """Return SMB server configuration checks.

    Returns:
        list[CheckResult]: Results for SMBv1 status, signing policy, and encryption.
    """
    try:
        data = run_powershell_json(_PS_SMB)
    except ApotropeError as exc:
        return [CheckResult(
            category=CATEGORY,
            check_name="SMB Configuration",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Checks SMB server configuration.",
            details=str(exc),
            remediation="Ensure Get-SmbServerConfiguration is available. Run with --log-level DEBUG.",
        )]

    if isinstance(data, list):
        data = data[0] if data else {}

    results: list[CheckResult] = []
    results.extend(_check_smb1(data))
    results.extend(_check_smb_signing(data))
    results.extend(_check_smb_encryption(data))
    return results


def _check_smb1(data: dict) -> list[CheckResult]:
    """Check whether SMBv1 is disabled."""
    raw = data.get("EnableSMB1Protocol")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="SMBv1 Disabled",
            status=Status.WARN,
            severity=Severity.CRITICAL,
            description="Checks that SMBv1 is disabled (mitigates EternalBlue/WannaCry).",
            details="Could not determine SMBv1 status from Get-SmbServerConfiguration.",
            remediation="Remove the legacy SMBv1 protocol, then reboot.",
            command="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
        )]

    enabled = bool(raw)
    return [CheckResult(
        category=CATEGORY,
        check_name="SMBv1 Disabled",
        status=Status.FAIL if enabled else Status.PASS,
        severity=Severity.CRITICAL,
        description="Checks that SMBv1 is disabled (mitigates EternalBlue/WannaCry/NotPetya).",
        details=f"SMBv1 protocol is {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if not enabled else
            "Remove the legacy SMBv1 protocol, then reboot."
        ),
        command=(
            "" if not enabled else
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        ),
    )]


def _check_smb_signing(data: dict) -> list[CheckResult]:
    """Check whether SMB message signing is required (not just enabled)."""
    required = data.get("RequireSecuritySignature")
    enabled = data.get("EnableSecuritySignature")

    if required is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="SMB Signing Required",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Checks that SMB message signing is required (mitigates relay attacks).",
            details="Could not determine SMB signing configuration.",
            remediation=(
                "Require SMB message signing on both the client and server side so "
                "sessions can't be relayed or tampered with."
            ),
            command=(
                "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force\n"
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
            ),
        )]

    required_bool = bool(required)
    enabled_bool = bool(enabled) if enabled is not None else False

    _signing_command = (
        "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force\n"
        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
    )
    _signing_remediation = (
        "Require SMB message signing on both the client and server side so "
        "sessions can't be relayed or tampered with."
    )

    if required_bool:
        details = "SMB signing is required on this server."
        status = Status.PASS
        remediation = ""
        command = ""
    elif enabled_bool:
        details = "SMB signing is enabled but not required — clients may negotiate unsigned connections."
        status = Status.WARN
        remediation = _signing_remediation
        command = _signing_command
    else:
        details = "SMB signing is neither required nor enabled."
        status = Status.FAIL
        remediation = _signing_remediation
        command = _signing_command

    return [CheckResult(
        category=CATEGORY,
        check_name="SMB Signing Required",
        status=status,
        severity=Severity.HIGH,
        description="Checks that SMB message signing is required (mitigates NTLM relay attacks).",
        details=details,
        remediation=remediation,
        command=command,
    )]


def _check_smb_encryption(data: dict) -> list[CheckResult]:
    """Check whether SMB encryption is enabled (SMB 3.0+ feature)."""
    raw = data.get("EncryptData")

    if raw is None:
        return [CheckResult(
            category=CATEGORY,
            check_name="SMB Encryption",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Checks whether SMB encryption is enforced (SMB 3.0+ feature).",
            details="Could not determine SMB encryption status.",
            remediation="",
        )]

    enabled = bool(raw)
    return [CheckResult(
        category=CATEGORY,
        check_name="SMB Encryption",
        status=Status.PASS if enabled else Status.INFO,
        severity=Severity.LOW,
        description="Checks whether SMB encryption is enforced (SMB 3.0+ feature).",
        details=f"SMB encryption (EncryptData) is {'enabled' if enabled else 'disabled'}.",
        remediation=(
            "" if enabled else
            "Enable SMB encryption for sensitive environments: "
            "Set-SmbServerConfiguration -EncryptData $true -Force. "
            "Note: requires all clients to support SMB 3.0+"
        ),
    )]
