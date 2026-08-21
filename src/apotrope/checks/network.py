"""Check: Network configuration — listening ports, LLMNR, NetBIOS, IPv6."""

from __future__ import annotations

import logging

from apotrope.exceptions import ApotropeError
from apotrope.models import CheckResult, Severity, Status
from apotrope.utils import run_powershell, run_powershell_json

log = logging.getLogger(__name__)

CATEGORY = "Network"

# Build a process-id lookup once, then join it to listening connections.
_PS_TCP_LISTEN = (
    "$procs = @{}; "
    "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }; "
    "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
    "| Select-Object LocalPort, LocalAddress, "
    # OwningProcess is a UInt32 but the hashtable is keyed by Get-Process.Id
    # (Int32); cast the lookup key so the boxed-numeric types match (otherwise
    # every port resolves to 'Unknown').
    "@{N='ProcessName';E={if($procs[[int]$_.OwningProcess]){$procs[[int]$_.OwningProcess]}else{'Unknown'}}} "
    "| ConvertTo-Json -Compress"
)

# EnableMulticast = 0 → LLMNR disabled. Key absent → LLMNR enabled (default).
_PS_LLMNR = (
    "$v = (Get-ItemProperty "
    "-LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
    "-Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast; "
    "if ($null -eq $v) { 'NOTSET' } else { $v }"
)

# TcpipNetbiosOptions per IP-enabled adapter: 0=DHCP, 1=Enabled, 2=Disabled
_PS_NETBIOS = (
    "Get-CimInstance Win32_NetworkAdapterConfiguration "
    "| Where-Object { $_.IPEnabled } "
    "| Select-Object -ExpandProperty TcpipNetbiosOptions "
    "| ConvertTo-Json -Compress"
)

# Count active adapters with an IPv6 address assigned
_PS_IPV6 = (
    "(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
    "| Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue "
    "| Measure-Object).Count"
)

# Ports to flag if found listening on any interface
_RISKY_PORTS: dict[int, tuple[str, Status, Severity, str]] = {
    21:  ("FTP",    Status.WARN, Severity.HIGH,     "FTP transmits credentials in cleartext."),
    23:  ("Telnet", Status.FAIL, Severity.CRITICAL, "Telnet transmits all traffic in cleartext."),
    69:  ("TFTP",   Status.WARN, Severity.HIGH,     "TFTP has no authentication."),
    3389: ("RDP",   Status.WARN, Severity.MEDIUM,   "RDP is exposed; ensure NLA is enforced."),
}

# Disable NetBIOS over TCP/IP on every IP-enabled adapter. Get-CimInstance returns
# inert CIM objects with no callable methods, so SetTcpipNetbios must be invoked via
# Invoke-CimMethod — the legacy Get-WmiObject "().SetTcpipNetbios(2)" form fails with
# "does not contain a method named 'SetTcpipNetbios'".
#
# The ReturnValue must be reported, not discarded. WMI signals failure through a
# uint32 ReturnValue rather than a PowerShell error, so -ErrorAction and $? see
# nothing and `| Out-Null` swallows the only signal there is. SetTcpipNetbios
# returns 1 for "succeeded, REBOOT REQUIRED" as routinely as 0 — piping to
# Out-Null means the operator sees a clean prompt, never reboots, NBT-NS keeps
# answering, and Apotrope reports the host remediated on a machine where
# Responder-style relay still works.
#
# $adapter captures the pipeline object because switch REBINDS $_ to the value
# being tested: inside the branches $_ is the numeric ReturnValue, so
# $_.Description there is empty and every adapter reports anonymously — on a
# mixed success/failure machine the operator cannot tell which adapter still
# needs attention.
_CMD_NETBIOS_DISABLE = (
    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
    "ForEach-Object {\n"
    "    $adapter = $_\n"
    "    $r = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios "
    "-Arguments @{ TcpipNetbiosOptions = 2 }\n"
    "    switch ($r.ReturnValue) {\n"
    "        0 { \"$($adapter.Description): NetBIOS disabled\" }\n"
    "        1 { Write-Warning \"$($adapter.Description): disabled, REBOOT REQUIRED\" }\n"
    "        default { Write-Warning "
    "\"$($adapter.Description): failed, ReturnValue=$($r.ReturnValue)\" }\n"
    "    }\n"
    "}"
)

# Port 3389. Two deliberate choices here:
#
# -Group '@FirewallAPI.dll,-28752' rather than -DisplayGroup 'Remote Desktop':
# DisplayGroup is the resolved MUI string, so it matches nothing on non-English
# Windows and the cmdlet no-ops with a non-terminating error the operator will
# not notice.
#
# The scoping line is COMMENTED OUT and carries no default scope. Making the
# selector locale-neutral is exactly what makes an active scoping line
# dangerous: 'LocalSubnet' locks out any operator connected from another subnet
# — a jump host, a VPN pool, a different VLAN — which is the normal enterprise
# case and the very outcome the NLA-not-block choice was meant to avoid. The
# operator must supply their own management network.
_CMD_RDP_EXPOSED = (
    "# Require Network Level Authentication for RDP:\n"
    "Set-ItemProperty -Path "
    "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
    "-Name 'UserAuthentication' -Value 1\n"
    "# Then restrict who can reach 3389. Replace the range below with YOUR\n"
    "# management network, and confirm it contains the address you are\n"
    "# connected from before running it — this can end your own RDP session:\n"
    "# Set-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -RemoteAddress 10.0.0.0/8"
)


def run() -> list[CheckResult]:
    """Return network exposure checks.

    Returns:
        list[CheckResult]: Results for risky listening ports, all-ports summary,
        LLMNR, NetBIOS, and IPv6 awareness.
    """
    results: list[CheckResult] = []
    results.extend(_check_listening_ports())
    results.extend(_check_llmnr())
    results.extend(_check_netbios())
    results.extend(_check_ipv6())
    return results


def _check_listening_ports() -> list[CheckResult]:
    """Enumerate TCP listening ports and flag known-dangerous services."""
    try:
        data = run_powershell_json(_PS_TCP_LISTEN)
    except ApotropeError as exc:
        return [_error("Listening Ports", str(exc))]

    conns = data if isinstance(data, list) else ([data] if data else [])

    # Build a compact set for risky-port lookup:  port → (addr, process)
    risky_hits: dict[int, list[tuple[str, str]]] = {}
    all_ports: list[str] = []

    for conn in conns:
        port = int(conn.get("LocalPort") or 0)
        addr = str(conn.get("LocalAddress") or "?")
        proc = str(conn.get("ProcessName") or "Unknown")
        all_ports.append(f"{port}/{proc}")
        if port in _RISKY_PORTS:
            risky_hits.setdefault(port, []).append((addr, proc))

    results: list[CheckResult] = []

    # One result per risky port found
    for port, hits in sorted(risky_hits.items()):
        service, status, severity, reason = _RISKY_PORTS[port]
        addr_list = ", ".join(f"{a} ({p})" for a, p in hits)
        if port == 23:
            # Telnet — catalog entry: stop/disable the service outright.
            remediation = "Stop and disable the Telnet service (it sends credentials in cleartext)."
            command = (
                "if (Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue) {\n"
                "    Stop-Service -Name 'TlntSvr' -Force\n"
                "    Set-Service -Name 'TlntSvr' -StartupType Disabled\n"
                "}\n"
                "if ((Get-WindowsOptionalFeature -Online -FeatureName TelnetServer "
                "-ErrorAction SilentlyContinue).State -eq 'Enabled') {\n"
                "    Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart\n"
                "}"
            )
        elif port == 3389:
            # The finding is "RDP exposed; ensure NLA" — so the command must enforce
            # NLA and scope access, NOT blindly block 3389 (which would sever the
            # operator's own RDP session mid-audit). See _CMD_RDP_EXPOSED for why
            # the scoping step ships commented and without a default scope.
            remediation = (
                "RDP is exposed. Require Network Level Authentication and restrict who "
                "can reach 3389 (firewall scope or a VPN / RD gateway) rather than "
                "blocking it outright. If the RDP settings are managed by Group Policy, "
                "change them in the GPO — a local registry edit is reverted on refresh."
            )
            command = _CMD_RDP_EXPOSED
        else:
            remediation = (
                f"Stop the service behind port {port} ({service}) and block the port in Windows Firewall."
            )
            command = (
                f"New-NetFirewallRule -DisplayName 'Block inbound TCP {port} (Apotrope)' "
                f"-Direction Inbound -LocalPort {port} -Protocol TCP -Action Block"
            )
        results.append(CheckResult(
            category=CATEGORY,
            check_name=f"Listening Port — {port}/{service}",
            status=status,
            severity=severity,
            description=f"Checks whether port {port} ({service}) is listening. {reason}",
            details=f"Port {port} ({service}) is listening on: {addr_list}",
            remediation=remediation,
            command=command,
        ))

    # Summary INFO result for all listeners
    unique_ports = sorted({int(c.get("LocalPort") or 0) for c in conns})
    port_summary = ", ".join(str(p) for p in unique_ports[:30])
    if len(unique_ports) > 30:
        port_summary += f" … (+{len(unique_ports) - 30} more)"

    results.append(CheckResult(
        category=CATEGORY,
        check_name="Listening Ports — Summary",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Enumerates all TCP ports in LISTEN state.",
        details=(
            f"{len(unique_ports)} listening port(s): {port_summary}"
            if unique_ports else "No listening TCP ports found."
        ),
        remediation="",
    ))

    return results


def _check_llmnr() -> list[CheckResult]:
    """Check whether Link-Local Multicast Name Resolution (LLMNR) is disabled."""
    try:
        output = run_powershell(_PS_LLMNR).strip()
    except ApotropeError as exc:
        return [_error("LLMNR", str(exc))]

    # NOTSET means the registry key doesn't exist → LLMNR is enabled by default
    if output == "NOTSET" or output == "1":
        return [CheckResult(
            category=CATEGORY,
            check_name="LLMNR Disabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Checks whether LLMNR is disabled (LLMNR is susceptible to poisoning attacks).",
            details=(
                "LLMNR is enabled (default). "
                "Attackers on the local network can use tools like Responder "
                "to capture NTLMv2 hashes via LLMNR poisoning."
            ),
            remediation="Disable LLMNR to block Responder-style name-resolution poisoning.",
            command=(
                # reg.exe writes the value and creates the missing parents in one
                # step. New-Item -Force would replace the key and delete its
                # values; without -Force it cannot create the parents; and a
                # [Registry]::...CreateSubKey() call is blocked under Constrained
                # Language Mode. See misc.py for the full comparison.
                'reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" '
                "/v EnableMulticast /t REG_DWORD /d 0 /f\n"
                'if ($LASTEXITCODE -ne 0) { throw "reg.exe add failed ($LASTEXITCODE)" }'
            ),
        )]

    return [CheckResult(
        category=CATEGORY,
        check_name="LLMNR Disabled",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        description="Checks whether LLMNR is disabled (LLMNR is susceptible to poisoning attacks).",
        details="LLMNR is disabled via Group Policy.",
        remediation="",
    )]


def _check_netbios() -> list[CheckResult]:
    """Check whether NetBIOS over TCP/IP is disabled on all adapters."""
    try:
        data = run_powershell_json(_PS_NETBIOS)
    except ApotropeError as exc:
        return [_error("NetBIOS over TCP/IP", str(exc))]

    # A single IP-enabled adapter with TcpipNetbiosOptions=0 (the DHCP default)
    # serialises as the bare scalar 0. Do NOT use `[data] if data else []` here:
    # 0 is falsy and would be dropped, making a DHCP adapter look like "no
    # adapters". The empty-stdout case already arrives as [] (a list).
    options = data if isinstance(data, list) else [data]
    # Normalise to plain ints
    opt_ints = []
    for o in options:
        # Elements come from JSON (dict | list | scalar); only coerce scalars.
        if isinstance(o, (int, str)):
            try:
                opt_ints.append(int(o))
            except (TypeError, ValueError):
                pass

    if not opt_ints:
        return [CheckResult(
            category=CATEGORY,
            check_name="NetBIOS over TCP/IP",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Checks whether NetBIOS over TCP/IP is disabled on all network adapters.",
            details="No IP-enabled adapters found or could not read NetBIOS setting.",
            remediation="",
        )]

    enabled_count  = opt_ints.count(1)   # explicitly enabled
    dhcp_count     = opt_ints.count(0)   # via DHCP (uncertain)
    disabled_count = opt_ints.count(2)   # explicitly disabled

    if enabled_count > 0:
        status, severity = Status.WARN, Severity.MEDIUM
        details = (
            f"NetBIOS over TCP/IP is explicitly enabled on {enabled_count} adapter(s). "
            f"NetBIOS exposes the host to name-spoofing and enumeration."
        )
        remediation = "Disable NetBIOS over TCP/IP on all IP-enabled adapters."
        command = _CMD_NETBIOS_DISABLE
    elif dhcp_count > 0:
        status, severity = Status.WARN, Severity.LOW
        details = (
            f"{dhcp_count} adapter(s) inherit NetBIOS setting from DHCP. "
            "If the DHCP server does not explicitly disable NetBIOS, it may be active."
        )
        remediation = "Explicitly disable NetBIOS on all adapters rather than relying on DHCP."
        command = _CMD_NETBIOS_DISABLE
    else:
        status, severity = Status.PASS, Severity.LOW
        details = f"NetBIOS over TCP/IP is explicitly disabled on all {disabled_count} adapter(s)."
        remediation = ""
        command = ""

    return [CheckResult(
        category=CATEGORY,
        check_name="NetBIOS over TCP/IP",
        status=status,
        severity=severity,
        description="Checks whether NetBIOS over TCP/IP is disabled on all network adapters.",
        details=details,
        remediation=remediation,
        command=command,
    )]


def _check_ipv6() -> list[CheckResult]:
    """Report IPv6 status (informational — not a security finding by itself)."""
    try:
        output = run_powershell(_PS_IPV6).strip()
        count = int(output) if output.isdigit() else 0
    except (ApotropeError, ValueError):
        count = 0

    return [CheckResult(
        category=CATEGORY,
        check_name="IPv6 Status",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Reports whether IPv6 is active on any network adapter (informational).",
        details=(
            f"IPv6 is active on {count} adapter(s)."
            if count > 0 else
            "IPv6 is not active on any adapter."
        ),
        remediation="",
    )]


def _error(check_name: str, details: str) -> CheckResult:
    return CheckResult(
        category=CATEGORY,
        check_name=check_name,
        status=Status.ERROR,
        severity=Severity.INFO,
        description="An error occurred while running this check.",
        details=details,
        remediation="Run with --log-level DEBUG for more detail.",
    )
