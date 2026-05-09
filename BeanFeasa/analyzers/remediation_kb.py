"""
BeanFeasa — Remediation Knowledge Base.

Maps known Event IDs, sources, and error patterns to actionable
remediation steps. This is the "what do I do about it" layer.

Usage:
    kb = RemediationKB()
    advice = kb.lookup(event_id="41", source="Kernel-Power", message="...")
"""

from dataclasses import dataclass, field


@dataclass
class RemediationEntry:
    """A single remediation knowledge base entry."""
    event_id: str = ""
    source_match: str = ""
    message_match: str = ""
    title: str = ""
    category: str = ""
    what_it_means: str = ""
    likely_cause: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    severity_hint: str = "medium"
    references: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────
#  THE KNOWLEDGE BASE
#  Organized by category. Entries match by Event ID,
#  source substring, or message substring.
# ──────────────────────────────────────────────────────────

_KB_ENTRIES: list[RemediationEntry] = [

    # ════════════════════════════════════
    #  KERNEL / BOOT / POWER
    # ════════════════════════════════════

    RemediationEntry(
        event_id="41",
        source_match="Kernel-Power",
        title="Unexpected Shutdown (Kernel-Power 41)",
        category="System",
        what_it_means="The system rebooted without a clean shutdown. This is the classic 'dirty reboot' indicator — could be BSOD, power loss, or watchdog timeout.",
        likely_cause=[
            "Blue screen (BSOD) — check Event 1001 for BugCheck code",
            "Power loss or PSU failure",
            "Overheating causing emergency shutdown",
            "Driver causing kernel hang (watchdog timeout)",
            "Windows Update forced reboot during a hang",
        ],
        remediation=[
            "Check Event 1001 (BugCheck) for the stop code and faulting module",
            "Check WHEA events in the same time window for hardware errors",
            "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "Update chipset, storage, and GPU drivers from the manufacturer",
            "Check power supply connections and UPS status",
            "Monitor CPU/GPU temperatures under load",
        ],
        severity_hint="critical",
    ),

    RemediationEntry(
        event_id="6008",
        source_match="EventLog",
        title="Previous Shutdown Was Unexpected (6008)",
        category="System",
        what_it_means="Confirms the previous shutdown was not clean. Always appears with Kernel-Power 41.",
        likely_cause=["Same as Kernel-Power 41 — this is the companion event."],
        remediation=["See Kernel-Power 41 remediation steps."],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="1074",
        source_match="User32",
        title="Planned Shutdown/Restart (1074)",
        category="System",
        what_it_means="A user or process initiated a shutdown or restart. Includes the reason code and initiating process.",
        likely_cause=[
            "User-initiated restart",
            "Windows Update restart",
            "Group Policy or SCCM forced restart",
            "Application requested restart",
        ],
        remediation=[
            "Check the 'process' field — it tells you what initiated the restart",
            "If unexpected: check for Windows Update activity or GPO settings",
            "If svchost.exe: likely Windows Update — check CBS.log",
        ],
        severity_hint="low",
    ),

    # ════════════════════════════════════
    #  BSOD / BUGCHECK
    # ════════════════════════════════════

    RemediationEntry(
        event_id="1001",
        message_match="BugCheck",
        title="Blue Screen Crash Report (BugCheck 1001)",
        category="System",
        what_it_means="Windows Error Reporting captured a BSOD crash dump. The BugCheck code identifies the type of failure.",
        likely_cause=[
            "0x9F (DRIVER_POWER_STATE_FAILURE) — driver failed to handle power transition",
            "0x1E (KMODE_EXCEPTION_NOT_HANDLED) — kernel-mode exception",
            "0x50 (PAGE_FAULT_IN_NONPAGED_AREA) — bad memory reference, often driver or RAM",
            "0x7A (KERNEL_DATA_INPAGE_ERROR) — disk I/O failure reading kernel data",
            "0xD1 (DRIVER_IRQL_NOT_LESS_OR_EQUAL) — driver accessing memory at wrong IRQL",
            "0x124 (WHEA_UNCORRECTABLE_ERROR) — hardware failure",
            "0x133 (DPC_WATCHDOG_VIOLATION) — DPC routine took too long",
        ],
        remediation=[
            "Note the BugCheck code (e.g., 0x0000009F) and parameter values",
            "Identify the faulting module from the event — this is your culprit",
            "If .sys file: update or roll back that driver",
            "If ntoskrnl.exe: usually points to RAM or storage hardware",
            "Analyze the minidump with WinDbg: '!analyze -v'",
            "If 0x124: check WHEA events — this is a hardware error",
            "If 0x7A: check disk health — SMART status and chkdsk",
        ],
        severity_hint="critical",
    ),

    # ════════════════════════════════════
    #  WHEA / HARDWARE
    # ════════════════════════════════════

    RemediationEntry(
        event_id="17",
        source_match="WHEA",
        title="WHEA Corrected Hardware Error (17)",
        category="Hardware",
        what_it_means="A hardware error was detected and corrected (ECC memory, CPU microcode fix). Non-fatal, but frequent occurrences predict failure.",
        likely_cause=[
            "ECC memory correcting bit flips — occasional is normal, frequent is not",
            "CPU cache error corrected by microcode",
            "PCIe correctable error from an expansion card",
        ],
        remediation=[
            "If occasional (< 1/day): monitor, no action needed",
            "If frequent (multiple/hour): failing DIMM or CPU",
            "Check the 'Error Source' field for component identification",
            "Run Windows Memory Diagnostic (mdsched.exe)",
            "Update BIOS/UEFI for latest microcode",
            "If cache hierarchy error: likely CPU — check thermals first",
        ],
        severity_hint="medium",
    ),

    RemediationEntry(
        event_id="18",
        source_match="WHEA",
        title="WHEA Fatal Hardware Error (18)",
        category="Hardware",
        what_it_means="An uncorrectable hardware error occurred — the system likely crashed. The hardware cannot self-correct this error.",
        likely_cause=[
            "Failing DIMM module",
            "CPU failure (internal parity, cache)",
            "PCIe device fatal error",
            "Northbridge/memory controller error",
        ],
        remediation=[
            "This is CRITICAL — the hardware is failing",
            "Check the error source: Memory, Processor, PCIe",
            "If Memory: test each DIMM individually, replace the failing module",
            "If Processor: check thermals, update BIOS, consider RMA",
            "If PCIe: reseat/replace the expansion card",
            "Cross-reference with Event 41 and Event 1001 for crash context",
        ],
        severity_hint="critical",
    ),

    RemediationEntry(
        event_id="19",
        source_match="WHEA",
        title="WHEA Corrected Machine Check (19)",
        category="Hardware",
        what_it_means="A corrected Machine Check Exception — the CPU detected and corrected an internal error.",
        likely_cause=[
            "Cache hierarchy error — CPU L1/L2/L3 cache corrected error",
            "Bus/interconnect error",
            "TLB (Translation Lookaside Buffer) error",
        ],
        remediation=[
            "Occasional events are normal on modern CPUs",
            "If 'Cache Hierarchy Error' is frequent: check CPU thermals",
            "Update BIOS for latest Intel/AMD microcode",
            "If happening on multiple cores (different APIC IDs): system-level issue",
            "If only one core (same APIC ID repeatedly): that core may be degrading",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  DISK / STORAGE
    # ════════════════════════════════════

    RemediationEntry(
        event_id="11",
        source_match="disk",
        title="Disk Controller Error (Event 11)",
        category="Storage",
        what_it_means="The disk driver detected a controller error on a physical disk. The I/O operation failed at the hardware level.",
        likely_cause=[
            "Bad sectors on the disk",
            "Failing SATA/NVMe cable or connector",
            "Disk controller hardware failure",
            "Drive firmware bug",
            "Power supply not delivering stable power to the drive",
        ],
        remediation=[
            "Identify the drive from \\Device\\Harddisk# — map to physical disk in Disk Management",
            "Check SMART status with CrystalDiskInfo",
            "Run 'chkdsk /r' on the affected volume",
            "Check/replace SATA cable if applicable",
            "Update disk firmware from manufacturer",
            "If SMART shows reallocated sectors: plan immediate replacement",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="153",
        source_match="disk",
        title="Disk I/O Reset (Event 153)",
        category="Storage",
        what_it_means="A disk I/O operation was retried after a reset. The disk needed to be reset to complete the operation.",
        likely_cause=[
            "Disk controller timeout — drive not responding in time",
            "Overloaded I/O queue (too many concurrent operations)",
            "Failing drive or cable",
            "Power management (link state) issue with NVMe/SATA",
        ],
        remediation=[
            "Check for accompanying Event 11/129 errors",
            "Disable SATA link power management in Power Options → PCI Express",
            "For NVMe: disable APST (Autonomous Power State Transitions) in device properties",
            "Update storage controller driver from chipset vendor (not Windows Update)",
            "Check SMART status for drive health",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="55",
        source_match="Ntfs",
        title="NTFS Filesystem Corruption (Event 55)",
        category="Storage",
        what_it_means="NTFS has detected corruption in its internal data structures. The volume may be partially inaccessible.",
        likely_cause=[
            "Underlying disk hardware failure (bad sectors, controller errors)",
            "Unclean shutdown corrupted the journal",
            "RAM errors causing corrupted writes",
            "Driver bug writing garbage to disk",
        ],
        remediation=[
            "Run 'chkdsk /f /r <drive>:' — schedule for next boot if system drive",
            "If chkdsk finds errors: back up data immediately",
            "Check disk hardware with SMART (CrystalDiskInfo)",
            "Run memory diagnostic to rule out RAM-caused corruption",
            "If recurring after chkdsk: the disk is failing — replace it",
        ],
        severity_hint="critical",
    ),

    # ════════════════════════════════════
    #  SERVICES
    # ════════════════════════════════════

    RemediationEntry(
        event_id="7034",
        source_match="Service Control Manager",
        title="Service Terminated Unexpectedly (7034)",
        category="Software",
        what_it_means="A Windows service crashed. The event includes how many times this has happened.",
        likely_cause=[
            "Service binary is corrupted",
            "Unhandled exception in the service code",
            "Dependency service failed or is unavailable",
            "Memory corruption or resource exhaustion",
            "Security software (AV/EDR) interfering with the service",
        ],
        remediation=[
            "Note the service name and crash count from the event",
            "Check Application log for Event 1000 at the same time — gives the faulting module",
            "Run 'sfc /scannow' to repair corrupted system files",
            "Check service dependencies: 'sc qc <service_name>'",
            "If third-party: reinstall/update the application",
            "If system service: consider 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "Check AV/EDR logs for false positive quarantine of service DLLs",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="7031",
        source_match="Service Control Manager",
        title="Service Crash Recovery Action (7031)",
        category="Software",
        what_it_means="The SCM is taking a corrective action (restart, run program, reboot) because a service crashed.",
        likely_cause=["Same as Event 7034 — this is the recovery response."],
        remediation=[
            "Check the recovery action configured: 'sc qfailure <service_name>'",
            "If 'Restart the Computer' is configured, that explains unexpected reboots",
            "Fix the underlying service crash first (see Event 7034 steps)",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="7000",
        source_match="Service Control Manager",
        title="Service Failed to Start (7000)",
        category="Software",
        what_it_means="A service could not start. May impact dependent services and system functionality.",
        likely_cause=[
            "Service binary path is incorrect or the executable is missing",
            "Insufficient permissions (service account)",
            "Dependency service is not running",
            "Port conflict or resource lock",
        ],
        remediation=[
            "Check the service binary path: 'sc qc <service_name>'",
            "Verify the file exists and is not quarantined by AV",
            "Check dependencies: 'sc enumdepend <service_name>'",
            "Try manual start: 'net start <service_name>' and note the error",
            "Check event log for more specific error from the service itself",
        ],
        severity_hint="medium",
    ),

    RemediationEntry(
        event_id="7045",
        source_match="Service Control Manager",
        title="New Service Installed (7045)",
        category="Security",
        what_it_means="A new service was registered with the system. Legitimate for software installs, suspicious if unexpected.",
        likely_cause=[
            "Software installation (legitimate)",
            "Driver installation",
            "Attacker persistence mechanism (PsExec, Cobalt Strike, etc.)",
        ],
        remediation=[
            "Verify the service name and binary path are expected",
            "If unrecognized: check the binary with VirusTotal",
            "Check who installed it: correlate with logon events (4624)",
            "If suspicious: disable the service, quarantine the binary, investigate",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  APPLICATION CRASHES
    # ════════════════════════════════════

    RemediationEntry(
        event_id="1000",
        source_match="Application Error",
        title="Application Crash (Event 1000)",
        category="Software",
        what_it_means="A user-mode application crashed. The event includes the faulting application, module, and exception code.",
        likely_cause=[
            "Bug in the application code",
            "Corrupted application binary or DLL",
            "Memory corruption (bad RAM can cause random app crashes)",
            "Incompatible update or dependency",
            "AV/EDR quarantined a required DLL",
        ],
        remediation=[
            "Note the Faulting application name and Faulting module name",
            "If faulting module is a system DLL (ntdll.dll, kernelbase.dll): likely a bug in the app or bad RAM",
            "If faulting module is application-specific: update or reinstall the application",
            "Check the Exception code: 0xc0000005 = access violation, 0xc0000409 = stack buffer overrun",
            "If multiple different apps crash with same exception: suspect RAM — run memory diagnostic",
            "Check AV quarantine list for false positives",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  SECURITY
    # ════════════════════════════════════

    RemediationEntry(
        event_id="4625",
        title="Logon Failure (4625)",
        category="Security",
        what_it_means="An account failed to log on. Single events are normal; high volume indicates brute force.",
        likely_cause=[
            "Wrong password (user error)",
            "Locked out account",
            "Stale credentials in a service or mapped drive",
            "Brute force attack (if high volume)",
            "Pass-the-hash attempt (if Logon Type 3, NTLM)",
        ],
        remediation=[
            "Check Failure Reason and Sub Status for specifics",
            "0xC000006A = wrong password, 0xC0000234 = account locked",
            "0xC0000072 = account disabled, 0xC000006D = bad username",
            "If high volume from one source IP: block the IP, enable account lockout",
            "If high volume across many accounts: network-wide brute force",
            "Check Logon Type: 2=Interactive, 3=Network, 10=RDP",
        ],
        severity_hint="medium",
    ),

    RemediationEntry(
        event_id="4624",
        title="Successful Logon (4624)",
        category="Security",
        what_it_means="An account successfully logged on. Important for tracking who accessed the system and how.",
        likely_cause=["Normal authentication — check logon type and source for context."],
        remediation=[
            "Logon Type 2 = Interactive (local console)",
            "Logon Type 3 = Network (file share, RPC)",
            "Logon Type 7 = Unlock",
            "Logon Type 10 = RemoteInteractive (RDP)",
            "Logon Type 11 = CachedInteractive (cached domain creds)",
            "If unexpected Type 10: verify RDP access is authorized",
            "If unexpected Type 3 with NTLM: possible Pass-the-Hash",
        ],
        severity_hint="low",
    ),

    RemediationEntry(
        event_id="1102",
        title="Audit Log Cleared (1102)",
        category="Security",
        what_it_means="The Security event log was cleared. This is a strong indicator of an attacker covering their tracks.",
        likely_cause=[
            "Administrator clearing logs for maintenance (legitimate but should be rare)",
            "Attacker wiping evidence after compromise",
        ],
        remediation=[
            "Verify the account that cleared the log — it's recorded in the event",
            "If unauthorized: treat as active incident — escalate immediately",
            "Check backup log collection (SIEM, log forwarding) for the erased events",
            "Implement log forwarding to a SIEM so clearing local logs doesn't destroy evidence",
            "Consider setting the Security log to 'Do not overwrite events (Clear manually)'",
        ],
        severity_hint="critical",
    ),

    # ════════════════════════════════════
    #  NETWORK
    # ════════════════════════════════════

    RemediationEntry(
        event_id="36871",
        source_match="Schannel",
        title="TLS/SSL Fatal Error (Schannel 36871)",
        category="Network",
        what_it_means="A TLS handshake failed fatally. Encrypted communications to or from this system are broken.",
        likely_cause=[
            "Expired certificate",
            "Certificate chain incomplete (missing intermediate CA)",
            "TLS version mismatch (client requires TLS 1.2, server offers 1.0)",
            "Cipher suite mismatch",
            "Certificate private key is missing or corrupted",
        ],
        remediation=[
            "Check the certificate store (certlm.msc) for expired certs",
            "Verify the certificate chain with 'certutil -verify <cert>'",
            "Check IIS bindings or service certificate configuration",
            "Ensure TLS 1.2 is enabled: check HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
            "If LDAPS: check the DC's certificate — it must have Server Authentication EKU",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  GROUP POLICY
    # ════════════════════════════════════

    RemediationEntry(
        event_id="1085",
        source_match="GroupPolicy",
        title="Group Policy Processing Error (1085)",
        category="Software",
        what_it_means="A Group Policy client-side extension failed to process. The specific extension and error are in the event.",
        likely_cause=[
            "Network connectivity to a DC was lost during processing",
            "The GPO references a resource (file, script) that is inaccessible",
            "SYSVOL replication issue — the GPO file on this DC is stale",
            "WMI filter evaluation failed",
        ],
        remediation=[
            "Run 'gpresult /h gpresult.html' to see full GP application status",
            "Run 'gpupdate /force' and check if the error recurs",
            "Check DNS resolution to domain controllers",
            "Verify SYSVOL accessibility: 'dir \\\\<domain>\\SYSVOL'",
            "If WMI-related: 'winmgmt /verifyrepository'",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  TPM / BITLOCKER / FIRMWARE
    # ════════════════════════════════════

    RemediationEntry(
        event_id="12",
        source_match="TPM",
        title="TPM Command Failure (Event 12)",
        category="Firmware",
        what_it_means="The TPM hardware failed to execute a command. This may impact BitLocker, Windows Hello, and Credential Guard.",
        likely_cause=[
            "TPM firmware needs update",
            "TPM is in lockout state (too many failed attempts)",
            "BIOS update changed TPM configuration",
            "TPM hardware failure",
        ],
        remediation=[
            "Open TPM.msc and check status",
            "If 'TPM is ready for use': transient error, monitor",
            "If in lockout: wait for the lockout period to expire",
            "Update BIOS/UEFI firmware — includes TPM firmware updates",
            "If persistent: clear TPM (WARNING: invalidates BitLocker keys — have recovery key ready)",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="3077",
        source_match="CodeIntegrity",
        title="WDAC Code Integrity Block (3077)",
        category="Firmware",
        what_it_means="Windows Defender Application Control (WDAC) blocked an unsigned or disallowed binary from loading. This is enforced mode — the binary was prevented from running.",
        likely_cause=[
            "Legitimate application not covered by the WDAC policy",
            "Driver not signed with an approved certificate",
            "WDAC policy is too restrictive for the workload",
            "Attacker's tool was blocked (this is WDAC working correctly)",
        ],
        remediation=[
            "Check which binary was blocked in the event details",
            "If legitimate: add the binary's hash or publisher to the WDAC policy",
            "If a driver: ensure it is WHQL signed or add to the WDAC supplemental policy",
            "If on a Teams Room / kiosk: audit the policy for missing allowances",
            "Event 3076 is audit-only (would have blocked); 3077 is enforced (did block)",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  GPU / DISPLAY
    # ════════════════════════════════════

    RemediationEntry(
        message_match="nvlddmkm",
        title="NVIDIA Display Driver Crash (TDR)",
        category="Hardware",
        what_it_means="The NVIDIA kernel-mode driver (nvlddmkm.sys) stopped responding and was recovered via TDR. The display may have flickered or gone black briefly.",
        likely_cause=[
            "GPU overheating — thermal throttling led to timeout",
            "Driver bug — especially after a Windows or driver update",
            "Insufficient power delivery to GPU (PSU issue)",
            "VRAM failure on the GPU",
            "Overclock instability",
        ],
        remediation=[
            "Update to the latest NVIDIA driver from nvidia.com (not Windows Update)",
            "If the crash started after a driver update: roll back via Device Manager",
            "Monitor GPU temperature with HWiNFO64 — sustained >85°C is problematic",
            "Check PSU wattage and PCIe power connector seating",
            "If overclocked: reset to stock clocks and retest",
            "Increase TDR timeout via registry (TdrDelay) as a temporary measure",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        message_match="display driver stopped responding",
        title="Display Driver TDR Recovery",
        category="Hardware",
        what_it_means="Windows detected that the display driver was not responding and recovered it. GPU was temporarily hung.",
        likely_cause=[
            "GPU driver bug or incompatibility",
            "GPU hardware issue (overheating, failing VRAM)",
            "System memory pressure causing GPU driver starvation",
            "Conflicting display software (screen capture, remote desktop)",
        ],
        remediation=[
            "Update or roll back the display driver",
            "Check GPU temperatures during the crash window",
            "Disable hardware acceleration in browser/apps to test",
            "Check Event Viewer for the specific driver module that faulted",
            "If Intel integrated: update from Intel DSA, not Windows Update",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  WINDOWS UPDATE
    # ════════════════════════════════════

    RemediationEntry(
        event_id="19",
        source_match="WindowsUpdateClient",
        title="Windows Update Installed Successfully (19)",
        category="Software",
        what_it_means="A Windows Update was installed successfully. Useful for tracking patch compliance and correlating with post-update issues.",
        likely_cause=["Normal patching activity."],
        remediation=[
            "No action needed — informational",
            "If issues started after this update: note the KB number for rollback",
            "Run 'wmic qfe list brief' to see all installed updates",
        ],
        severity_hint="low",
    ),

    RemediationEntry(
        event_id="20",
        source_match="WindowsUpdateClient",
        title="Windows Update Installation Failed (20)",
        category="Software",
        what_it_means="A Windows Update failed to install. The error code in the event identifies the failure reason.",
        likely_cause=[
            "Disk space insufficient for the update",
            "Component store corruption (SxS / WinSxS)",
            "Conflicting software (AV, VPN agent, driver)",
            "Network interruption during download",
            "Pending reboot from a previous update blocking this one",
        ],
        remediation=[
            "Note the error code: 0x80070002 = file not found, 0x80073712 = component store corrupt",
            "Run 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "Run 'sfc /scannow'",
            "Clear C:\\Windows\\SoftwareDistribution\\Download and retry",
            "Check C:\\Windows\\Logs\\CBS\\CBS.log for detailed failure info",
            "If persistent: use Windows Update Troubleshooter or WSUS/Intune to force",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  DHCP / DNS / NETWORK
    # ════════════════════════════════════

    RemediationEntry(
        event_id="1002",
        source_match="Dhcp",
        title="DHCP Lease Expired (1002)",
        category="Network",
        what_it_means="The DHCP lease for an interface has expired. The machine may have no IP address or has fallen back to APIPA (169.254.x.x).",
        likely_cause=[
            "DHCP server unreachable (server down, VLAN misconfiguration)",
            "Network cable disconnected during renewal window",
            "DHCP scope exhausted (no addresses available)",
            "Firewall blocking DHCP traffic (UDP 67/68)",
        ],
        remediation=[
            "Run 'ipconfig /release' then 'ipconfig /renew'",
            "Check if the DHCP server is reachable: 'ping <dhcp_server>'",
            "Check DHCP scope utilization on the server",
            "If on WiFi: forget and re-join the network",
            "If APIPA (169.254): the machine cannot reach any DHCP server",
        ],
        severity_hint="medium",
    ),

    RemediationEntry(
        event_id="4015",
        source_match="DNS",
        title="DNS Server Error (4015)",
        category="Network",
        what_it_means="The DNS Server encountered an error while processing a zone or query. May impact name resolution for the entire zone.",
        likely_cause=[
            "DNS zone file corruption",
            "AD-integrated zone replication failure",
            "Insufficient permissions on zone data",
            "DNS server running out of resources",
        ],
        remediation=[
            "Check DNS Manager for zone status",
            "Run 'dnscmd /enumzones' to list zone health",
            "If AD-integrated: check AD replication with 'repadmin /replsummary'",
            "Restart the DNS Server service as a quick fix",
            "Clear the DNS server cache: 'dnscmd /clearcache'",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="4771",
        title="Kerberos Pre-Authentication Failed (4771)",
        category="Security",
        what_it_means="Kerberos pre-authentication failed for an account. Similar to 4625 but specific to Kerberos.",
        likely_cause=[
            "Wrong password",
            "Clock skew > 5 minutes between client and DC",
            "Account locked out or disabled",
            "Encryption type mismatch (RC4 vs AES)",
            "Stale Kerberos tickets cached on the client",
        ],
        remediation=[
            "Check failure code: 0x18 = wrong password, 0x12 = account disabled/expired",
            "0x17 = password expired, 0x6 = unknown principal",
            "Check time sync: 'w32tm /query /status' — must be within 5 min of DC",
            "Run 'klist purge' on the client to clear cached tickets",
            "Check account status in AD: lockout, expiration, password age",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  STORAGE / VOLUME
    # ════════════════════════════════════

    RemediationEntry(
        event_id="129",
        source_match="storahci",
        title="Storage Controller Reset (storahci 129)",
        category="Storage",
        what_it_means="The storage controller (AHCI) has reset a device. The I/O command timed out and the controller had to reset to recover.",
        likely_cause=[
            "NVMe/SATA drive not responding to commands in time",
            "Power management (APST/HIPM/DIPM) putting the drive to sleep too aggressively",
            "Failing drive firmware",
            "Overheated drive throttling I/O",
        ],
        remediation=[
            "Disable AHCI Link Power Management: Power Options → PCI Express → Link State",
            "For NVMe: disable APST in device properties → Power Management",
            "Update storage controller driver from the chipset vendor",
            "Update drive firmware from the manufacturer (KIOXIA, Samsung, WD, etc.)",
            "Check drive temperature with CrystalDiskInfo",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="137",
        source_match="Ntfs",
        title="NTFS Delayed Write Failure (137)",
        category="Storage",
        what_it_means="Windows was unable to save data to a file. Data that should have been written to disk has been lost.",
        likely_cause=[
            "Disk removed or disconnected while writes were pending",
            "USB drive pulled without safe removal",
            "Network drive disconnected during write",
            "Disk hardware failure mid-write",
        ],
        remediation=[
            "Check which volume is affected — the event includes the drive letter",
            "If USB: always use safe removal before unplugging",
            "If internal disk: check Event 11/153 for disk hardware errors",
            "Run 'chkdsk /r' on the affected volume",
            "If network drive: check network stability and SMB session health",
        ],
        severity_hint="critical",
    ),

    RemediationEntry(
        event_id="98",
        source_match="Ntfs",
        title="NTFS Post-Crash Volume Recovery (98)",
        category="Storage",
        what_it_means="NTFS dirty-bit recovery notification. This fires on every volume that was not cleanly unmounted (e.g., after a BSOD or power loss) and reports that NTFS has checked and recovered the volume. Parameter value 0 means recovery succeeded with NO errors. This is EXPECTED after every crash and is NOT evidence of corruption.",
        likely_cause=[
            "Unclean shutdown (BSOD, power loss, watchdog timeout) — this event is the NORMAL recovery",
            "Parameter 0 = all volumes remounted cleanly — no filesystem damage",
            "Only concerning if parameter is non-zero, which indicates actual repair was needed",
        ],
        remediation=[
            "If parameter = 0: NO ACTION NEEDED — this confirms filesystem integrity after crash",
            "This event closes the filesystem corruption question — volumes are clean",
            "If parameter is non-zero: THEN run 'chkdsk /r' and check for disk hardware errors",
            "Focus investigation on the CAUSE of the crash (Kernel-Power 41), not on this recovery event",
        ],
        severity_hint="low",
    ),

    # ════════════════════════════════════
    #  TEAMS / COLLABORATION
    # ════════════════════════════════════

    RemediationEntry(
        message_match="Teams",
        source_match="Application Error",
        title="Microsoft Teams Application Crash",
        category="Software",
        what_it_means="Microsoft Teams has crashed. May affect ongoing calls, meetings, or chat functionality.",
        likely_cause=[
            "Teams client update in progress",
            "Corrupted Teams cache",
            "GPU driver incompatibility with Teams video rendering",
            "Conflicting browser extensions or Outlook add-ins",
            "Insufficient memory during a meeting with many participants",
        ],
        remediation=[
            "Clear Teams cache: delete contents of %appdata%\\Microsoft\\Teams",
            "Update Teams to the latest version",
            "If video-related: update GPU drivers, disable hardware acceleration in Teams settings",
            "Check if the crash correlates with a specific action (screen share, gallery view)",
            "For Teams Rooms: check peripheral firmware (camera, mic, speaker bar)",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  PERFORMANCE
    # ════════════════════════════════════

    RemediationEntry(
        event_id="2004",
        source_match="Resource-Exhaustion",
        title="Resource Exhaustion Warning (2004)",
        category="Performance",
        what_it_means="Windows has detected that the system is running critically low on virtual memory (commit charge approaching the limit).",
        likely_cause=[
            "Memory leak in an application",
            "Too many applications running simultaneously",
            "Pagefile too small for the workload",
            "Kernel pool exhaustion from a buggy driver",
        ],
        remediation=[
            "Open Task Manager → Details → sort by Memory to find the top consumer",
            "If a single process is consuming GBs: likely a memory leak — restart it",
            "Increase pagefile size: System → Advanced → Performance → Virtual Memory",
            "Consider adding physical RAM if workload is legitimately large",
            "Use RAMMap (Sysinternals) to see where memory is allocated",
            "If 'Nonpaged Pool' is large: use poolmon to find the leaking driver",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        event_id="6008",
        source_match="EventLog",
        title="Unexpected Shutdown (EventLog 6008)",
        category="System",
        what_it_means="The previous system shutdown was unexpected — this is the EventLog service's record confirming a dirty shutdown.",
        likely_cause=[
            "Same root cause as Kernel-Power 41",
            "Power failure, BSOD, or watchdog timeout",
        ],
        remediation=[
            "Cross-reference with Kernel-Power 41 at the same timestamp",
            "Check Event 1001 for BugCheck data",
            "See Kernel-Power 41 remediation steps",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  SENTINEL ONE / EDR
    # ════════════════════════════════════

    RemediationEntry(
        message_match="SentinelOne",
        title="SentinelOne Agent Event",
        category="Security",
        what_it_means="SentinelOne endpoint agent has generated an event — could be a detection, quarantine, service issue, or operational message.",
        likely_cause=[
            "Threat detection (malware, suspicious script, PUP)",
            "False positive on a custom IT tool or script",
            "Agent service crash or update issue",
            "Policy conflict or exclusion needed",
        ],
        remediation=[
            "Check the S1 Management Console for the full threat details",
            "If false positive: add a path/hash exclusion in the S1 policy",
            "Common FP targets: custom batch scripts, Python tools, admin utilities",
            "If service crash: check Application Error (1000) for faulting module",
            "If agent offline: verify network connectivity and management server reachability",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  SCHEDULED TASKS
    # ════════════════════════════════════

    RemediationEntry(
        event_id="101",
        source_match="TaskScheduler",
        title="Scheduled Task Failed to Start (101)",
        category="Software",
        what_it_means="The Task Scheduler failed to start a scheduled task. The task action could not be executed.",
        likely_cause=[
            "Task action binary no longer exists at the configured path",
            "Run-as account password has changed or expired",
            "Task trigger fired but conditions (idle, AC power) were not met",
            "Insufficient permissions for the task's run-as account",
        ],
        remediation=[
            "Open Task Scheduler → find the task → check the action path",
            "Verify the run-as account credentials are current",
            "Check the task's Conditions tab for restrictive requirements",
            "Check the task History tab for previous failure details",
            "Test by right-clicking the task → Run",
        ],
        severity_hint="medium",
    ),

    RemediationEntry(
        event_id="4698",
        title="Scheduled Task Created (4698)",
        category="Security",
        what_it_means="A new scheduled task was registered. Legitimate for software installs, suspicious if unexpected — scheduled tasks are a top persistence mechanism.",
        likely_cause=[
            "Software installation creating maintenance tasks",
            "Admin creating an automation task",
            "Attacker establishing persistence (Cobalt Strike, PsExec, etc.)",
        ],
        remediation=[
            "Check the task XML in the event — note the command, arguments, and trigger",
            "Verify the creating account and whether it was expected",
            "If unrecognized: export the task XML, check the binary with VirusTotal",
            "Suspicious patterns: tasks running at login, tasks pointing to Temp/AppData",
            "Use 'schtasks /query /fo LIST /v' to dump all tasks for review",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  ACTIVE DIRECTORY / GPO
    # ════════════════════════════════════

    RemediationEntry(
        event_id="1129",
        source_match="GroupPolicy",
        title="Group Policy Connectivity Failure (1129)",
        category="Network",
        what_it_means="Group Policy processing failed because the domain controller could not be contacted. Policies will not be updated.",
        likely_cause=[
            "DNS cannot resolve domain controller SRV records",
            "Network connectivity to DC is blocked (firewall, VLAN)",
            "All DCs in the site are down",
            "VPN not connected (for remote workers)",
        ],
        remediation=[
            "Run 'nltest /dsgetsite' to check site assignment",
            "Run 'nltest /dsgetdc:<domain>' to test DC discovery",
            "Verify DNS: 'nslookup _ldap._tcp.dc._msdcs.<domain>'",
            "Check network path to DC: 'Test-NetConnection <dc> -Port 389'",
            "If VPN: ensure the VPN tunnel is established before GPO refresh",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        message_match="replication",
        source_match="NTDS",
        title="Active Directory Replication Error",
        category="Network",
        what_it_means="AD replication between domain controllers has failed. Directory changes (password resets, group membership, GPO) may not propagate.",
        likely_cause=[
            "Network connectivity between DCs interrupted",
            "DNS resolution between DCs failing",
            "Lingering objects or tombstone issues",
            "USN rollback on a restored DC",
            "Firewall blocking RPC/LDAP between DCs",
        ],
        remediation=[
            "Run 'repadmin /replsummary' to see replication health",
            "Run 'repadmin /showrepl' on the failing DC",
            "Check DNS: each DC must have correct SRV records",
            "If lingering objects: 'repadmin /removelingeringobjects'",
            "If USN rollback: the DC must be demoted and re-promoted",
            "Test connectivity: 'dcdiag /test:connectivity /s:<dc>'",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  BITLOCKER
    # ════════════════════════════════════

    RemediationEntry(
        message_match="BitLocker",
        source_match="BitLocker",
        title="BitLocker Event",
        category="Security",
        what_it_means="BitLocker Drive Encryption has reported a status change, error, or recovery event.",
        likely_cause=[
            "BIOS/firmware update changed PCR measurements",
            "Hardware change (RAM, disk) invalidated TPM seal",
            "TPM failure or lockout",
            "User entered recovery mode intentionally",
            "Secure Boot configuration changed",
        ],
        remediation=[
            "If recovery key required: retrieve from Entra ID (Azure AD), AD, or backup location",
            "Run 'manage-bde -status' to check current encryption state",
            "If triggered by BIOS update: suspend BitLocker before future BIOS updates",
            "Suspend: 'manage-bde -protectors -disable C:' → update → reboot → re-enable",
            "If TPM issue: check TPM.msc, consider clearing and reinitializing",
            "Back up recovery keys to Entra ID: 'manage-bde -protectors -adbackup C: -id {key-id}'",
        ],
        severity_hint="high",
    ),

    # ════════════════════════════════════
    #  PRINTING
    # ════════════════════════════════════

    RemediationEntry(
        message_match="spoolsv",
        title="Print Spooler Crash",
        category="Software",
        what_it_means="The Print Spooler service (spoolsv.exe) has crashed. All printing will be disrupted until it restarts.",
        likely_cause=[
            "Corrupt print driver (most common cause)",
            "Malformed print job in the queue",
            "Third-party print management software conflict",
            "PrintNightmare or other vulnerability exploitation",
        ],
        remediation=[
            "Restart the service: 'net stop spooler && net start spooler'",
            "Clear the print queue: delete files in C:\\Windows\\System32\\spool\\PRINTERS",
            "If recurring: identify the last-added printer driver and remove it",
            "Run 'printmanagement.msc' to audit installed drivers",
            "Ensure print spooler security updates are current (PrintNightmare patches)",
        ],
        severity_hint="medium",
    ),

    # ════════════════════════════════════
    #  LSASS / KERBEROS / GPO
    #  Added post USVIS-952KC14 analysis
    # ════════════════════════════════════

    RemediationEntry(
        event_id="5000",
        source_match="LsaSrv",
        title="Kerberos SSP Exception in lsass (LsaSrv 5000)",
        category="Security",
        what_it_means=(
            "The Local Security Authority (lsass.exe) caught an unhandled exception "
            "from the Kerberos authentication package. This event fires within ~1 second "
            "before every Kerberos-induced lsass crash. When followed by Event 1000 "
            "(lsass.exe faulting application), root cause is confirmed: a Kerberos "
            "authentication package failure killed lsass and forced a system restart. "
            "Previously undetected — its presence would have identified root cause "
            "immediately without manual WinDbg analysis."
        ),
        likely_cause=[
            "GPO applied AES-256-only Kerberos encryption (SupportedEncryptionTypes=24) "
            "on a system that still has RC4 service accounts or older DCs",
            "kerberos.dll or msv1_0.dll version incompatibility after a partial update",
            "Kerberos ticket renewal timeout/mismatch causing an in-progress TGT operation "
            "to fail catastrophically inside lsass",
            "Group Policy Kerberos policy change (ticket lifetime, renewal interval) applied "
            "without reboot on a system with active Kerberos sessions",
        ],
        remediation=[
            "Check HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters "
            "— SupportedEncryptionTypes value. 0x18 (24) = AES-only. If recently changed, "
            "this is the root cause vector.",
            "Check GroupPolicy/Operational log Event 1502 within 60 minutes before first crash "
            "to identify the triggering GPO application.",
            "Run 'gpresult /X' and review the Kerberos and Network Security policy sections.",
            "Temporarily add RC4 back: SupportedEncryptionTypes=0x1C (AES+RC4) to restore "
            "stability, then upgrade all RC4-only service accounts before re-enforcing AES.",
            "Check Security log Events 4768/4769 for Kerberos failure codes: "
            "0x17 = RC4 encryption not supported, 0x12 = account disabled/expired.",
            "Run 'klist' on affected machine to view current Kerberos tickets and renewal times.",
            "Run 'klist purge' to clear cached tickets after fixing the encryption policy.",
        ],
        severity_hint="critical",
        references=[
            "Event ID 5000 LsaSrv — The security package Kerberos generated an exception",
            "KB5014754 — Certificate-based authentication changes on Windows DCs",
        ],
    ),

    RemediationEntry(
        event_id="1074",
        source_match="User32",
        message_match="lsass.exe",
        title="lsass-Induced System Restart (wininit Event 1074)",
        category="Security",
        what_it_means=(
            "wininit.exe logged that lsass.exe terminated unexpectedly and caused a system "
            "restart (reason code 0x50006). This is definitive proof of a lsass-induced "
            "shutdown — wininit monitors lsass and forces a restart when lsass dies because "
            "the system cannot function without the security subsystem. This event is "
            "standalone confirmation of lsass death independent of any crash dump."
        ),
        likely_cause=[
            "Kerberos SSP exception (see LsaSrv 5000 — fires within 1 second before this)",
            "GPO applied Kerberos encryption policy incompatible with current environment",
            "SentinelOne or other security product incompatibility with lsass",
            "lsass.dll or kerberos.dll corruption after incomplete update",
        ],
        remediation=[
            "Check System log for LsaSrv Event 5000 within 5 seconds before this event "
            "— if present, root cause is Kerberos SSP exception (see that KB entry).",
            "Check Application log for Event 1000 (lsass.exe faulting application) at same time.",
            "Check GroupPolicy/Operational for Event 1502 (new settings) within 60 minutes prior.",
            "If no LsaSrv 5000 present: check for NTLM or Digest authentication package exceptions "
            "— other auth packages can also cause lsass termination.",
        ],
        severity_hint="critical",
    ),

    RemediationEntry(
        event_id="1502",
        source_match="GroupPolicy",
        title="Group Policy Applied New Settings (Event 1502)",
        category="Software",
        what_it_means=(
            "Group Policy completed a foreground or background refresh and applied at least "
            "one new policy object to this machine. This event records how many new GPO "
            "settings were applied. When correlated with crashes in the following 60 minutes, "
            "this is the primary configuration-change root-cause vector. The most impactful "
            "GPO settings that can destabilize a system are Kerberos encryption type restrictions "
            "and Credential Guard enablement."
        ),
        likely_cause=[
            "Kerberos encryption restriction GPO (Network Security: Configure encryption types "
            "allowed for Kerberos) recently deployed with AES-only setting",
            "Credential Guard enablement via Device Guard GPO",
            "Protected Users security group change applied via GP",
            "A GPO policy with a blank display name (missing ADMX template on this endpoint) "
            "applying an unrecognised registry value",
        ],
        remediation=[
            "Run 'gpresult /X C:\\Temp\\gpresult.xml' and open in XML viewer. Search for "
            "<n> elements that are blank — these are applied policies with no local ADMX "
            "template and cannot be audited without the originating policy file.",
            "In GPMC, check version numbers of all GPOs linked to the machine's OU. Compare "
            "against the 'N objects' count in Event 1502 to find which GPO(s) changed.",
            "If Kerberos policy changed: check SupportedEncryptionTypes under "
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters.",
            "Roll back the triggering GPO using GPMC Settings > Previous Versions if enabled.",
            "For blank ADMX policy names: copy the relevant ADMX file to "
            "%SYSTEMROOT%\\PolicyDefinitions (or the central store) to restore visibility.",
        ],
        severity_hint="high",
    ),

    RemediationEntry(
        message_match="LONG_POWER_PRESS",
        title="Power Button Hold — Live Dump (LPBH, Not a Crash)",
        category="System",
        what_it_means=(
            "Windows generated a live kernel diagnostic dump because the user held the power "
            "button for 7+ seconds. BugCheck codes 0x1A8 / 0x1B8 with FAILURE_BUCKET_ID "
            "'LONG_POWER_PRESS' and Arg1=0x8 are the definitive LPBH indicators. "
            "This is NOT a system crash — the machine was intentionally force-powered off. "
            "The dump is a diagnostic snapshot only. Without parameter inspection, tools "
            "misclassify these as GPU watchdog crashes."
        ),
        likely_cause=[
            "User held power button because the system appeared frozen (most common)",
            "Deliberate hard shutdown during an unresponsive state",
            "Accidental long press on a device with a capacitive power button",
        ],
        remediation=[
            "If the system was actually frozen when the user held the button: investigate the "
            "freeze cause using other findings in this report (lsass crashes, GPU hangs, "
            "kernel lockups). The LPBH is a symptom, not the cause.",
            "If the machine was healthy: no remediation needed. Document and suppress "
            "these events in future reports using the bsod-lpbh-001 rule.",
            "To confirm LPBH: open the dump in WinDbg and run '!analyze -v'. "
            "Look for FAILURE_BUCKET_ID: LONG_POWER_PRESS and BUGCHECK_P1: 8.",
            "Do NOT count LPBH dumps toward the BSOD crash count — they are not crashes.",
        ],
        severity_hint="informational",
    ),

    RemediationEntry(
        message_match="periodic crash",
        title="Periodic Crash — Scheduled or Timer-Driven Failure",
        category="Software",
        what_it_means=(
            "Crash events are occurring at a regular interval. A consistent inter-crash "
            "period (e.g., every 4 hours) strongly suggests the failure is triggered by a "
            "timer-driven operation: Kerberos ticket renewal, Group Policy background refresh, "
            "a scheduled task, or a service watchdog timer. Random hardware failures do not "
            "produce periodic patterns — periodicity is almost always a software trigger."
        ),
        likely_cause=[
            "Kerberos TGT renewal — default 10h, common GPO values: 4h, 8h, 10h",
            "Group Policy background refresh — 90min server / 30min workstation",
            "Scheduled task (backup, AV scan, compliance check) triggering instability",
            "Service watchdog or health check timer",
        ],
        remediation=[
            "Calculate the exact interval from crash timestamps and match against known timers. "
            "A 240-minute interval = Kerberos TGT renewal (4h). A 90-minute interval = "
            "Group Policy background refresh.",
            "Check Kerberos ticket lifetime: Computer Config > Windows Settings > Security "
            "Settings > Account Policies > Kerberos Policy > Maximum lifetime for user ticket.",
            "Check Security log Events 4768 (TGT request) and 4769 (service ticket) for "
            "failure codes around the crash timestamps.",
            "Run 'schtasks /query /fo LIST /v > tasks.txt' and check for tasks with triggers "
            "matching the crash interval.",
            "The periodic pattern is a symptom — address the underlying failure the timer "
            "triggers (Kerberos auth failure, service crash, etc.).",
        ],
        severity_hint="high",
    ),

]


class RemediationKB:
    """
    Knowledge base that maps events to remediation advice.

    Lookup by Event ID, source, or message keywords.
    """

    def __init__(self, entries: list[RemediationEntry] | None = None):
        self.entries = entries or _KB_ENTRIES
        self._by_event_id: dict[str, list[RemediationEntry]] = {}
        self._build_index()

    def _build_index(self):
        for entry in self.entries:
            if entry.event_id:
                self._by_event_id.setdefault(entry.event_id, []).append(entry)

    def lookup(
        self,
        event_id: str = "",
        source: str = "",
        message: str = "",
    ) -> list[RemediationEntry]:
        """
        Find matching KB entries for an event.

        Returns a list of matching entries, best match first.
        """
        results = []
        source_lower = (source or "").lower()
        message_lower = (message or "").lower()

        for entry in self.entries:
            score = 0

            # Event ID match (strongest signal)
            if entry.event_id and entry.event_id == str(event_id):
                score += 10

            # Source match
            if entry.source_match and entry.source_match.lower() in source_lower:
                score += 5

            # Message match
            if entry.message_match and entry.message_match.lower() in message_lower:
                score += 3

            if score > 0:
                results.append((score, entry))

        results.sort(key=lambda x: -x[0])
        return [entry for _, entry in results]

    def lookup_event(self, event: "ParsedEvent") -> list[RemediationEntry]:
        """Convenience: look up a ParsedEvent directly."""
        return self.lookup(
            event_id=event.event_id,
            source=event.source,
            message=event.message,
        )

    def get_all_covered_event_ids(self) -> set[str]:
        """Return all Event IDs that have KB entries."""
        return {e.event_id for e in self.entries if e.event_id}

    def get_categories(self) -> set[str]:
        """Return all categories in the KB."""
        return {e.category for e in self.entries}
