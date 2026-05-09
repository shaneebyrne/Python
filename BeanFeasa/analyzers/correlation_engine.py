"""
BeanFeasa — Correlation Engine v3.

v3 changes (post USVIS-952KC14):
  - Added chain-lsass-krb-001: LsaSrv 5000 → lsass Event 1000 → wininit 1074.
    This single chain would have identified root cause in USVIS-952KC14
    without manual WinDbg analysis.
  - Added chain-gpo-crash-001: GPO Event 1502 (new settings) → crash within 60 min.
  - Fixed chain-ad-001: added boot-window suppression. Netlogon 5719 within
    120 seconds of system boot (EventLog 6005/6009) is a normal transient
    failure, not an AD incident. Previously fired as an independent incident
    on every post-crash reboot (INC-0002 in USVIS-952KC14 analysis).
  - Integrated bsod_classifier: _enrich_bsod now detects LONG_POWER_PRESS_HALT
    dumps and prevents them from producing a false GPU-crash primary finding.
  - Added boot timestamp tracking alongside existing crash timestamp tracking.
  - Added suppress_if_boot_artifact / boot_window_seconds to EventChain.

v2 changes:
  - Evidence gating: required_link_indices specify which links MUST match.
  - Compound event keys: (source, event_id) matching.
  - Crash timeline suppression: post-crash network/AD events downgraded.
  - Security context filtering: logon type, source address, caller process.
  - WER message body parsing for faulting module extraction.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from parsers.base import ParsedEvent
from analyzers.wer_parser import parse_wer_message, count_unique_dumps

try:
    from utils.bsod_classifier import classify as classify_bugcheck
    _HAS_CLASSIFIER = True
except ImportError:
    _HAS_CLASSIFIER = False


@dataclass
class CorrelatedIncident:
    incident_id: str
    title: str
    severity: str
    category: str
    description: str
    root_cause: str = ""
    remediation: list[str] = field(default_factory=list)
    events: list[ParsedEvent] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    computer: str = ""
    event_count: int = 0
    confidence: str = "medium"
    is_crash_artifact: bool = False
    faulting_module: str = ""
    crash_count: int = 0

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "root_cause": self.root_cause,
            "remediation": " | ".join(self.remediation),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "computer": self.computer,
            "event_count": self.event_count,
            "confidence": self.confidence,
            "faulting_module": self.faulting_module,
        }

    @staticmethod
    def csv_headers() -> list[str]:
        return [
            "incident_id", "title", "severity", "category",
            "description", "root_cause", "remediation",
            "first_seen", "last_seen", "computer",
            "event_count", "confidence", "faulting_module",
        ]


@dataclass
class ChainLink:
    event_id: str = ""
    source: str = ""
    message: str = ""
    message_exclude: str = ""
    required: bool = False


@dataclass
class EventChain:
    chain_id: str
    title: str
    severity: str
    category: str
    links: list[ChainLink]
    time_window_minutes: int = 30
    min_links_required: int = 2
    min_event_count: int = 0     # v4: minimum matching events before incident fires (0=no extra gate)
    description: str = ""
    root_cause: str = ""
    remediation: list[str] = field(default_factory=list)
    confidence: str = "high"
    suppress_if_crash_artifact: bool = False
    suppress_if_boot_artifact: bool = False
    boot_window_seconds: int = 120


# ── KNOWN CHAINS ──────────────────────────────────────────────

KNOWN_CHAINS: list[EventChain] = [

    # ── v3 NEW: Kerberos SSP → lsass crash (root cause chain) ──────────────
    EventChain(
        chain_id="chain-lsass-krb-001",
        title="Kerberos SSP Exception → lsass Crash (Root Cause Confirmed)",
        severity="critical",
        category="lsass",
        links=[
            # LsaSrv Event 5000 fires <1 second before every lsass death
            # caused by a Kerberos package exception
            ChainLink(event_id="5000", source="LsaSrv", required=True),
            # lsass.exe terminates — recorded as Application Error 1000
            ChainLink(event_id="1000", source="Application Error",
                      message="lsass.exe", required=True),
            # wininit restarts the system — optional (may not appear if dump pre-empts)
            ChainLink(event_id="1074", source="User32", message="lsass.exe"),
        ],
        time_window_minutes=5,
        min_links_required=2,
        description=(
            "Confirmed Kerberos-induced lsass crash. LsaSrv Event 5000 (Kerberos "
            "package unhandled exception) fires within seconds before every lsass.exe "
            "termination in this pattern. This chain identifies root cause definitively "
            "without requiring WinDbg analysis."
        ),
        root_cause=(
            "Kerberos authentication package (kerberos.dll) threw an unhandled exception "
            "inside lsass.exe. Common triggers: GPO applied AES-256-only encryption "
            "(SupportedEncryptionTypes=24) on a system with RC4 service accounts; "
            "kerberos.dll version incompatibility after partial update; Kerberos ticket "
            "renewal interval mismatch. Check GroupPolicy/Operational log for Event 1502 "
            "preceding the first crash."
        ),
        remediation=[
            "Check HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters "
            "SupportedEncryptionTypes value. 0x18 (24) = AES-only — breaks RC4 service accounts.",
            "Run gpresult /X and review Kerberos/Security policy sections for recent changes.",
            "Check GroupPolicy/Operational log Event 1502 within 60 minutes before first crash.",
            "Temporarily add RC4 back (SupportedEncryptionTypes=0x1C) to restore stability, "
            "then identify and upgrade all RC4-only service accounts before re-enforcing AES.",
            "Check Security log Event 4768/4769 for Kerberos failure codes (0x17 = RC4 unsupported).",
        ],
        confidence="high",
    ),

    # ── v3 NEW: GPO change → crash (configuration root cause chain) ─────────
    EventChain(
        chain_id="chain-gpo-crash-001",
        title="GPO Change Applied → Subsequent System Crash",
        severity="critical",
        category="configuration",
        links=[
            # GPO Event 1502: new settings applied
            ChainLink(event_id="1502", source="GroupPolicy",
                      message="new settings", required=True),
            # Any crash or lsass death following the GPO change
            ChainLink(event_id="1000", source="Application Error", message="lsass.exe"),
            ChainLink(event_id="41",   source="Kernel-Power"),
            ChainLink(event_id="1074", source="User32", message="lsass.exe"),
        ],
        time_window_minutes=60,
        min_links_required=2,
        description=(
            "Group Policy applied new settings (Event 1502) followed by a system crash "
            "within 60 minutes. This is the primary configuration-change root-cause vector. "
            "The 60-minute window captures both immediate failures (settings applied during "
            "logon refresh) and deferred failures (background refresh on next service cycle)."
        ),
        root_cause=(
            "Group Policy change is the probable root cause trigger. A new policy setting "
            "applied at the time of Event 1502 caused subsequent system instability. "
            "Review the GPO change log and gpresult /X output for Kerberos encryption or "
            "security policy changes applied at that time. Confidence: medium — correlation "
            "is circumstantial without confirming the specific policy applied."
        ),
        remediation=[
            "Run gpresult /X and compare Kerberos/security policy settings against known baseline.",
            "Check GroupPolicy/Operational log for the full set of events around Event 1502.",
            "Identify changed GPOs via GPMC and compare version numbers.",
            "Roll back the most recently changed GPO using GPMC version history.",
            "If blank policy names appear in gpresult (missing ADMX): copy ADMX templates "
            "to %SYSTEMROOT%\\PolicyDefinitions to restore visibility.",
        ],
        confidence="medium",
    ),

    # ── BSOD cascade ────────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-bsod-001",
        title="BSOD / Unexpected Reboot Sequence",
        severity="critical",
        category="software",
        links=[
            ChainLink(event_id="41",   source="Kernel-Power", required=True),
            ChainLink(event_id="6008", source="EventLog"),
            ChainLink(event_id="1001", source="Windows Error Reporting", required=True),
            ChainLink(event_id="6009", source="EventLog"),
        ],
        time_window_minutes=5,
        min_links_required=2,
        description="System crashed (BSOD) and rebooted. Kernel-Power 41 + BugCheck 1001 confirm unclean shutdown.",
        root_cause="",  # Populated dynamically from WER + BSOD classifier
        remediation=[
            "Check faulting_module in this incident — if sntp.sys/Sophos: run SophosZap immediately (Sophos KB-000038247)",
            "If faulting module is a third-party .sys driver: update or roll back that driver first",
            "If ntoskrnl.exe: suspect RAM or storage — run Windows Memory Diagnostic",
            "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "If faulting module is blank: check ANOM entries for minidump analysis results",
            "For recurring BSODs with unknown cause: analyze minidump with WinDbg '!analyze -v'",
        ],
    ),

    # ── WHEA → BSOD ─────────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-whea-bsod-001",
        title="Hardware Error Leading to BSOD",
        severity="critical",
        category="hardware",
        links=[
            ChainLink(source="WHEA", required=True),
            ChainLink(event_id="41", source="Kernel-Power", required=True),
        ],
        time_window_minutes=10,
        min_links_required=2,
        description="WHEA hardware error followed by system crash. Hardware error is likely root cause.",
        root_cause="Failing hardware component (RAM, CPU, or PCIe) triggered a fatal error.",
        remediation=[
            "Check WHEA event for error source (memory, processor, PCIe)",
            "If memory: run Windows Memory Diagnostic, test DIMMs individually",
            "If processor: check thermals, update BIOS/microcode",
            "If PCIe: reseat expansion cards, check firmware",
            "Replace the identified failing component",
        ],
    ),

    # ── Disk failure cascade ─────────────────────────────────────────────────
    EventChain(
        chain_id="chain-disk-001",
        title="Disk Failure Cascade",
        severity="critical",
        category="hardware",
        links=[
            ChainLink(event_id="11", source="disk", required=True),
            ChainLink(event_id="153", source="disk"),
            ChainLink(event_id="129", source="storahci"),
            ChainLink(event_id="55", source="Ntfs"),
            ChainLink(event_id="137", source="Ntfs"),
        ],
        time_window_minutes=60,
        min_links_required=2,
        description="Multiple disk errors indicating progressive drive failure.",
        root_cause="Physical disk failing — bad sectors, controller errors, or cable issues.",
        remediation=[
            "IMMEDIATELY back up all data from the affected volume",
            "Run 'chkdsk /r' on the affected volume",
            "Check SMART status with CrystalDiskInfo",
            "Check/replace SATA or NVMe cables",
            "Replace the drive — do not wait for complete failure",
        ],
    ),

    # ── Memory degradation ───────────────────────────────────────────────────
    EventChain(
        chain_id="chain-mem-001",
        title="Progressive Memory Failure",
        severity="critical",
        category="hardware",
        links=[
            ChainLink(event_id="17", source="WHEA", required=True),
            ChainLink(event_id="18", source="WHEA"),
            ChainLink(event_id="19", source="WHEA"),
        ],
        time_window_minutes=120,
        min_links_required=2,
        description="Multiple WHEA memory errors. Corrected errors escalating toward failure.",
        root_cause="One or more DIMM modules are failing.",
        remediation=[
            "Run Windows Memory Diagnostic (mdsched.exe)",
            "Check WHEA events for specific DIMM slot / APIC ID",
            "Reseat all memory modules",
            "Test each DIMM individually",
            "Update BIOS for latest microcode",
        ],
    ),

    # ── Service crash loop ───────────────────────────────────────────────────
    EventChain(
        chain_id="chain-svc-001",
        title="Service Crash Loop",
        severity="high",
        category="software",
        links=[
            ChainLink(event_id="7034", source="Service Control Manager", required=True),
            ChainLink(event_id="7031", source="Service Control Manager"),
            ChainLink(event_id="7023", source="Service Control Manager"),
        ],
        time_window_minutes=30,
        min_links_required=2,
        description="A service is repeatedly crashing and being restarted by the SCM.",
        root_cause="Service binary corrupted, has unmet dependencies, or persistent runtime error.",
        remediation=[
            "Identify the crashing service from the event message",
            "Check Application log for corresponding Event 1000 with faulting module",
            "Run 'sfc /scannow' to check for corrupted system files",
            "Reinstall or update the service's parent application",
            "Check AV/EDR logs for false positive quarantine of service DLLs",
        ],
    ),

    # ── WU failure → reboot ──────────────────────────────────────────────────
    EventChain(
        chain_id="chain-wu-001",
        title="Windows Update Failure Triggering Reboot",
        severity="high",
        category="software",
        links=[
            ChainLink(event_id="20", source="WindowsUpdateClient", required=True),
            ChainLink(event_id="1074", source="User32"),
            ChainLink(event_id="41", source="Kernel-Power"),
        ],
        time_window_minutes=60,
        min_links_required=2,
        description="Windows Update installation failed and triggered instability.",
        root_cause="Failed update left the system in an inconsistent state.",
        remediation=[
            "Check WindowsUpdate.log and CBS.log for the specific error code",
            "Run 'DISM /Online /Cleanup-Image /RestoreHealth'",
            "Clear SoftwareDistribution folder and retry",
            "Check for conflicting software (AV, VPN, management agents)",
        ],
    ),

    # ── Brute force (network logon) ──────────────────────────────────────────
    EventChain(
        chain_id="chain-bf-001",
        title="Brute Force Attack — Possible Success",
        severity="critical",
        category="security",
        links=[
            ChainLink(event_id="4625", required=True, message_exclude="consent.exe"),
            ChainLink(event_id="4624", message="Logon Type:\t\t3", required=True),
        ],
        time_window_minutes=15,
        min_links_required=2,
        description="Multiple failed logon attempts followed by successful REMOTE logon (Type 3/10).",
        root_cause="An attacker or automated tool guessed valid credentials via network logon.",
        remediation=[
            "Verify the successful logon (4624) — check source IP and logon type",
            "If unauthorized: reset the compromised account password immediately",
            "Enable account lockout policy",
            "Check for lateral movement on other machines",
            "Block the source IP if external",
            "Enable MFA for the affected account",
        ],
    ),

    # ── Brute force (RDP) ────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-bf-002",
        title="RDP Brute Force — Possible Success",
        severity="critical",
        category="security",
        links=[
            ChainLink(event_id="4625", required=True, message_exclude="consent.exe"),
            ChainLink(event_id="4624", message="Logon Type:\t\t10", required=True),
        ],
        time_window_minutes=15,
        min_links_required=2,
        description="Multiple failed logon attempts followed by successful RDP logon (Type 10).",
        root_cause="An attacker or automated tool guessed valid credentials via RDP.",
        remediation=[
            "Check the source IP of the Type 10 logon",
            "If unauthorized: reset password, disable RDP access",
            "Enable NLA (Network Level Authentication) for RDP",
            "Enable account lockout policy",
            "Enable MFA",
        ],
    ),

    # ── Lateral movement ─────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-lateral-001",
        title="Lateral Movement Indicators",
        severity="critical",
        category="security",
        links=[
            ChainLink(event_id="4624", message="Logon Type:\t\t10", required=True),
            ChainLink(event_id="7045", source="Service Control Manager"),
            ChainLink(event_id="4698"),
        ],
        time_window_minutes=30,
        min_links_required=2,
        description="Remote logon (Type 10) combined with service or task creation.",
        root_cause="An attacker or tool is moving through the network via remote services.",
        remediation=[
            "Identify source and destination from Event 4624",
            "Check for PsExec, WMI, or PowerShell remoting artifacts",
            "Isolate affected machines",
            "Review scheduled tasks and new services",
            "Perform full AV/EDR scan",
        ],
    ),

    # ── Network connectivity ─────────────────────────────────────────────────
    EventChain(
        chain_id="chain-net-001",
        title="Network Connectivity Loss",
        severity="high",
        category="network",
        links=[
            ChainLink(event_id="1002", source="Dhcp", required=True),
            ChainLink(message="network adapter"),
            ChainLink(message="media disconnected"),
            ChainLink(event_id="8003", source="WLAN"),
        ],
        time_window_minutes=10,
        min_links_required=2,
        description="Multiple network subsystems reporting failures simultaneously.",
        root_cause="NIC failure, cable disconnect, switch port issue, or WiFi disassociation.",
        remediation=[
            "Check physical cable or WiFi signal strength",
            "Run 'ipconfig /all' to verify adapter status",
            "Run 'netsh winsock reset' and 'netsh int ip reset'",
            "Update NIC driver from manufacturer",
        ],
        suppress_if_crash_artifact=True,
    ),

    # ── AD communication — v3: also suppress within boot window ─────────────
    EventChain(
        chain_id="chain-ad-001",
        title="Active Directory Communication Failure",
        severity="high",
        category="network",
        links=[
            ChainLink(event_id="5719", source="NETLOGON", required=True),
            ChainLink(message="Group Policy", source="GroupPolicy"),
            ChainLink(event_id="4771"),
        ],
        time_window_minutes=15,
        min_links_required=1,
        description=(
            "Domain controller communication failure — Netlogon secure channel issues. "
            "NOTE: Suppressed within 120 seconds of system boot (normal transient — "
            "Netlogon fails before network stack is ready) and within 10 minutes of a "
            "crash (lsass death breaks the secure channel)."
        ),
        root_cause="DNS resolution to DCs failing, network path blocked, or secure channel broken.",
        remediation=[
            "Run 'nltest /sc_query:<domain>'",
            "Verify DNS: 'nslookup _ldap._tcp.dc._msdcs.<domain>'",
            "If post-crash: likely transient — lsass death breaks Netlogon secure channel",
            "If persistent: 'Test-ComputerSecureChannel -Repair'",
            "Check time sync: 'w32tm /query /status'",
        ],
        suppress_if_crash_artifact=True,
        suppress_if_boot_artifact=True,   # v3: suppress within 120s of boot
        boot_window_seconds=120,
    ),

    # ── BitLocker + TPM ──────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-bl-001",
        title="BitLocker Recovery Triggered by TPM",
        severity="critical",
        category="firmware",
        links=[
            ChainLink(source="BitLocker", required=True),
            ChainLink(event_id="24576", source="BitLocker"),
            ChainLink(event_id="24577", source="BitLocker"),
            ChainLink(message="recovery key"),
        ],
        time_window_minutes=10,
        min_links_required=1,
        description="BitLocker encryption has triggered recovery mode.",
        root_cause="BIOS update, hardware change, or TPM failure invalidated key protector.",
        remediation=[
            "Enter the BitLocker recovery key from Entra ID / AD",
            "Run 'manage-bde -protectors -get C:' to check protector status",
            "If caused by BIOS update: suspend BitLocker before future updates",
            "If TPM failing: check TPM.msc, clear and reinitialize if needed",
        ],
    ),

    # ── Resource exhaustion ───────────────────────────────────────────────────
    EventChain(
        chain_id="chain-perf-001",
        title="System Resource Exhaustion",
        severity="high",
        category="performance",
        links=[
            ChainLink(event_id="2004", source="Resource-Exhaustion", required=True),
            ChainLink(message="nonpaged pool"),
            ChainLink(message="out of memory"),
        ],
        time_window_minutes=30,
        min_links_required=1,
        description="System is running out of memory, causing instability.",
        root_cause="Memory leak, insufficient RAM, or kernel pool exhaustion.",
        remediation=[
            "Check Task Manager for processes with high memory usage",
            "Use RAMMap (Sysinternals) to identify pool consumers",
            "Check pagefile settings",
            "Consider adding RAM if workload is legitimate",
        ],
    ),

    # ── Encrypted volume corruption ───────────────────────────────────────────
    EventChain(
        chain_id="chain-stor-001",
        title="Encrypted Volume Corruption",
        severity="critical",
        category="storage",
        links=[
            ChainLink(event_id="55", source="Ntfs", required=True),
            ChainLink(message="BitLocker"),
            ChainLink(event_id="11", source="disk"),
        ],
        time_window_minutes=60,
        min_links_required=2,
        description="Filesystem corruption on a BitLocker volume with underlying disk errors.",
        root_cause="Physical disk errors corrupting filesystem underneath encryption.",
        remediation=[
            "Back up data immediately — decrypt if possible",
            "Run 'manage-bde -status' to check encryption health",
            "Run 'chkdsk /r' after confirming BitLocker is unlocked",
            "Check SMART status of the underlying disk",
            "Plan disk replacement",
        ],
    ),

    # ── Hard lockup ───────────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-lockup-001",
        title="Hard System Lockup (Non-BSOD Freeze)",
        severity="critical",
        category="software",
        links=[
            ChainLink(event_id="41", source="Kernel-Power", required=True),
            ChainLink(event_id="6008", source="EventLog"),
            ChainLink(event_id="98", source="Ntfs"),
        ],
        time_window_minutes=5,
        min_links_required=2,
        description=(
            "System froze without generating a bugcheck dump. Kernel-Power 41 with "
            "BugcheckCode=0 indicates a hard hang. No crash dump is available."
        ),
        root_cause=(
            "Hard lockup — common causes: driver deadlock, GPU TDR timeout, "
            "Modern Standby wake failure, or hardware hang."
        ),
        remediation=[
            "Check if lockup correlates with Kernel-Power 566 (Modern Standby) events",
            "If Teams Room: disable sleep on AC power — 'powercfg /change standby-timeout-ac 0'",
            "Update GPU driver from the manufacturer",
            "Check for USB device enumeration issues after wake",
            "If recurring: enable kernel crash dump to capture data on next occurrence",
        ],
    ),

    # ── Recurring application crash loop ─────────────────────────────────────
    EventChain(
        chain_id="chain-appcrash-loop-001",
        title="Recurring Application Crash Loop",
        severity="high",
        category="software",
        links=[
            ChainLink(event_id="1000", source="Application Error", required=True),
        ],
        time_window_minutes=1440,
        min_links_required=1,
        min_event_count=3,   # v4: must see 3+ crash events before firing
        description=(
            "An application is crashing repeatedly. 3+ crashes with a consistent "
            "faulting module indicates a broken component that will not self-heal."
        ),
        root_cause="",  # Populated from WER parsing
        remediation=[
            "Identify the faulting application and module from Event 1000",
            "Check for available updates for the crashing application",
            "Check AV/EDR quarantine for false-positived DLLs",
            "Reinstall the parent application",
            "If CLR exception (0xe0434352): check .NET Framework health",
        ],
    ),

    # ── SentinelOne injection conflict ────────────────────────────────────────
    EventChain(
        chain_id="chain-s1-inject-001",
        title="SentinelOne DLL Injection Conflict",
        severity="high",
        category="endpoint",
        links=[
            ChainLink(event_id="1000", source="Application Error", required=True),
            ChainLink(message="InProcessClient", required=True),
        ],
        time_window_minutes=60,
        min_links_required=2,
        description=(
            "An application crashed due to a SentinelOne injected DLL "
            "(InProcessClient32.dll / InProcessClient64.dll)."
        ),
        root_cause=(
            "SentinelOne DLL injection conflict with the host process. "
            "Version mismatch, thread safety issue, or COM conflict."
        ),
        remediation=[
            "Identify the crashing host process from Event 1000",
            "Add the host process to SentinelOne's interoperability exclusion list",
            "Contact S1 support for a known compatibility fix",
            "Check if updating the host application resolves the conflict",
        ],
    ),


    # ── Sophos NTP driver → BSOD (0xD1) ─────────────────────────────────────
    # RICHLT root cause: sntp.sys loads, triggers DRIVER_IRQL_NOT_LESS_OR_EQUAL
    # within seconds. Observed: driver loaded at 9:33:47, crash at 9:34:00.
    # Also fires on Sophos-NTP buffer overflow (Event 9) before a 0xD1 crash.
    EventChain(
        chain_id="chain-sophos-ntp-bsod-001",
        title="Sophos NTP Driver → BSOD (DRIVER_IRQL — sntp.sys)",
        severity="critical",
        category="software",
        links=[
            # Sophos NTP driver load event (fires within seconds of crash)
            ChainLink(source="Sophos-NetworkThreatProtection-Driver", required=True),
            # 0xD1 BSOD — DRIVER_IRQL_NOT_LESS_OR_EQUAL (sntp.sys buffer overflow)
            ChainLink(event_id="41", source="Kernel-Power", required=True),
            # WER report with 0xD1 bugcheck (optional — confirms code)
            ChainLink(event_id="1001", message="0x000000d1"),
            # Buffer overflow event (may appear before crash)
            ChainLink(source="Sophos-NetworkThreatProtection-Driver",
                      message="network event buffer is full"),
        ],
        time_window_minutes=2,
        min_links_required=2,
        description=(
            "Sophos Network Threat Protection driver (sntp.sys) loaded within "
            "minutes of a 0x000000D1 (DRIVER_IRQL_NOT_LESS_OR_EQUAL) BSOD. "
            "sntp.sys is the known crash driver on RICHLT — the driver accesses "
            "network memory at an elevated IRQL, causing a kernel fault. "
            "Confirmed: driver load at 9:33:47, crash at 9:34:00 (13 seconds). "
            "This chain fires even if Sophos is nominally 'uninstalled' — "
            "the kernel drivers survive product uninstallation and continue loading."
        ),
        root_cause=(
            "Sophos Network Threat Protection kernel driver (sntp.sys) is crashing "
            "the system. The driver is making a network buffer access at IRQL > "
            "DISPATCH_LEVEL, violating kernel memory access rules. "
            "FIX: Run SophosZap (Sophos cleanup tool) to forcibly remove all "
            "Sophos kernel drivers. Standard uninstall does NOT remove the drivers. "
            "SophosZap download: https://support.sophos.com/support/s/article/KB-000038247"
        ),
        remediation=[
            "Download and run SophosZap from Sophos support (KB-000038247). "
            "This is the ONLY reliable removal method — standard uninstall leaves "
            "sntp.sys, savonaccess.sys, SophosED.sys, and swi_callout.sys in place.",
            "After SophosZap: reboot and confirm Sophos services no longer appear "
            "in Services.msc or RunningProcesses.",
            "Verify SentinelOne is the sole active AV — check for Defender conflict too.",
            "If Sophos was intentionally deployed: contact Sophos support to get a "
            "compatible version that does not crash on this hardware/kernel combination.",
        ],
        confidence="high",
    ),

    # ── GPU TDR failure ───────────────────────────────────────────────────────
    EventChain(
        chain_id="chain-gpu-tdr-001",
        title="GPU TDR Failure — Display Driver Crash",
        severity="critical",
        category="hardware",
        links=[
            # REQUIRED: Must have VIDEO_TDR bugcheck code in WER report.
            # 0x116 = VIDEO_TDR_FAILURE. Without this the chain fired on
            # ANY Kernel-Power 41 event, producing INC-0002 on RICHLT which
            # had 0x000000D1 (DRIVER_IRQL) BSODs with zero GPU involvement.
            ChainLink(event_id="1001", source="Windows Error Reporting",
                      message="0x00000116", required=True),
            ChainLink(event_id="41", source="Kernel-Power", required=True),
            ChainLink(message="VIDEO_TDR"),
            ChainLink(event_id="4101"),
            ChainLink(message="nvlddmkm"),
            ChainLink(message="atikmpag"),
        ],
        time_window_minutes=5,
        min_links_required=2,
        description=(
            "GPU display driver timed out and failed to recover (VIDEO_TDR_FAILURE). "
            "Requires WER Event 1001 with BugCheck 0x116 to confirm GPU TDR — "
            "prevents false positive on other BSOD types (0xD1, 0x3B, etc.)."
        ),
        root_cause=(
            "GPU driver deadlock, VRAM failure, GPU overheating, or driver bug. "
            "Check for GPU driver updates and thermal throttling."
        ),
        remediation=[
            "Update GPU driver to the latest version from the manufacturer",
            "Check GPU temperatures with GPU-Z or HWiNFO — sustained >85°C causes TDR",
            "Increase TDR timeout: HKLM\\System\\CurrentControlSet\\Control\\GraphicsDrivers TdrDelay=8",
            "If recurring: DDU (Display Driver Uninstaller) clean reinstall",
            "Check for VRAM errors with GPU stress test (FurMark, OCCT)",
        ],
    ),
    # ── Sophos NTP buffer overflow → BSOD (P0 from RICHLT evaluation) ───────
    # ANOM-0020 on RICHLT correctly surfaced Sophos-NetworkThreatProtection-
    # Driver Event 9 ('network event buffer is full') but did not link it
    # to the concurrent 0xD1 BSODs. This chain explicitly connects them.
    # sntp.sys (Sophos NTP) registers NDIS callouts in tcpip.sys. When its
    # event buffer overflows, the callout writes to an already-released NBL
    # at DISPATCH_LEVEL — DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) guaranteed.
    EventChain(
        chain_id="chain-sophos-ntp-bsod-001",
        title="Sophos NTP Buffer Overflow → DRIVER_IRQL BSOD (sntp.sys)",
        severity="critical",
        category="software",
        links=[
            # Event 9 from Sophos-NetworkThreatProtection-Driver = buffer full
            ChainLink(event_id="9", source="Sophos", required=True),
            # Followed by a 0xD1 BSOD (KP41 or WER 1001 with D1 code)
            ChainLink(event_id="41",   source="Kernel-Power", required=True),
            ChainLink(event_id="1001", message="0x000000d1"),
        ],
        time_window_minutes=10,
        min_links_required=2,
        description=(
            "Sophos Network Threat Protection driver (sntp.sys) event buffer "
            "overflow (Event 9 from Sophos-NetworkThreatProtection-Driver) "
            "followed by a DRIVER_IRQL_NOT_LESS_OR_EQUAL BSOD within 10 minutes. "
            "sntp.sys registers NDIS callouts in tcpip.sys. On buffer overflow, "
            "the callout writes to an invalid Network Buffer List structure at "
            "DISPATCH_LEVEL — a guaranteed 0xD1 crash. This pattern was confirmed "
            "in all 5 minidumps on RICHLT (4/17–4/30/2026)."
        ),
        root_cause=(
            "CONFIRMED ROOT CAUSE: sntp.sys (Sophos Network Threat Protection kernel "
            "driver) is crashing tcpip.sys via an NDIS callout buffer overflow. "
            "Sophos was uninstalled via standard uninstaller but all four kernel-mode "
            "drivers (sntp.sys, savonaccess.sys, SophosED.sys, swi_callout.sys) "
            "remain loaded. SophosED.sys is a self-protecting kernel driver that "
            "prevents removal in normal mode. "
            "FIX: Run SophosZap in Safe Mode. Download from "
            "sophos.com/en-us/support/downloads/standalone-cleanup-utility. "
            "Normal uninstall WILL NOT work."
        ),
        remediation=[
            "IMMEDIATE: Download SophosZap.exe — do NOT attempt normal uninstall again",
            "Run: bcdedit /set safeboot minimal, then reboot into Safe Mode",
            "In Safe Mode: run SophosZap.exe as Administrator — accept all prompts",
            "SophosZap reboots automatically and removes the safeboot flag",
            "After reboot: verify in Device Manager (Show Hidden Devices → Non-PnP) "
            "that sntp.sys, savonaccess.sys, SophosED.sys, swi_callout.sys are gone",
            "Check C:\\Windows\\System32\\drivers\\ for absence of all 4 files",
            "If BSODs continue: secondary suspect is NVIDIA nvlddmkm.sys (3+ years old)",
        ],
        confidence="high",
    ),

    # ── Recurring service crash ───────────────────────────────────────────────
    EventChain(
        chain_id="chain-svc-crash-001",
        title="Recurring Service Crash",
        severity="medium",
        category="software",
        links=[
            ChainLink(event_id="7034", source="Service Control Manager", required=True),
        ],
        time_window_minutes=43200,
        min_links_required=1,
        description="A Windows service has terminated unexpectedly across multiple boot sessions.",
        root_cause="Service binary has a bug, unmet dependency, or environmental conflict.",
        remediation=[
            "Identify the crashing service name from the Event 7034 message",
            "Check Application log for corresponding Event 1000 with faulting module",
            "Update or reinstall the service's parent application",
            "Check AV/EDR quarantine for false-positived DLLs",
        ],
    ),
]


class CorrelationEngine:
    """
    Evidence-gated correlation engine.

    Incidents ONLY fire when required evidence is CONFIRMED PRESENT.
    Implements crash timeline and boot window suppression for downstream events.
    """

    def __init__(self, chains: list[EventChain] | None = None,
                 post_crash_window_seconds: int = 600):
        self.chains = chains or KNOWN_CHAINS
        self.incidents: list[CorrelatedIncident] = []
        self._incident_counter = 0
        self.post_crash_window = timedelta(seconds=post_crash_window_seconds)
        self.crash_timestamps: list[datetime] = []
        self.boot_timestamps: list[datetime] = []   # v3

    def correlate(
        self,
        events: list[ParsedEvent],
        source_file: str = "",
        callback=None,
    ) -> list[CorrelatedIncident]:
        self.incidents = []
        self.crash_timestamps = []
        self.boot_timestamps = []

        if not events:
            return []

        # Phase 0a: Build crash timeline from Kernel-Power 41 events
        for evt in events:
            if str(evt.event_id) == "41" and "Kernel-Power" in (evt.source or ""):
                ts = self._parse_timestamp(evt.timestamp)
                if ts:
                    self.crash_timestamps.append(ts)

        # Phase 0b: v3 — Build boot timeline from EventLog 6005/6009 (boot markers)
        for evt in events:
            if str(evt.event_id) in ("6005", "6009") and "EventLog" in (evt.source or ""):
                ts = self._parse_timestamp(evt.timestamp)
                if ts:
                    self.boot_timestamps.append(ts)

        by_computer = defaultdict(list)
        for evt in events:
            key = evt.computer or "unknown"
            by_computer[key].append(evt)

        total_machines = len(by_computer)
        for idx, (computer, machine_events) in enumerate(by_computer.items()):
            machine_events.sort(key=lambda e: e.timestamp or "")

            for chain in self.chains:
                matches = self._find_chain_matches(chain, machine_events)
                if matches is None:
                    continue

                is_crash_artifact = False
                if chain.suppress_if_crash_artifact and self.crash_timestamps:
                    is_crash_artifact = self._is_crash_artifact(matches)

                # v3: boot artifact suppression
                is_boot_artifact = False
                if chain.suppress_if_boot_artifact and self.boot_timestamps:
                    is_boot_artifact = self._is_boot_artifact(
                        matches, chain.boot_window_seconds
                    )

                is_artifact = is_crash_artifact or is_boot_artifact

                self._incident_counter += 1

                root_cause = chain.root_cause
                faulting_module = ""
                crash_count = 0

                if chain.chain_id == "chain-bsod-001":
                    root_cause, faulting_module, crash_count = self._enrich_bsod(machine_events)

                severity = chain.severity
                artifact_note = ""
                if is_boot_artifact:
                    severity = "low"
                    artifact_note = (
                        " [POST-BOOT TRANSIENT] Netlogon/AD failures within 120 seconds "
                        "of boot are normal — network stack is not yet available."
                    )
                elif is_crash_artifact:
                    severity = "low"
                    artifact_note = (
                        " [POST-CRASH ARTIFACT] This finding occurred within 10 minutes "
                        "of a confirmed crash and is likely a consequence, not an independent failure."
                    )

                # v4: extract proper first_seen/last_seen from actual timestamps
                ts_list = [
                    self._parse_timestamp(m.timestamp)
                    for m in matches
                    if m.timestamp and self._parse_timestamp(m.timestamp)
                ]
                first_seen_dt = min(ts_list).isoformat() if ts_list else (
                    matches[0].timestamp if matches else ""
                )
                last_seen_dt  = max(ts_list).isoformat() if ts_list else (
                    matches[-1].timestamp if matches else ""
                )

                # v4: extract faulting_module from Event 1000 messages if not already set
                if not faulting_module:
                    for m in matches:
                        if str(m.event_id) == "1000" and m.message:
                            msg_lower = m.message.lower()
                            for prefix in ("faulting module name: ", "faulting module: "):
                                if prefix in msg_lower:
                                    idx = msg_lower.index(prefix) + len(prefix)
                                    faulting_module = m.message[idx:].split(",")[0].strip()
                                    break
                        if faulting_module:
                            break

                # For BSOD incidents, event_count reflects the actual crash count
                # (from WER + DMP events), not just the number of chain link matches.
                effective_event_count = (
                    max(len(matches), crash_count)
                    if crash_count > 0 else len(matches)
                )

                incident = CorrelatedIncident(
                    incident_id=f"INC-{self._incident_counter:04d}",
                    title=chain.title + artifact_note,
                    severity=severity,
                    category=chain.category,
                    description=chain.description + (
                        " NOTE: " + artifact_note.strip(" []") if artifact_note else ""
                    ),
                    root_cause=root_cause or chain.root_cause,
                    remediation=list(chain.remediation),
                    events=matches,
                    first_seen=first_seen_dt,
                    last_seen=last_seen_dt,
                    computer=computer,
                    event_count=effective_event_count,
                    confidence="low" if is_artifact else chain.confidence,
                    is_crash_artifact=is_artifact,
                    faulting_module=faulting_module,
                    crash_count=crash_count,
                )
                self.incidents.append(incident)

            if callback:
                callback(idx + 1, total_machines)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        self.incidents.sort(key=lambda i: severity_order.get(i.severity, 5))

        return self.incidents

    def _find_chain_matches(
        self, chain: EventChain, events: list[ParsedEvent]
    ) -> list[ParsedEvent] | None:
        # For single-link chains (e.g., appcrash-loop): collect ALL matching events
        # so event_count and min_event_count gate work correctly.
        single_link_chain = len(chain.links) == 1

        matched_events: list[ParsedEvent] = []
        matched_links: set[int] = set()

        for event in events:
            for link_idx, link in enumerate(chain.links):
                if not single_link_chain and link_idx in matched_links:
                    continue
                if self._event_matches_link(event, link):
                    matched_events.append(event)
                    if not single_link_chain:
                        matched_links.add(link_idx)
                    else:
                        matched_links.add(0)
                    break

        # Check required links are present
        for link_idx, link in enumerate(chain.links):
            if link.required and link_idx not in matched_links:
                return None

        if len(matched_links) < chain.min_links_required:
            return None

        # v4: enforce minimum event count gate
        if chain.min_event_count > 0 and len(matched_events) < chain.min_event_count:
            return None

        if len(matched_events) >= 2:
            if not self._within_time_window(matched_events, chain.time_window_minutes):
                return None

        return matched_events

    def _event_matches_link(self, event: ParsedEvent, link: ChainLink) -> bool:
        if not link.event_id and not link.source and not link.message:
            return False

        if link.event_id and str(event.event_id) != link.event_id:
            return False

        if link.source and link.source.lower() not in (event.source or "").lower():
            return False

        if link.message and link.message.lower() not in (event.message or "").lower():
            return False

        if link.message_exclude:
            if link.message_exclude.lower() in (event.message or "").lower():
                return False

        return True

    def _is_crash_artifact(self, events: list[ParsedEvent]) -> bool:
        if not self.crash_timestamps:
            return False
        for evt in events:
            ts = self._parse_timestamp(evt.timestamp)
            if ts:
                for crash_ts in self.crash_timestamps:
                    if timedelta(0) <= (ts - crash_ts) <= self.post_crash_window:
                        return True
        return False

    def _is_boot_artifact(self, events: list[ParsedEvent], window_seconds: int = 120) -> bool:
        """v3: Check if events fall within window_seconds of a system boot."""
        if not self.boot_timestamps:
            return False
        boot_window = timedelta(seconds=window_seconds)
        for evt in events:
            ts = self._parse_timestamp(evt.timestamp)
            if ts:
                for boot_ts in self.boot_timestamps:
                    if timedelta(0) <= (ts - boot_ts) <= boot_window:
                        return True
        return False

    def _enrich_bsod(self, events: list[ParsedEvent]) -> tuple[str, str, int]:
        """
        Parse WER 1001 messages AND DMP minidump events to extract faulting
        module and crash count.

        v4 changes (post USVIS-RICHLT evaluation):
          - Now reads DMP-source events (event_id="DMP" or "DMP-MOD") from
            the Minidump Analysis parser. Previously only WER Event 1001 was
            read, so DMP events correctly named 'tcpip.sys / sntp.sys' but
            INC-0001 still showed faulting_module=blank and count='3'.
          - Total crash count = unique WER dumps + unique DMP files (deduplicated
            by dump filename extracted from event message).
          - If faulting_module contains 'sntp' or 'Sophos', adds SophosZap
            remediation to the incident automatically.
        """
        wer_messages = []
        faulting_module = ""
        lpbh_count = 0
        dmp_files_seen: set[str] = set()
        dmp_crash_count = 0

        for evt in events:
            # WER Event 1001 path
            if str(evt.event_id) == "1001" and evt.message:
                wer_messages.append(evt.message)
                info = parse_wer_message(evt.message, "1001")
                if info.faulting_module and not faulting_module:
                    faulting_module = info.faulting_module
                if "LONG_POWER_PRESS" in evt.message.upper():
                    lpbh_count += 1
                elif _HAS_CLASSIFIER and info.faulting_module:
                    for line in evt.message.splitlines():
                        if "0x1a8" in line.lower() or "0x1b8" in line.lower():
                            result = classify_bugcheck(line.split()[-1] if line.split() else "0")
                            if result.suppress_gpu:
                                lpbh_count += 1
                            break

            # DMP / DMP-MOD events from minidump parser
            elif str(evt.event_id) in ("DMP", "DMP-MOD") and (
                (evt.source or "").lower() == "minidump analysis"
            ):
                # Extract faulting module from DMP-MOD events
                if str(evt.event_id) == "DMP-MOD" and evt.message and not faulting_module:
                    faulting_module = evt.message.split("]")[0].lstrip("[").strip()
                    if not faulting_module:
                        faulting_module = evt.message[:80].strip()

                # Extract dump filename from source_file path for deduplication
                source_path = getattr(evt, "source_file", "") or (evt.metadata or {}).get("source_file", "")
                if source_path:
                    import os
                    dmp_name = os.path.basename(source_path).lower()
                    if dmp_name.endswith(".dmp") and dmp_name not in dmp_files_seen:
                        dmp_files_seen.add(dmp_name)
                        dmp_crash_count += 1
                elif str(evt.event_id) == "DMP":
                    # Count each DMP event as one crash if we can't get filename
                    dmp_crash_count += 1

        wer_crash_count, _ = count_unique_dumps(wer_messages)
        if wer_crash_count == 0:
            wer_crash_count = max(1, len(wer_messages)) if wer_messages else 0

        genuine_wer = max(0, wer_crash_count - lpbh_count)
        # Total = max of WER count and DMP count (they may overlap for same crash)
        crash_count = max(genuine_wer, dmp_crash_count) if (genuine_wer or dmp_crash_count) else 1

        # Detect Sophos sntp.sys as faulting driver
        is_sophos_crash = faulting_module and any(
            tok in faulting_module.lower()
            for tok in ("sntp", "sophos", "savon", "sophosed")
        )

        if lpbh_count > 0 and genuine_wer == 0 and dmp_crash_count == 0:
            root_cause = (
                f"No genuine crashes detected. All {lpbh_count} BugCheck event(s) are "
                "LONG_POWER_PRESS_HALT (LPBH) — user held the power button. "
                "Investigate the underlying instability using other findings in this report."
            )
        elif faulting_module and is_sophos_crash:
            root_cause = (
                f"CONFIRMED BSOD ROOT CAUSE: Sophos kernel driver — {faulting_module}. "
                f"{crash_count} crash(es) detected. "
                f"The Sophos Network Threat Protection driver (sntp.sys) is accessing "
                f"network buffers at elevated IRQL, causing DRIVER_IRQL_NOT_LESS_OR_EQUAL. "
                f"Standard uninstall does NOT remove this driver. Use SophosZap."
            )
        elif faulting_module:
            lp = f" (LPBH: {lpbh_count} excluded)" if lpbh_count else ""
            root_cause = (
                f"BSOD caused by driver/module: {faulting_module}. "
                f"{crash_count} crash(es) detected{lp}. "
                f"Update or roll back this specific driver."
            )
        else:
            root_cause = (
                f"{crash_count} BSOD crash(es) detected. "
                "Check WER Event 1001 fault bucket and minidump analysis findings "
                "for the faulting module. Analyze with WinDbg '!analyze -v'."
            )

        return root_cause, faulting_module, crash_count

    def _within_time_window(self, events: list[ParsedEvent], window_minutes: int) -> bool:
        timestamps = []
        for evt in events:
            ts = self._parse_timestamp(evt.timestamp)
            if ts:
                timestamps.append(ts)
        if len(timestamps) < 2:
            return True
        return (max(timestamps) - min(timestamps)) <= timedelta(minutes=window_minutes)

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime | None:
        if not ts_str:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str[:26], fmt)
            except ValueError:
                continue
        return None

    def get_summary(self) -> dict:
        by_category = defaultdict(int)
        by_severity = defaultdict(int)
        artifacts = 0
        for inc in self.incidents:
            by_category[inc.category] += 1
            by_severity[inc.severity] += 1
            if inc.is_crash_artifact:
                artifacts += 1
        return {
            "total_incidents": len(self.incidents),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "chains_evaluated": len(self.chains),
            "crash_artifacts_suppressed": artifacts,
        }
