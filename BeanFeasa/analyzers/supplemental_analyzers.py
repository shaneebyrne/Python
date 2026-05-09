"""
BeanFeasa — Supplemental File Analyzers.

Analyzes non-event-log collection files to surface findings that
cannot be detected from event logs alone:
  - HotfixStalenessAnalyzer  : Hotfixes.csv → update lag detection
  - InstalledAppAnalyzer     : InstalledApps.csv → EOL software detection
  - DualAVAnalyzer           : Services.csv + RunningProcesses.csv → AV stack conflicts
  - SophosKernelAnalyzer     : Services.csv → Sophos post-uninstall kernel driver detection

These findings are surfaced as SupplementalFinding objects and included
in the full report and GUI. They are separate from rule detections because
they operate on inventory files, not event logs.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path


@dataclass
class SupplementalFinding:
    finding_id: str
    category: str
    severity: str           # critical | high | medium | low | informational
    title: str
    detail: str
    recommendation: str
    source_file: str = ""
    affected_item: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "source_file": self.source_file,
            "affected_item": self.affected_item,
        }

    @staticmethod
    def csv_headers() -> list[str]:
        return [
            "finding_id", "category", "severity", "title",
            "detail", "recommendation", "source_file", "affected_item",
        ]


def _read_csv(filepath: str) -> tuple[list[dict], list[str]]:
    """Read a CSV file into a list of dicts. Returns (rows, errors)."""
    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(raw))
        rows = []
        for row in reader:
            rows.append({k.strip().lower(): (v or "").strip() for k, v in row.items()})
        return rows, []
    except Exception as exc:
        return [], [str(exc)]


def _parse_date(s: str) -> date | None:
    """Parse various date string formats to a date object."""
    if not s:
        return None
    s = s.strip()
    # Try longer/more specific formats first so AM/PM variants don't fall through
    for fmt in (
        "%m/%d/%Y %I:%M:%S %p",   # 3/24/2025 12:00:00 AM (PowerShell default)
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%Y%m%d",
    ):
        try:
            return datetime.strptime(s[:26], fmt).date()
        except ValueError:
            continue
    return None


# ── HotfixStalenessAnalyzer ──────────────────────────────────────────────────

class HotfixStalenessAnalyzer:
    """
    Reads Hotfixes.csv and flags update staleness.
      > 90 days  → MEDIUM
      > 180 days → HIGH
      > 365 days → CRITICAL (machine missing a full year of patches)
    """

    THRESHOLDS = [
        (365, "critical",
         "Machine is over 12 months behind on Windows updates. "
         "Critical security vulnerabilities are unpatched."),
        (180, "high",
         "Machine is over 6 months behind on Windows updates. "
         "Multiple security patches are missing."),
        (90,  "medium",
         "Machine is over 90 days behind on Windows updates."),
    ]

    def analyze(self, hotfix_csv: str, counter: int = 1) -> list[SupplementalFinding]:
        rows, errors = _read_csv(hotfix_csv)
        if not rows:
            return []

        today = date.today()
        dates = []
        for row in rows:
            d = _parse_date(row.get("installedon", "") or row.get("installed_on", ""))
            if d:
                dates.append(d)

        if not dates:
            return []

        most_recent = max(dates)
        age_days = (today - most_recent).days
        hotfix_count = len(rows)

        for threshold_days, severity, detail in self.THRESHOLDS:
            if age_days >= threshold_days:
                return [SupplementalFinding(
                    finding_id=f"SUPP-{counter:04d}",
                    category="patch_management",
                    severity=severity,
                    title=f"Windows Updates {age_days} Days Stale (Last: {most_recent})",
                    detail=(
                        f"{detail} Last applied hotfix: {most_recent} "
                        f"({age_days} days ago). Total hotfixes on record: {hotfix_count}."
                    ),
                    recommendation=(
                        "Apply all pending Windows cumulative updates via Windows Update "
                        "or WSUS. On RICHLT: 59+ updates pending as of 4/29/2026. "
                        "Stage update deployment through WSUS or run 'wuauclt /detectnow' "
                        "followed by 'Get-WindowsUpdate -Install -AcceptAll' in PowerShell."
                    ),
                    source_file=Path(hotfix_csv).name,
                    affected_item=f"Last hotfix: {most_recent}",
                )]
        return []


# ── InstalledAppAnalyzer ─────────────────────────────────────────────────────

class InstalledAppAnalyzer:
    """
    Reads InstalledApps.csv and flags EOL software and critically old installs.
    """

    # Known EOL version thresholds: (app_name_contains, eol_version_max, severity, note)
    EOL_RULES = [
        ("Google Chrome",       "123.0", "high",
         "Chrome 122 is past End-of-Life with multiple known CVEs. "
         "Update to current stable release immediately."),
        ("Cisco AnyConnect",    "5.0",  "high",
         "Cisco AnyConnect 4.x is EOL. Migrate to Cisco Secure Client 5.x. "
         "EOL VPN clients pose a significant security risk."),
        ("Microsoft Silverlight","6.0", "medium",
         "Silverlight is fully EOL and should be uninstalled."),
        ("Java ",               "11.0", "medium",
         "Java version may be outdated. Verify update status with vendor."),
    ]

    # Track which EOL apps have already fired to prevent duplicate findings
    _seen_eol: set = set()

    # Age-based flagging: if install date is this many days old → flag
    AGE_RULES = [
        (1095, "medium", "Software installed over 3 years ago with no recorded update."),
    ]

    def analyze(self, apps_csv: str, counter_start: int = 2) -> list[SupplementalFinding]:
        rows, errors = _read_csv(apps_csv)
        if not rows:
            return []

        findings = []
        today = date.today()
        idx = counter_start

        seen_eol: set[str] = set()

        for row in rows:
            name = row.get("displayname", "") or row.get("display_name", "")
            version = row.get("displayversion", "") or row.get("display_version", "") or row.get("version", "")
            if not name:
                continue

            # EOL check — deduplicate by (app_match, version) key
            for app_match, eol_version, severity, note in self.EOL_RULES:
                if app_match.lower() in name.lower():
                    dedup_key = f"{app_match}|{version}"
                    if version and version < eol_version and dedup_key not in seen_eol:
                        seen_eol.add(dedup_key)
                        findings.append(SupplementalFinding(
                            finding_id=f"SUPP-{idx:04d}",
                            category="eol_software",
                            severity=severity,
                            title=f"EOL Software: {name} {version}",
                            detail=f"{name} version {version} is past end-of-life. {note}",
                            recommendation=f"Update or replace {name}. {note}",
                            source_file=Path(apps_csv).name,
                            affected_item=f"{name} {version}",
                        ))
                        idx += 1

        return findings


# ── DualAVAnalyzer ───────────────────────────────────────────────────────────

# Known AV product signatures: (service_name_pattern, display_name, product_name)
_AV_SIGNATURES = [
    ("sentinelagent",       "SentinelOne",       "SentinelOne"),
    ("sentinelone",         "SentinelOne",       "SentinelOne"),
    ("savservice",          "Sophos Anti-Virus",  "Sophos"),
    ("savadminservice",     "Sophos Admin",       "Sophos"),
    ("sntpservice",         "Sophos NTP",         "Sophos"),
    ("sophos autoUpdate",   "Sophos AutoUpdate",  "Sophos"),
    ("swi_filter",          "Sophos Web Filter",  "Sophos"),
    ("windefend",           "Windows Defender",  "Defender"),
    ("msmpeng",             "Defender/MsMpEng",  "Defender"),
    ("mssecflt",            "Defender Filter",   "Defender"),
    ("crowdstrike",         "CrowdStrike",       "CrowdStrike"),
    ("csagent",             "CrowdStrike Agent", "CrowdStrike"),
    ("mfemms",              "McAfee",            "McAfee"),
    ("mfefire",             "McAfee Firewall",   "McAfee"),
    ("cylancesvc",          "Cylance",           "Cylance"),
    ("cbdefense",           "Carbon Black",      "Carbon Black"),
]


class DualAVAnalyzer:
    """
    Reads Services.csv and RunningProcesses.csv to detect multiple AV products
    running simultaneously — a frequent source of performance degradation,
    kernel conflicts, and crashes.
    """

    def analyze(
        self,
        services_csv: str,
        processes_csv: str | None = None,
        counter_start: int = 10,
    ) -> list[SupplementalFinding]:

        findings = []
        idx = counter_start
        active_products: dict[str, list[str]] = {}   # product_name → [service_names]

        # Scan services
        if Path(services_csv).exists():
            rows, _ = _read_csv(services_csv)
            for row in rows:
                svc_name = (row.get("name", "") or "").lower()
                svc_status = (row.get("status", "") or "").lower()
                if svc_status not in ("running",):
                    continue
                for pattern, display, product in _AV_SIGNATURES:
                    if pattern.lower() in svc_name:
                        active_products.setdefault(product, [])
                        if display not in active_products[product]:
                            active_products[product].append(display)

        # Scan processes
        if processes_csv and Path(processes_csv).exists():
            rows, _ = _read_csv(processes_csv)
            for row in rows:
                proc_name = (row.get("name", "") or "").lower()
                for pattern, display, product in _AV_SIGNATURES:
                    if pattern.lower() in proc_name:
                        active_products.setdefault(product, [])
                        if display not in active_products[product]:
                            active_products[product].append(display)

        if len(active_products) >= 2:
            product_list = list(active_products.keys())
            is_critical = len(active_products) >= 3

            detail_parts = []
            for prod, svcs in active_products.items():
                detail_parts.append(f"{prod} ({', '.join(svcs[:3])})")

            findings.append(SupplementalFinding(
                finding_id=f"SUPP-{idx:04d}",
                category="av_conflict",
                severity="critical" if is_critical else "high",
                title=f"{'Triple' if is_critical else 'Dual'} AV Stack Conflict: {' + '.join(product_list)}",
                detail=(
                    f"{len(active_products)} AV products running simultaneously: "
                    f"{'; '.join(detail_parts)}. "
                    "Multiple AV products at kernel level cause performance degradation, "
                    "false quarantine of each other's components, and can produce kernel "
                    "crashes via conflicting NDIS hooks or minifilter conflicts."
                ),
                recommendation=(
                    "Designate ONE AV product as the primary endpoint protection platform. "
                    "Fully remove all others using vendor-specific removal tools "
                    "(SophosZap for Sophos, not standard uninstaller). "
                    "Standard uninstallers leave kernel drivers loaded on Sophos — "
                    "run SophosZap in Safe Mode."
                ),
                source_file=Path(services_csv).name,
                affected_item=" + ".join(product_list),
            ))
            idx += 1

        return findings


# ── SophosKernelAnalyzer ─────────────────────────────────────────────────────

_SOPHOS_KERNEL_SERVICES = {
    "sntpservice":          "sntp.sys — Sophos NTP/Network Threat Protection (BSOD driver on RICHLT)",
    "savservice":           "savonaccess.sys — Sophos On-Access file system minifilter",
    "sophosed":             "SophosED.sys — Sophos self-protection kernel driver (prevents normal removal)",
    "swi_filter":           "swi_callout.sys — Sophos Web Intelligence NDIS callout",
    "swi_service":          "Sophos Web Intelligence service",
    "savadminservice":      "Sophos Anti-Virus admin service",
    "sophos autoUpdate Service": "Sophos AutoUpdate",
}

_SOPHOS_INSTALLED_MARKERS = [
    "sophos anti-virus", "sophos endpoint", "sophos autoUpdate",
    "sophos network threat", "sophos diagnostic",
]


class SophosKernelAnalyzer:
    """
    Detects Sophos kernel drivers still running after an attempted uninstall.

    The standard Sophos uninstaller removes user-mode components and registry
    entries but leaves SophosED.sys (a self-protecting kernel driver) and all
    other kernel-mode drivers loaded. This is the RICHLT root cause pattern.
    """

    def analyze(
        self,
        services_csv: str,
        apps_csv: str | None = None,
        counter_start: int = 20,
    ) -> list[SupplementalFinding]:

        findings = []
        idx = counter_start

        if not Path(services_csv).exists():
            return []

        rows, _ = _read_csv(services_csv)
        active_sophos: list[str] = []

        for row in rows:
            svc_name = (row.get("name", "") or "").lower()
            svc_status = (row.get("status", "") or "").lower()
            svc_display = (row.get("displayname", "") or "")
            if svc_status != "running":
                continue
            for pattern, description in _SOPHOS_KERNEL_SERVICES.items():
                if pattern.lower() in svc_name or pattern.lower() in svc_display.lower():
                    entry = f"{svc_display or svc_name} — {description}"
                    if entry not in active_sophos:
                        active_sophos.append(entry)

        if not active_sophos:
            return []

        # Check if Sophos appears uninstalled (not in InstalledApps or very old)
        sophos_in_apps = False
        if apps_csv and Path(apps_csv).exists():
            app_rows, _ = _read_csv(apps_csv)
            for row in app_rows:
                name = (row.get("displayname", "") or "").lower()
                for marker in _SOPHOS_INSTALLED_MARKERS:
                    if marker in name:
                        sophos_in_apps = True
                        break

        driver_list = "\n".join(f"  • {s}" for s in active_sophos)

        if sophos_in_apps:
            title = "Sophos Kernel Drivers Running (Sophos Still Installed)"
            severity = "high"
            detail = (
                f"Sophos kernel-mode services are running. "
                f"Sophos appears to be registered in installed apps but "
                f"SentinelOne is also running simultaneously (dual AV conflict). "
                f"Running Sophos kernel drivers:\n{driver_list}"
            )
        else:
            title = "Sophos Kernel Drivers Running After Failed Uninstall"
            severity = "critical"
            detail = (
                f"Sophos kernel-mode drivers are running despite Sophos appearing "
                f"to be uninstalled. Standard Sophos uninstaller removes user-mode "
                f"components but leaves SophosED.sys (self-protecting kernel driver) "
                f"and all NDIS callout drivers loaded. This is the confirmed root cause "
                f"of the 0xD1 BSOD pattern on RICHLT (sntp.sys crashing tcpip.sys via "
                f"NDIS callout). Running Sophos kernel drivers:\n{driver_list}"
            )

        findings.append(SupplementalFinding(
            finding_id=f"SUPP-{idx:04d}",
            category="sophos_residual",
            severity=severity,
            title=title,
            detail=detail,
            recommendation=(
                "Run SophosZap in Safe Mode — normal uninstall has already failed. "
                "Download: https://www.sophos.com/en-us/support/downloads/standalone-cleanup-utility\n"
                "Procedure: (1) Download SophosZap.exe while in normal mode. "
                "(2) Run: bcdedit /set safeboot minimal — reboot into Safe Mode. "
                "(3) Run SophosZap.exe as Administrator — accept all prompts. "
                "(4) SophosZap reboots and clears the safeboot flag automatically. "
                "(5) Verify: Device Manager → View → Show Hidden Devices → "
                "Non-Plug and Play Drivers — no Sophos entries should appear. "
                "(6) Check C:\\Windows\\System32\\drivers\\ for absence of sntp.sys, "
                "savonaccess.sys, SophosED.sys, swi_callout.sys."
            ),
            source_file=Path(services_csv).name,
            affected_item=f"{len(active_sophos)} Sophos kernel service(s)",
        ))

        return findings


# ── Facade ───────────────────────────────────────────────────────────────────

class SupplementalAnalyzerSuite:
    """
    Runs all supplemental analyzers against the files present in a collection folder.
    Auto-discovers which files are available.
    """

    def analyze_folder(self, folder: str) -> list[SupplementalFinding]:
        """
        Discover and analyze all supplemental files in a collection folder.
        Returns combined findings from all analyzers.
        """
        folder_path = Path(folder)
        all_findings: list[SupplementalFinding] = []
        counter = 1

        def find(name: str) -> str | None:
            for p in folder_path.rglob(name):
                return str(p)
            return None

        hotfix_path   = find("Hotfixes.csv")
        apps_path     = find("InstalledApps.csv")
        services_path = find("Services.csv")
        procs_path    = find("RunningProcesses.csv")

        if hotfix_path:
            findings = HotfixStalenessAnalyzer().analyze(hotfix_path, counter)
            all_findings.extend(findings)
            counter += len(findings) + 1

        if apps_path:
            findings = InstalledAppAnalyzer().analyze(apps_path, counter)
            all_findings.extend(findings)
            counter += len(findings) + 1

        if services_path:
            findings = DualAVAnalyzer().analyze(services_path, procs_path, counter)
            all_findings.extend(findings)
            counter += len(findings) + 1

            findings = SophosKernelAnalyzer().analyze(services_path, apps_path, counter)
            all_findings.extend(findings)
            counter += len(findings) + 1

        # Sort: critical first
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.severity, 5))
        return all_findings
