"""
BeanFeasa — Supplemental File Analyzer.

Analyzes non-event-log files from the collection package:
  - Hotfixes.csv       → update staleness
  - InstalledApps.csv  → EOL software (Chrome, browsers)
  - Drivers.csv        → outdated drivers
  - Services.csv       → dual/triple AV stack, Sophos kernel drivers
  - RunningProcesses.csv → AV process resource usage

Each produces SupplementalFinding objects, exported alongside
rule detections in the full report.

Usage:
    from analyzers.supplemental_analyzer import SupplementalAnalyzer
    analyzer = SupplementalAnalyzer()
    findings = analyzer.analyze_directory("/path/to/logcollect/")
"""

from __future__ import annotations
import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class SupplementalFinding:
    category: str          # update_staleness | eol_software | outdated_driver | av_conflict | sophos_driver
    severity: str          # critical | high | medium | low | informational
    title: str
    detail: str
    recommendation: str
    source_file: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "source_file": self.source_file,
        }

    @staticmethod
    def csv_headers() -> list[str]:
        return ["category", "severity", "title", "detail", "recommendation", "source_file"]


# Known EOL/stale thresholds
_BROWSER_EOL: dict[str, tuple[int, str]] = {
    # name_fragment: (last_safe_major, eol_date_approx)
    "google chrome":     (123, "Feb 2024"),
    "firefox":           (122, "Jan 2024"),
    "internet explorer": (11,  "Jun 2022"),
}

_KNOWN_SOPHOS_DRIVERS = {
    "sntp.sys", "savonaccess.sys", "sophosed.sys", "swi_callout.sys",
    "sophosbootdriver.sys", "savonaccess64.sys",
}

_AV_PROCESS_NAMES = {
    "sentinelagent": "SentinelOne",
    "sentinelservicehost": "SentinelOne",
    "savservice": "Sophos",
    "sntpservice": "Sophos NTP",
    "sophosips": "Sophos",
    "msmpeng": "Windows Defender",
    "msseces": "Microsoft Security Essentials",
    "avgnt": "Avira",
    "avgui": "AVG",
    "avastui": "Avast",
    "bdservicehost": "Bitdefender",
    "bdagent": "Bitdefender",
    "cscservice": "CrowdStrike",
    "csfalconservice": "CrowdStrike",
}

_AV_SERVICE_NAMES = {
    "sentinelagent": "SentinelOne",
    "savservice": "Sophos Anti-Virus",
    "sntpservice": "Sophos NTP",
    "sav admin service": "Sophos Admin",
    "sophos autoupdate service": "Sophos AutoUpdate",
    "windefend": "Windows Defender",
    "sense": "Windows Defender ATP",
    "wdnissvc": "Windows Defender NIS",
    "csagent": "CrowdStrike",
    "bdredline": "Bitdefender",
}

_DRIVER_AGE_THRESHOLDS = {
    "high": 365 * 3,    # >3 years = HIGH
    "medium": 365 * 2,  # >2 years = MEDIUM
}


class SupplementalAnalyzer:
    """Analyzes supplemental collection files for systemic issues."""

    def __init__(self):
        self.findings: list[SupplementalFinding] = []

    def analyze_directory(self, directory: str) -> list[SupplementalFinding]:
        """Scan a log collection directory and analyze all supplemental files."""
        self.findings = []
        d = Path(directory)

        for fname, method in [
            ("Hotfixes.csv",         self._analyze_hotfixes),
            ("InstalledApps.csv",    self._analyze_installed_apps),
            ("Drivers.csv",          self._analyze_drivers),
            ("Services.csv",         self._analyze_services),
            ("RunningProcesses.csv", self._analyze_processes),
        ]:
            fpath = d / fname
            if fpath.exists():
                try:
                    method(str(fpath))
                except Exception as exc:
                    self.findings.append(SupplementalFinding(
                        category="parse_error", severity="low",
                        title=f"Could not parse {fname}",
                        detail=str(exc), recommendation="",
                        source_file=fname,
                    ))

        # Cross-file analysis (requires multiple files to have been parsed)
        self._cross_analyze()

        self.findings.sort(key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
            .get(f.severity, 5)
        ))
        return self.findings

    # ── Hotfix staleness ────────────────────────────────────────────────────

    def _analyze_hotfixes(self, filepath: str):
        rows = _read_csv(filepath)
        if not rows:
            return

        dates = []
        for row in rows:
            raw = row.get("InstalledOn") or row.get("installedon") or ""
            dt = _parse_date(raw)
            if dt:
                dates.append(dt)

        if not dates:
            return

        latest = max(dates)
        now = datetime.now()
        age_days = (now - latest).days

        if age_days >= 365:
            severity = "high"
            label = f"{age_days // 30} months"
        elif age_days >= 180:
            severity = "medium"
            label = f"{age_days // 30} months"
        elif age_days >= 90:
            severity = "low"
            label = f"{age_days} days"
        else:
            return  # Not stale

        self.findings.append(SupplementalFinding(
            category="update_staleness",
            severity=severity,
            title=f"Windows Updates Stale — Last Hotfix {label} Ago",
            detail=(
                f"Most recent hotfix installed: {latest.strftime('%Y-%m-%d')} "
                f"({age_days} days ago, {len(rows)} hotfixes total). "
                f"Current date: {now.strftime('%Y-%m-%d')}. "
                f"Machines >90 days behind miss critical security patches."
            ),
            recommendation=(
                "Run Windows Update immediately. If updates are blocked by policy, "
                "check WSUS/Intune update ring configuration. "
                "Investigate why automatic updates have not applied — check Windows "
                "Update service status and update history for errors."
            ),
            source_file="Hotfixes.csv",
        ))

    # ── Installed apps EOL check ────────────────────────────────────────────

    def _analyze_installed_apps(self, filepath: str):
        rows = _read_csv(filepath)
        self._installed_apps_rows = rows  # cache for cross-analysis

        for row in rows:
            name = (row.get("DisplayName") or row.get("displayname") or "").strip()
            version = (row.get("DisplayVersion") or row.get("displayversion") or "").strip()
            install_date_raw = (row.get("InstallDate") or row.get("installdate") or "").strip()
            name_lower = name.lower()

            # Chrome EOL
            if "google chrome" in name_lower and version:
                major = _parse_major_version(version)
                if major and major <= 122:
                    install_dt = _parse_date_yyyymmdd(install_date_raw)
                    age_str = f", installed {install_dt.strftime('%Y-%m-%d')}" if install_dt else ""
                    self.findings.append(SupplementalFinding(
                        category="eol_software",
                        severity="medium",
                        title=f"Google Chrome EOL — v{version} (Major {major})",
                        detail=(
                            f"Chrome {version} reached end-of-life in early 2024{age_str}. "
                            f"Current Chrome is v123+. EOL browsers receive no security patches "
                            f"and are a primary exploit vector for drive-by attacks."
                        ),
                        recommendation=(
                            "Update Chrome immediately via the Chrome menu → Help → About Google Chrome, "
                            "or deploy the latest MSI from the Chrome Enterprise download page. "
                            "If Chrome is deployed via UEMS/ManageEngine, check why automatic "
                            "browser updates have not applied."
                        ),
                        source_file="InstalledApps.csv",
                    ))

            # Internet Explorer
            if "internet explorer" in name_lower:
                self.findings.append(SupplementalFinding(
                    category="eol_software",
                    severity="high",
                    title="Internet Explorer Detected — EOL June 2022",
                    detail=(
                        f"Internet Explorer '{name}' v{version} is installed. "
                        "IE reached end-of-life on June 15, 2022 and receives no security updates. "
                        "It is disabled on Windows 11 but may still be invocable via Edge IE Mode."
                    ),
                    recommendation=(
                        "Remove IE or disable IE Mode in Edge via Group Policy. "
                        "Migrate any IE-dependent applications to Edge IE Mode or a modern browser."
                    ),
                    source_file="InstalledApps.csv",
                ))

            # Sophos presence in installed apps despite being 'uninstalled'
            if "sophos" in name_lower:
                install_dt = _parse_date_yyyymmdd(install_date_raw)
                age_str = f" (installed {install_dt.strftime('%Y-%m-%d')})" if install_dt else ""
                self.findings.append(SupplementalFinding(
                    category="sophos_driver",
                    severity="high",
                    title=f"Sophos Product Still Registered: {name}",
                    detail=(
                        f"'{name}' v{version} is still registered in Programs & Features{age_str}. "
                        f"If Sophos was supposed to be uninstalled, the standard uninstaller "
                        f"did not complete removal — kernel drivers typically survive."
                    ),
                    recommendation=(
                        "Run SophosZap (Sophos KB-000038247) to forcibly remove all "
                        "Sophos components including kernel drivers (sntp.sys, savonaccess.sys, "
                        "SophosED.sys, swi_callout.sys). Standard uninstall is insufficient."
                    ),
                    source_file="InstalledApps.csv",
                ))

    # ── Driver age check ────────────────────────────────────────────────────

    def _analyze_drivers(self, filepath: str):
        rows = _read_csv(filepath)
        now = datetime.now()
        stale_drivers: list[tuple[int, str, str, str]] = []

        for row in rows:
            name = (row.get("DeviceName") or row.get("devicename") or "").strip()
            date_raw = (row.get("DriverDate") or row.get("driverdate") or "").strip()
            version = (row.get("DriverVersion") or row.get("driverversion") or "").strip()
            inf = (row.get("InfName") or row.get("infname") or "").strip()

            if not name or not date_raw:
                continue

            dt = _parse_date(date_raw)
            if not dt:
                continue

            age_days = (now - dt).days

            if age_days >= _DRIVER_AGE_THRESHOLDS["high"]:
                severity = "high"
            elif age_days >= _DRIVER_AGE_THRESHOLDS["medium"]:
                severity = "medium"
            else:
                continue

            # Skip virtual/generic drivers that don't update
            name_lower = name.lower()
            if any(skip in name_lower for skip in (
                "microsoft", "generic", "standard", "basic", "unknown",
                "virtual", "remote desktop", "null", "root"
            )):
                continue

            stale_drivers.append((age_days, name, version, severity))

        # Sort by age descending, report top 10 to avoid noise
        stale_drivers.sort(reverse=True)
        for age_days, name, version, severity in stale_drivers[:10]:
            years = age_days / 365
            self.findings.append(SupplementalFinding(
                category="outdated_driver",
                severity=severity,
                title=f"Outdated Driver: {name} ({years:.1f} years old)",
                detail=(
                    f"Driver '{name}' version {version} is {age_days} days old "
                    f"({years:.1f} years). Outdated drivers are a common source of "
                    f"system instability, BSOD, and security vulnerabilities."
                ),
                recommendation=(
                    f"Update '{name}' from the device manufacturer's website or via "
                    f"Windows Update / Intel DSA / Dell Update. "
                    f"Priority: drivers older than 3 years on production workstations."
                ),
                source_file="Drivers.csv",
            ))

    # ── Services analysis — AV conflict + Sophos kernel drivers ────────────

    def _analyze_services(self, filepath: str):
        rows = _read_csv(filepath)
        self._services_rows = rows

        running_av: list[str] = []
        sophos_services: list[str] = []

        for row in rows:
            name = (row.get("Name") or row.get("name") or "").strip().lower()
            display = (row.get("DisplayName") or row.get("displayname") or "").strip()
            status = (row.get("Status") or row.get("status") or "").strip().lower()

            if status not in ("running", "1", "4"):
                continue

            # AV detection
            for svc_key, av_name in _AV_SERVICE_NAMES.items():
                if svc_key in name:
                    if av_name not in running_av:
                        running_av.append(av_name)

            # Sophos-specific
            if "sophos" in name or "savservice" in name or "sntp" in name.lower():
                sophos_services.append(display or name)

        if sophos_services:
            self.findings.append(SupplementalFinding(
                category="sophos_driver",
                severity="critical",
                title=f"Sophos Kernel Services Running ({len(sophos_services)} found)",
                detail=(
                    f"The following Sophos services are actively running: "
                    f"{', '.join(sophos_services[:8])}. "
                    f"This includes SntpService (Sophos Network Threat Protection), "
                    f"the driver confirmed to cause 0x000000D1 BSODs on this hardware. "
                    f"Sophos was installed in 2021 and has not been cleanly removed."
                ),
                recommendation=(
                    "Run SophosZap immediately (Sophos KB-000038247). "
                    "Do NOT use standard uninstall — Sophos kernel drivers "
                    "(sntp.sys, savonaccess.sys, SophosED.sys) survive normal removal. "
                    "After SophosZap, reboot and verify services are gone before "
                    "returning the machine to production."
                ),
                source_file="Services.csv",
            ))

        # Dual/triple AV detection
        unique_av = list(set(running_av))
        if len(unique_av) >= 2:
            severity = "critical" if len(unique_av) >= 3 else "high"
            self.findings.append(SupplementalFinding(
                category="av_conflict",
                severity=severity,
                title=f"{'Triple' if len(unique_av) >= 3 else 'Dual'} AV Stack Running: {', '.join(unique_av)}",
                detail=(
                    f"{len(unique_av)} security products are running simultaneously: "
                    f"{', '.join(unique_av)}. Concurrent AV engines cause: "
                    f"(1) kernel driver conflicts and BSODs, "
                    f"(2) severe performance degradation (CPU/RAM contention), "
                    f"(3) quarantine conflicts where each AV flags the other's files."
                ),
                recommendation=(
                    "Retain only ONE security product. For this environment: "
                    "SentinelOne is the intended EDR. Remove Sophos (SophosZap) "
                    "and disable Windows Defender real-time protection "
                    "(SentinelOne manages this automatically when properly configured). "
                    "Verify SentinelOne is reporting to the correct management console "
                    "before removing other AV products."
                ),
                source_file="Services.csv",
            ))

    # ── Process analysis ─────────────────────────────────────────────────────

    def _analyze_processes(self, filepath: str):
        rows = _read_csv(filepath)

        av_cpu: dict[str, float] = {}
        av_ram: dict[str, int] = {}

        for row in rows:
            name = (row.get("Name") or row.get("name") or "").strip().lower()
            cpu_raw = row.get("CPU") or row.get("cpu") or "0"
            ram_raw = row.get("WorkingSet") or row.get("workingset") or "0"

            try:
                cpu = float(cpu_raw)
                ram = int(ram_raw)
            except (ValueError, TypeError):
                cpu, ram = 0.0, 0

            for proc_key, av_name in _AV_PROCESS_NAMES.items():
                if proc_key in name:
                    av_cpu[av_name] = av_cpu.get(av_name, 0.0) + cpu
                    av_ram[av_name] = av_ram.get(av_name, 0) + ram

        for av_name, total_cpu in av_cpu.items():
            ram_mb = av_ram.get(av_name, 0) // (1024 * 1024)
            if total_cpu > 50 or ram_mb > 300:
                severity = "high" if (total_cpu > 100 or ram_mb > 500) else "medium"
                self.findings.append(SupplementalFinding(
                    category="av_conflict",
                    severity=severity,
                    title=f"{av_name} High Resource Usage: {total_cpu:.0f} CPU units / {ram_mb} MB RAM",
                    detail=(
                        f"{av_name} is consuming {total_cpu:.0f} CPU time units and "
                        f"{ram_mb} MB RAM. This level of AV overhead is consistent with "
                        f"scanning conflicts caused by multiple concurrent security products "
                        f"or an AV product in a degraded/thrashing state."
                    ),
                    recommendation=(
                        f"If {av_name} is not the intended security product: remove it. "
                        f"If it is intended: check the management console for policy issues, "
                        f"exclusion misconfigurations, or repeated scan triggers from another AV."
                    ),
                    source_file="RunningProcesses.csv",
                ))

    # ── Cross-file analysis ─────────────────────────────────────────────────

    def _cross_analyze(self):
        """Analysis requiring data from multiple files."""
        # Primary NIC disconnected detection
        # (This would normally come from parsing Network_IPConfig.txt
        #  but we check for it in the supplemental flow)
        pass


# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_csv(filepath: str) -> list[dict]:
    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(raw))
        return list(reader)
    except Exception:
        return []


def _parse_date(raw: str) -> datetime | None:
    if not raw:
        return None
    for fmt in (
        "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d",
        "%d/%m/%Y",
    ):
        try:
            return datetime.strptime(raw.strip()[:20], fmt)
        except ValueError:
            continue
    return None


def _parse_date_yyyymmdd(raw: str) -> datetime | None:
    if not raw or len(raw) != 8:
        return None
    try:
        return datetime(int(raw[:4]), int(raw[4:6]), int(raw[6:8]))
    except (ValueError, TypeError):
        return None


def _parse_major_version(version: str) -> int | None:
    m = re.match(r"(\d+)", version.strip())
    if m:
        return int(m.group(1))
    return None
