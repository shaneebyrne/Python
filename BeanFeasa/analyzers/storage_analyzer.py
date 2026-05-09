"""
BeanFeasa — Storage Analysis Engine.

Analyzes the output of Get-LargestFiles.ps1 to identify:
  - Files safe to delete (orphaned installers, old backups, temp files)
  - Files to review (large OST/PST, VM bundles, driver staging)
  - Space recovery potential by category
  - Environment-specific patterns (S1 log retention, MSI patch cache,
    dual-OST / archive OST, hiberfil.sys / pagefile.sys)

Usage:
    from parsers.storage_parser import parse_largest_files_csv
    from analyzers.storage_analyzer import StorageAnalyzer

    records, errors = parse_largest_files_csv("LargestFiles_20260429_151016.csv")
    analyzer = StorageAnalyzer()
    findings = analyzer.analyze(records)
    summary = analyzer.get_summary()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from parsers.storage_parser import StorageFileRecord


# ── Action / Priority constants ───────────────────────────────
ACTION_DELETE  = "DELETE"       # Safe to remove — no legitimate use
ACTION_REVIEW  = "REVIEW"       # Confirm with user before removing
ACTION_KEEP    = "KEEP"         # Required — do not remove
ACTION_PENDING = "PENDING"      # Requires a preparation step before removal

PRIORITY_CRITICAL = "1-CRITICAL"   # Blocking issue (e.g., disk full contributor)
PRIORITY_HIGH     = "2-HIGH"       # High-value target for space recovery
PRIORITY_MEDIUM   = "3-MEDIUM"     # Moderate space, worth reviewing
PRIORITY_LOW      = "4-LOW"        # Small files, informational only
PRIORITY_INFO     = "5-INFO"       # Informational — no action needed


@dataclass
class StorageFinding:
    """A single storage analysis finding."""
    priority: str
    action: str
    category: str
    size_gb: float
    size_mb: int
    file_name: str
    full_path: str
    directory: str
    last_modified: str
    reason: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "action": self.action,
            "category": self.category,
            "size_gb": self.size_gb,
            "size_mb": self.size_mb,
            "file_name": self.file_name,
            "full_path": self.full_path,
            "directory": self.directory,
            "last_modified": self.last_modified,
            "reason": self.reason,
            "recommendation": self.recommendation,
        }


@dataclass
class StorageSummary:
    total_files_scanned: int = 0
    total_size_gb: float = 0.0
    recoverable_gb: float = 0.0      # DELETE findings
    review_gb: float = 0.0           # REVIEW findings
    findings_by_category: dict = field(default_factory=dict)
    findings_by_action: dict = field(default_factory=dict)
    critical_paths: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


class StorageAnalyzer:
    """
    Categorizes and scores large file records, producing actionable findings.

    Category rules are applied in priority order — the first match wins
    for the primary categorization (though multiple findings can be emitted
    for the same file if it triggers multiple alert patterns).
    """

    def __init__(self):
        self.findings: list[StorageFinding] = []
        self._emitted_paths: set[str] = set()

    def analyze(self, records: list[StorageFileRecord]) -> list[StorageFinding]:
        """Analyze a list of StorageFileRecord objects and return findings."""
        self.findings = []
        self._emitted_paths = set()

        if not records:
            return []

        # Sort descending by size for priority ordering
        sorted_records = sorted(records, key=lambda r: r.size_bytes, reverse=True)

        for rec in sorted_records:
            self._classify(rec)

        # Sort output: priority ascending, then size descending
        self.findings.sort(key=lambda f: (f.priority, -f.size_gb))
        return self.findings

    def get_summary(self) -> StorageSummary:
        summary = StorageSummary()
        summary.total_files_scanned = len(self._emitted_paths)
        summary.total_size_gb = sum(f.size_gb for f in self.findings)

        by_action: dict[str, float] = {}
        by_cat: dict[str, float] = {}
        alerts: list[str] = []

        for f in self.findings:
            by_action[f.action] = by_action.get(f.action, 0.0) + f.size_gb
            by_cat[f.category] = by_cat.get(f.category, 0.0) + f.size_gb

        summary.recoverable_gb = round(by_action.get(ACTION_DELETE, 0.0), 2)
        summary.review_gb      = round(by_action.get(ACTION_REVIEW, 0.0), 2)
        summary.findings_by_action = {k: round(v, 2) for k, v in by_action.items()}
        summary.findings_by_category = {k: round(v, 2) for k, v in by_cat.items()}

        # Generate summary alerts
        if summary.recoverable_gb >= 10:
            alerts.append(
                f"HIGH PRIORITY: {summary.recoverable_gb:.1f} GB of files are safe "
                f"to delete immediately — run the DELETE actions first."
            )
        elif summary.recoverable_gb >= 2:
            alerts.append(
                f"{summary.recoverable_gb:.1f} GB recoverable via DELETE actions."
            )

        if summary.review_gb >= 20:
            alerts.append(
                f"{summary.review_gb:.1f} GB in REVIEW items — confirm with user "
                f"before removing (OST files, VM bundles, etc.)."
            )

        # S1 log alert
        s1_gb = by_cat.get("sentinelone_logs", 0.0)
        if s1_gb >= 1.0:
            alerts.append(
                f"SentinelOne logs consuming {s1_gb:.1f} GB. "
                f"Review log retention / rotation policy with MSP."
            )

        # Windows Installer cache
        inst_gb = by_cat.get("windows_installer_cache", 0.0)
        if inst_gb >= 2.0:
            alerts.append(
                f"Windows Installer patch cache at {inst_gb:.1f} GB. "
                f"Run 'DISM /Online /Cleanup-Image /StartComponentCleanup' to reclaim safely."
            )

        summary.alerts = alerts
        return summary

    # ── Classification logic ──────────────────────────────────

    def _classify(self, rec: StorageFileRecord):
        p = rec.path_lower
        ext = rec.extension
        name_lower = rec.file_name.lower()

        # ── OST / PST — Email data files ─────────────────────
        if ext in (".ost", ".pst"):
            if name_lower.endswith(".bak"):
                self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "email_backup",
                    "Outlook backup file (.bak). These are created by Outlook when "
                    "it repairs a data file and are no longer needed once the repair "
                    "completes. Safe to delete if Outlook is functioning normally.",
                    "Confirm Outlook is healthy, then delete this file to reclaim space.")
            elif ".bak" in name_lower:
                self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "email_backup",
                    "Outlook data file backup (.bak). Safe to remove.",
                    "Verify Outlook is operational, then delete.")
            else:
                # Multiple OST files for the same account suggest orphaned/stale
                self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "email_data",
                    "Outlook OST/PST data file. These are required for offline email "
                    "access. Before removing, confirm this account is still active and "
                    "whether the file is the primary mailbox or an archive/secondary.",
                    "If primary mailbox OST: run Compact Now (File > Account Settings > "
                    "Data Files > Settings > Compact Now) to shrink without deleting. "
                    "If unused secondary account: remove the account in Outlook to "
                    "allow Windows to clean up the OST.")
            return

        # ── System files — pagefile, hiberfil ────────────────
        if name_lower == "pagefile.sys":
            self._emit(rec, PRIORITY_INFO, ACTION_KEEP, "system_pagefile",
                "Windows virtual memory pagefile. Required for system stability — "
                "do not delete while Windows is running.",
                "If the pagefile is larger than expected, verify RAM is adequate for "
                "the workload. On 16 GB RAM systems, pagefile > 8 GB is unusually large.")
            return

        if name_lower == "hiberfil.sys":
            self._emit(rec, PRIORITY_MEDIUM, ACTION_PENDING, "system_hibernate",
                "Hibernation file. Required for hibernate / fast startup. Safe to "
                "reclaim if hibernation is not used (desktops, always-on systems).",
                "To reclaim: run 'powercfg /h off' as Administrator. "
                "This disables hibernation and deletes the file. "
                "Verify user does not use Hibernate before running.")
            return

        # ── SentinelOne logs ──────────────────────────────────
        if ("sentinel" in p or "sentinelone" in p) and ext == ".binlog":
            self._emit(rec, PRIORITY_HIGH, ACTION_REVIEW, "sentinelone_logs",
                "SentinelOne agent binary log. These are required for S1 diagnostics "
                "but can consume significant disk space on small drives. "
                "Each file is typically ~100 MB; 12+ files = 1.2 GB/day on USVIS-JQD1SQ3.",
                "Raise a ticket with your MSP/S1 admin to review the log retention "
                "and rotation policy. The binlog cap or rotation interval can be "
                "adjusted in the S1 management console without losing agent functionality.")
            return

        if "sentinel" in p and ext in (".log", ".gz", ".zip"):
            self._emit(rec, PRIORITY_LOW, ACTION_REVIEW, "sentinelone_logs",
                "SentinelOne agent log file.",
                "Review retention policy with MSP if total S1 log volume is high.")
            return

        # ── Windows Installer patch cache ─────────────────────
        if "\\windows\\installer\\" in p and ext in (".msp", ".msi"):
            self._emit(rec, PRIORITY_MEDIUM, ACTION_PENDING, "windows_installer_cache",
                "Windows Installer patch cache file (.msp/.msi). These accumulate over "
                "time and can reach 4-8 GB. They are required for repair/uninstall of "
                "the associated application — deleting manually can break uninstallation.",
                "Use DISM to reclaim safely: "
                "'DISM /Online /Cleanup-Image /StartComponentCleanup' — "
                "this removes superseded packages while preserving installer integrity. "
                "Do NOT delete .msp/.msi files manually.")
            return

        # ── VM / container bundles ────────────────────────────
        if ext in (".vhdx", ".vmdk", ".vhd") or "vm_bundle" in p or "claudevm" in p:
            self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "vm_bundle",
                "Virtual machine disk image or container bundle. May be in active use.",
                "Confirm the VM/container is still needed. If unused, the containing "
                "folder can be deleted. If active, consider moving to a larger volume.")
            return

        if "initrd" in name_lower or (ext == "" and "vm_bundle" in p):
            self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "vm_bundle",
                "VM bundle component file.",
                "Review parent VM bundle — delete entire bundle directory if unused.")
            return

        # ── Intel DSA / driver downloads (orphaned) ───────────
        if ("intel\\dsa\\downloads" in p or "intel\\dsa\\cache" in p) and ext == ".exe":
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "orphaned_installer",
                "Intel DSA download cache — installer executable that has already been "
                "applied. DSA does not automatically clean its download cache.",
                "Safe to delete. The update has already been applied. "
                "Intel DSA will re-download if the same update is needed again.")
            return

        # ── Orphaned installers in Temp ───────────────────────
        if "\\temp\\" in p and ext in (".msix", ".msixbundle", ".exe", ".msi", ".tmp"):
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "orphaned_temp",
                f"Orphaned file in %TEMP% or system Temp folder. "
                f"Extension '{ext}' suggests a staged installer or download "
                f"that was not cleaned up.",
                "Verify no active installation is in progress, then delete. "
                "It is safe to clear %TEMP% when the user is not actively installing software.")
            return

        # ── macOS / cross-platform packages (useless on Windows) ──
        if ext in (".pkg", ".dmg") and "mac" in name_lower.replace("_", "").lower():
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "wrong_platform",
                "macOS package or disk image — cannot execute on Windows. "
                "No business value on a Windows endpoint.",
                "Delete immediately.")
            return

        if ext == ".pkg" and ("osx" in name_lower or "mac" in name_lower or "apple" in name_lower):
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "wrong_platform",
                "macOS package — not executable on Windows.",
                "Delete immediately.")
            return

        # ── Media files in non-system paths ──────────────────
        if ext in (".mov", ".mp4", ".avi", ".mkv", ".mpg", ".mpeg", ".wmv"):
            if not any(sys in p for sys in ("\\windows\\", "\\program files\\")):
                self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "media_file",
                    "Video file in a user or non-system path. Personal media files "
                    "have no business function on a work endpoint.",
                    "Confirm with user — if personal media with no business purpose, "
                    "delete or move to personal storage.")
            return

        # ── Outlook backup files (generic) ────────────────────
        if ext == ".bak" and "outlook" in p:
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "email_backup",
                "Outlook data file backup. Safe to remove once Outlook is confirmed healthy.",
                "Verify Outlook is functioning, then delete.")
            return

        # ── Dell TechHub / driver telemetry backups ───────────
        if ("\\dell\\dtp\\" in p or "\\dell\\telemetry\\" in p) and ext in (".bak", ".db", ".old"):
            self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "vendor_backup",
                "Dell telemetry or TechHub database backup file. "
                "Old backup copies accumulate and are not needed once superseded.",
                "Safe to delete. Dell DTP will recreate its database if needed.")
            return

        # ── Old Dell driver staging ───────────────────────────
        if ("\\drivers\\video\\" in p or "\\programdata\\dell\\drivers\\" in p) and ext in (".exe", ".inf", ".cab"):
            self._emit(rec, PRIORITY_MEDIUM, ACTION_DELETE, "old_driver_staging",
                "Old Dell driver staging package. These are left behind after driver "
                "updates and are superseded by the current DriverStore.",
                "Safe to delete — the DriverStore contains the current version.")
            return

        # ── Google Updater CRX cache ──────────────────────────
        if "googleupdater\\crx_cache" in p:
            self._emit(rec, PRIORITY_MEDIUM, ACTION_DELETE, "app_cache",
                "Google Updater CRX extension cache. Populated by Google software "
                "updates and not automatically cleaned.",
                "Safe to delete. Google Updater will repopulate as needed.")
            return

        # ── Adobe installer cache ─────────────────────────────
        if "adobe" in p and ext == ".cab" and "setup" in p:
            self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "orphaned_installer",
                "Adobe installer cabinet file — likely a staged update package.",
                "If the Adobe product is already at the current version, "
                "this can be deleted. Check Adobe app version before removing.")
            return

        # ── Intel ME / legacy installer cache ────────────────
        if "intel package cache" in p and ext == ".exe":
            self._emit(rec, PRIORITY_MEDIUM, ACTION_REVIEW, "orphaned_installer",
                "Intel package cache installer. May be required for repair/uninstall "
                "of Intel management software.",
                "Verify current Intel ME/AMT version. If software is up to date, "
                "this cached installer may be removable. Test uninstall/repair first.")
            return

        # ── Old Teams installs in non-primary profiles ────────
        if "teams" in p and "squirrel" in p and "\\appdata\\local\\" in p:
            # Check if in a non-active profile
            if "\\tempadmin\\" in p or "\\administrator\\" in p or "\\defaultuser" in p:
                self._emit(rec, PRIORITY_HIGH, ACTION_DELETE, "orphaned_app",
                    "Classic Microsoft Teams (Squirrel-based) installation in a "
                    "non-daily-use profile (admin/TempoAdmin account). Current Teams "
                    "uses MSIX packaging and does not use this path.",
                    "Safe to delete the entire Teams directory under this profile's AppData.")
                return

        # ── DriverStore staging ───────────────────────────────
        if "\\driverstore\\filerepository\\" in p and ext in (".dll", ".sys", ".inf"):
            # Only flag very large ones
            if rec.size_gb >= 0.2:
                self._emit(rec, PRIORITY_LOW, ACTION_REVIEW, "driver_store",
                    "Large file in Windows DriverStore. The DriverStore manages driver "
                    "versions and should not be modified manually.",
                    "Use 'pnputil /delete-driver <inf> /uninstall' to safely remove "
                    "old driver packages. Use 'DISM /Online /Cleanup-Image /StartComponentCleanup' "
                    "to let Windows identify removable driver packages.")
                return

        # ── Any remaining large file > 500 MB — flag for review ──
        if rec.size_gb >= 0.5:
            self._emit(rec, PRIORITY_LOW, ACTION_REVIEW, "large_file_uncategorised",
                f"Large file ({rec.size_gb:.2f} GB) not matching any known cleanup category. "
                f"Extension: {rec.extension or 'none'}.",
                "Review manually — determine if this file is actively used or can be archived/removed.")

    def _emit(
        self,
        rec: StorageFileRecord,
        priority: str,
        action: str,
        category: str,
        reason: str,
        recommendation: str,
    ):
        """Add a finding for a file record."""
        self._emitted_paths.add(rec.full_path)
        self.findings.append(StorageFinding(
            priority=priority,
            action=action,
            category=category,
            size_gb=rec.size_gb,
            size_mb=rec.size_mb,
            file_name=rec.file_name,
            full_path=rec.full_path,
            directory=rec.directory,
            last_modified=rec.last_modified,
            reason=reason,
            recommendation=recommendation,
        ))
