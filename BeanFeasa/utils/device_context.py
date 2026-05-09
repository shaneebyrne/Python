"""
BeanFeasa — Device Context.

Auto-detects device profile from SystemInfo.txt and other sources.
Provides suppression flags that disable inappropriate rules for
the device type (e.g., suppress AD/Kerberos on WORKGROUP machines).

Addresses: "Missing Device Context — Environment Not Considered"
from the Sidekick evaluation (~150 false positives).
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class DeviceProfile:
    """Detected device context used to suppress inappropriate rules."""
    hostname: str = ""
    domain: str = ""
    is_workgroup: bool = False
    is_domain_joined: bool = False
    is_teams_room: bool = False
    is_vbs_enabled: bool = False
    is_hvci_enabled: bool = False
    is_wdac_enforced: bool = False
    manufacturer: str = ""
    model: str = ""
    os_name: str = ""
    is_iot: bool = False

    # Suppression flags derived from profile
    suppress_ad_kerberos: bool = False      # No AD rules on WORKGROUP
    suppress_hyperv_errors: bool = False    # VBS Hyper-V events are normal
    suppress_wifi_failures: bool = False    # Wired-only device
    suppress_oem_mismatch: bool = False     # Wrong OEM rules

    # Auto-detected OEM for rule targeting
    oem: str = ""  # "dell", "hp", "lenovo", "yealink", etc.

    def summary(self) -> str:
        flags = []
        if self.is_workgroup:
            flags.append("WORKGROUP")
        if self.is_domain_joined:
            flags.append("DOMAIN")
        if self.is_teams_room:
            flags.append("TEAMS_ROOM")
        if self.is_vbs_enabled:
            flags.append("VBS")
        if self.is_wdac_enforced:
            flags.append("WDAC")
        if self.oem:
            flags.append(f"OEM:{self.oem.upper()}")
        return f"{self.hostname} [{', '.join(flags)}]"


# Rule IDs that should be suppressed per context
WORKGROUP_SUPPRESS = {
    "net-krb-002",    # Kerberos errors — no Kerberos on WORKGROUP
    "net-krb-001",
    "net-ldap-001",   # LDAP — no LDAP on WORKGROUP
    "ep-ad-001",      # AD replication — no AD relationship
    "net-smb-001",    # SMB share errors (often AD-related context)
    "perf-gpo-001",   # Group Policy — no GPO on WORKGROUP
    "perf-gpo-002",
}

VBS_SUPPRESS = {
    "ep-vm-001",      # Hyper-V "errors" are normal VBS capability enumeration
}

TEAMS_ROOM_SUPPRESS = {
    "net-wifi-001",   # WiFi adapter events — wired-only appliance
    "net-wifi-002",
}


def detect_profile(directory: str) -> DeviceProfile:
    """
    Auto-detect device profile from SystemInfo.txt and other files
    in a log collection directory.

    Returns a DeviceProfile with appropriate suppression flags set.
    """
    profile = DeviceProfile()

    # Try SystemInfo.txt
    for name in ("SystemInfo.txt", "systeminfo.txt", "Systeminfo.txt"):
        path = os.path.join(directory, name)
        if os.path.exists(path):
            _parse_systeminfo(path, profile)
            break

    # Try IPConfig for wired-only detection
    for name in ("Network_IPConfig.txt", "IPConfig.txt", "ipconfig.txt"):
        path = os.path.join(directory, name)
        if os.path.exists(path):
            _parse_ipconfig_for_wifi(path, profile)
            break

    # Derive suppression flags
    if profile.is_workgroup:
        profile.suppress_ad_kerberos = True

    if profile.is_vbs_enabled:
        profile.suppress_hyperv_errors = True

    if profile.is_teams_room:
        profile.suppress_wifi_failures = True

    return profile


def _parse_systeminfo(filepath: str, profile: DeviceProfile):
    """Parse SystemInfo.txt to populate the device profile."""
    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return

    raw_lower = raw.lower()

    # Hostname
    m = re.search(r"Host Name[:\s]+(\S+)", raw, re.IGNORECASE)
    if m:
        profile.hostname = m.group(1).strip()

    # Domain
    m = re.search(r"^Domain[:\s]+(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m:
        profile.domain = m.group(1).strip()
        if profile.domain.upper() == "WORKGROUP":
            profile.is_workgroup = True
        else:
            profile.is_domain_joined = True

    # Manufacturer / Model
    m = re.search(r"System Manufacturer[:\s]+(.+)", raw, re.IGNORECASE)
    if m:
        profile.manufacturer = m.group(1).strip()

    m = re.search(r"System Model[:\s]+(.+)", raw, re.IGNORECASE)
    if m:
        profile.model = m.group(1).strip()

    # OEM detection
    mfg_lower = profile.manufacturer.lower()
    model_lower = profile.model.lower()
    if "dell" in mfg_lower:
        profile.oem = "dell"
    elif "hp" in mfg_lower or "hewlett" in mfg_lower:
        profile.oem = "hp"
    elif "lenovo" in mfg_lower:
        profile.oem = "lenovo"
    elif "yealink" in mfg_lower:
        profile.oem = "yealink"
    elif "microsoft" in mfg_lower and "surface" in model_lower:
        profile.oem = "microsoft"

    # OS
    m = re.search(r"OS Name[:\s]+(.+)", raw, re.IGNORECASE)
    if m:
        profile.os_name = m.group(1).strip()
        if "iot" in profile.os_name.lower():
            profile.is_iot = True

    # Teams Room detection
    if any(x in model_lower for x in ("mcore", "mtouch", "teams room", "room system")):
        profile.is_teams_room = True
    if "skype room" in raw_lower or "teams room" in raw_lower or "mcore" in model_lower:
        profile.is_teams_room = True

    # VBS / HVCI
    if "virtualization-based security" in raw_lower:
        m = re.search(r"virtualization-based security[:\s]+Status[:\s]+(\S+)", raw, re.IGNORECASE)
        if m and m.group(1).lower() == "running":
            profile.is_vbs_enabled = True

    if "hypervisor enforced code integrity" in raw_lower:
        profile.is_hvci_enabled = True

    # WDAC / App Control
    if "app control for business" in raw_lower:
        m = re.search(r"App Control for Business policy[:\s]+(\S+)", raw, re.IGNORECASE)
        if m and m.group(1).lower() == "enforced":
            profile.is_wdac_enforced = True


def _parse_ipconfig_for_wifi(filepath: str, profile: DeviceProfile):
    """Check if WiFi is disconnected (wired-only device)."""
    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return

    # If WiFi adapter exists but is disconnected, and Ethernet is connected
    wifi_disconnected = ("wi-fi" in raw.lower() or "wireless" in raw.lower()) and \
                        "media disconnected" in raw.lower()
    ethernet_connected = "ethernet" in raw.lower() and "ipv4 address" in raw.lower()

    if wifi_disconnected and ethernet_connected:
        profile.suppress_wifi_failures = True


def get_suppressed_rules(profile: DeviceProfile) -> set[str]:
    """
    Return the set of rule IDs that should be suppressed based on
    the device profile.
    """
    suppressed = set()

    if profile.suppress_ad_kerberos:
        suppressed.update(WORKGROUP_SUPPRESS)

    if profile.suppress_hyperv_errors:
        suppressed.update(VBS_SUPPRESS)

    if profile.suppress_wifi_failures:
        suppressed.update(TEAMS_ROOM_SUPPRESS)

    # OEM mismatch suppression
    if profile.oem:
        oem_rules = {
            "dell": {"fw-oem-002", "fw-oem-003"},     # Suppress HP/Lenovo on Dell
            "hp": {"fw-oem-001", "fw-oem-003"},        # Suppress Dell/Lenovo on HP
            "lenovo": {"fw-oem-001", "fw-oem-002"},    # Suppress Dell/HP on Lenovo
            "yealink": {"fw-oem-001", "fw-oem-002", "fw-oem-003"},  # Suppress all OEM on Yealink
        }
        suppressed.update(oem_rules.get(profile.oem, set()))

    return suppressed
