"""
BeanFeasa — Supplemental Data Parsers.

Parses auxiliary data files that are not event logs but contain
diagnostic context needed for accurate analysis:

  - SystemInfo.txt → hostname, OS version, memory, boot time
  - Drivers.csv → installed driver versions for crash correlation
  - CBS.log → component store health (corruption detection)
  - DISM.log → image servicing health
  - DiskUsage.csv → volume free space
  - IPConfig.txt → network adapter configuration

Addresses items 11, 15, 16 from the evaluation report.
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SystemContext:
    """System context resolved from supplemental files."""
    hostname: str = ""
    os_version: str = ""
    os_build: str = ""
    total_memory_mb: int = 0
    available_memory_mb: int = 0
    memory_percent_used: float = 0.0
    boot_time: str = ""
    domain: str = ""
    logon_server: str = ""
    model: str = ""
    manufacturer: str = ""

    # From Drivers.csv
    drivers: dict = field(default_factory=dict)  # {driver_name: {version, date, ...}}

    # From CBS/DISM
    cbs_health: str = ""           # "healthy", "repairable", "corrupt"
    cbs_errors: list[str] = field(default_factory=list)
    dism_health: str = ""
    dism_errors: list[str] = field(default_factory=list)

    # From DiskUsage
    volumes: list[dict] = field(default_factory=list)  # [{drive, total, free, percent_free}]

    # From IPConfig
    ip_addresses: list[str] = field(default_factory=list)
    dhcp_enabled: bool = False
    dns_servers: list[str] = field(default_factory=list)


def parse_systeminfo(filepath: str) -> SystemContext:
    """
    Parse SystemInfo.txt to extract hostname, OS version, memory, etc.
    Addresses Item 15: "computer field should never be unknown."
    """
    ctx = SystemContext()

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return ctx

    patterns = {
        "hostname": r"(?:Host Name|Computer Name)[:\s]+(.+)",
        "os_version": r"(?:OS Name)[:\s]+(.+)",
        "os_build": r"(?:OS Version)[:\s]+(.+)",
        "domain": r"(?:Domain)[:\s]+(.+)",
        "logon_server": r"(?:Logon Server)[:\s]+(.+)",
        "boot_time": r"(?:System Boot Time|Original Install Date)[:\s]+(.+)",
        "model": r"(?:System Model)[:\s]+(.+)",
        "manufacturer": r"(?:System Manufacturer)[:\s]+(.+)",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            setattr(ctx, key, m.group(1).strip())

    # Memory
    m = re.search(r"Total Physical Memory[:\s]+([\d,]+)\s*MB", raw, re.IGNORECASE)
    if m:
        ctx.total_memory_mb = int(m.group(1).replace(",", ""))

    m = re.search(r"Available Physical Memory[:\s]+([\d,]+)\s*MB", raw, re.IGNORECASE)
    if m:
        ctx.available_memory_mb = int(m.group(1).replace(",", ""))

    if ctx.total_memory_mb > 0:
        used = ctx.total_memory_mb - ctx.available_memory_mb
        ctx.memory_percent_used = round((used / ctx.total_memory_mb) * 100, 1)

    return ctx


def parse_drivers_csv(filepath: str) -> dict[str, dict]:
    """
    Parse Drivers.csv to build a driver name → version/date lookup.
    Addresses Item 11: "correlate driver version with crash bucket."

    Returns {module_name_lower: {name, version, date, path}}.
    """
    import csv
    drivers = {}

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return drivers

    try:
        import io
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            # Common column names across different export tools
            name = (
                row.get("Module Name", "") or
                row.get("Name", "") or
                row.get("DriverName", "") or
                row.get("DeviceName", "")
            ).strip()

            version = (
                row.get("Version", "") or
                row.get("DriverVersion", "") or
                row.get("FileVersion", "")
            ).strip()

            date = (
                row.get("Date", "") or
                row.get("DriverDate", "") or
                row.get("Link Date", "")
            ).strip()

            path = (
                row.get("Path", "") or
                row.get("DriverPath", "") or
                row.get("Inf Name", "")
            ).strip()

            if name:
                key = name.lower().replace(".sys", "").replace(".dll", "")
                drivers[key] = {
                    "name": name,
                    "version": version,
                    "date": date,
                    "path": path,
                }
    except Exception:
        pass

    return drivers


def correlate_driver_with_crash(
    faulting_module: str,
    drivers: dict[str, dict],
) -> dict | None:
    """
    Look up a faulting module name in the driver inventory.
    Returns driver info dict or None.

    Usage:
        info = correlate_driver_with_crash("RtUsbA64", drivers)
        if info:
            print(f"Driver: {info['name']} version {info['version']}")
    """
    if not faulting_module:
        return None

    # Normalize: strip .sys, lowercase
    key = faulting_module.lower().replace(".sys", "").replace(".dll", "")

    # Direct match
    if key in drivers:
        return drivers[key]

    # Partial match
    for dkey, dinfo in drivers.items():
        if key in dkey or dkey in key:
            return dinfo

    return None


def parse_cbs_log(filepath: str) -> tuple[str, list[str]]:
    """
    Parse CBS.log for component store health indicators.
    Addresses Item 16: "check for component store corruption."

    Returns (health_status, error_lines).
    health_status: "healthy", "repairable", "corrupt", or "unknown"
    """
    errors = []
    health = "unknown"

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return health, ["Failed to read CBS.log"]

    # Check for corruption indicators
    corruption_indicators = [
        "cannot repair member file",
        "repair failed",
        "manifest is corrupt",
        "component store is not repairable",
        "store corruption",
        "hresult = 0x800f0831",
        "hresult = 0x800f081f",
        "hash mismatch",
    ]

    repairable_indicators = [
        "repair succeeded",
        "repairing component",
        "successfully repaired",
    ]

    healthy_indicators = [
        "no component store corruption detected",
        "the component store is in good health",
        "the operation completed successfully",
    ]

    raw_lower = raw.lower()

    for indicator in healthy_indicators:
        if indicator in raw_lower:
            health = "healthy"

    for indicator in repairable_indicators:
        if indicator in raw_lower:
            if health != "corrupt":
                health = "repairable"

    for indicator in corruption_indicators:
        if indicator in raw_lower:
            health = "corrupt"
            # Extract the specific lines
            for line in raw.splitlines():
                if indicator in line.lower():
                    errors.append(line.strip()[:200])

    if not errors and health == "unknown":
        health = "healthy"  # No corruption indicators found

    return health, errors


def parse_dism_log(filepath: str) -> tuple[str, list[str]]:
    """
    Parse DISM.log for image servicing health.
    Returns (health_status, error_lines).
    """
    errors = []
    health = "unknown"

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return health, ["Failed to read DISM.log"]

    raw_lower = raw.lower()

    error_patterns = [
        "error",
        "the source files could not be found",
        "failed to get",
        "repair operation not successful",
    ]

    success_patterns = [
        "the restore health operation completed successfully",
        "the operation completed successfully",
        "no component store corruption",
    ]

    for pattern in success_patterns:
        if pattern in raw_lower:
            health = "healthy"

    for pattern in error_patterns:
        if pattern in raw_lower:
            for line in raw.splitlines():
                if pattern in line.lower() and "info" not in line.lower()[:20]:
                    errors.append(line.strip()[:200])

    if errors:
        health = "errors_found"

    if health == "unknown":
        health = "healthy"

    return health, errors[:20]  # Cap at 20 error lines


def parse_ipconfig(filepath: str) -> dict:
    """
    Parse IPConfig.txt output for network context.
    Extracts hostname, IP addresses, DHCP status, DNS servers.
    """
    result = {
        "hostname": "",
        "ip_addresses": [],
        "dhcp_enabled": False,
        "dns_servers": [],
    }

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return result

    # Hostname
    m = re.search(r"Host Name[.\s:]+(\S+)", raw, re.IGNORECASE)
    if m:
        result["hostname"] = m.group(1).strip()

    # IPv4 addresses
    for m in re.finditer(r"IPv4 Address[.\s:]+(\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE):
        addr = m.group(1)
        if not addr.startswith("169.254"):  # Skip APIPA
            result["ip_addresses"].append(addr)

    # DHCP
    if re.search(r"DHCP Enabled[.\s:]+Yes", raw, re.IGNORECASE):
        result["dhcp_enabled"] = True

    # DNS servers
    for m in re.finditer(r"DNS Servers[.\s:]+(\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE):
        result["dns_servers"].append(m.group(1))

    return result


def resolve_hostname(directory: str) -> str:
    """
    Attempt to resolve the hostname from multiple sources in a
    log collection directory. Checks SystemInfo.txt, IPConfig.txt,
    and falls back to directory name heuristics.

    Addresses Item 15: "computer field should never be unknown."
    """
    # Try SystemInfo.txt
    for name in ("SystemInfo.txt", "systeminfo.txt", "Systeminfo.txt"):
        path = os.path.join(directory, name)
        if os.path.exists(path):
            ctx = parse_systeminfo(path)
            if ctx.hostname:
                return ctx.hostname

    # Try IPConfig
    for name in ("IPConfig.txt", "ipconfig.txt", "IPConfig_output.txt"):
        path = os.path.join(directory, name)
        if os.path.exists(path):
            result = parse_ipconfig(path)
            if result["hostname"]:
                return result["hostname"]

    # Try directory name as last resort (CollectLogs often names dirs after hostname)
    dirname = os.path.basename(directory.rstrip("/\\"))
    if dirname and dirname.upper().startswith(("USVIS-", "USTX-", "US")):
        return dirname

    return ""
