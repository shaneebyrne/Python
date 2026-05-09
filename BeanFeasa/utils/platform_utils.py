"""
BeanFeasa — Cross-platform utility helpers.

Handles OS detection, native file dialogs, and path normalization.
"""

import os
import sys
import platform
from pathlib import Path

try:
    from tkinter import filedialog
except ImportError:
    filedialog = None  # CLI mode — no GUI needed


def get_platform() -> str:
    """Return normalized platform name: 'windows', 'macos', or 'linux'."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    return system  # 'windows' or 'linux'


def get_default_log_paths() -> list[str]:
    """Return a list of common log directories for the current OS."""
    plat = get_platform()
    paths = []

    if plat == "windows":
        windir = os.environ.get("SYSTEMROOT", r"C:\Windows")
        paths = [
            os.path.join(windir, "System32", "winevt", "Logs"),
            os.path.join(windir, "System32", "LogFiles"),
            os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Microsoft", "Windows", "WER"),
        ]
    elif plat == "macos":
        paths = [
            "/var/log",
            "/Library/Logs",
            os.path.expanduser("~/Library/Logs"),
            "/private/var/log",
        ]
    else:  # linux
        paths = [
            "/var/log",
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/journal",
            os.path.expanduser("~/.local/share/systemd"),
        ]

    return [p for p in paths if os.path.exists(p)]


# ── File dialog wrappers (all use native OS dialogs via tkinter) ──

LOG_FILE_TYPES = [
    ("All Supported", "*.evtx *.dmp *.csv *.json *.jsonl *.log *.txt *.xml *.syslog"),
    ("Windows Event Log", "*.evtx"),
    ("Crash Dumps", "*.dmp"),
    ("CSV Files", "*.csv"),
    ("JSON / JSONL", "*.json *.jsonl"),
    ("XML Files", "*.xml"),
    ("Text / Syslog", "*.log *.txt *.syslog"),
    ("All Files", "*.*"),
]


def select_log_files(parent=None) -> list[str]:
    """Open a native multi-select file dialog for log files."""
    files = filedialog.askopenfilenames(
        parent=parent,
        title="Select Log Files to Analyze",
        filetypes=LOG_FILE_TYPES,
    )
    return list(files) if files else []


def select_log_directory(parent=None) -> str:
    """Open a native folder selection dialog."""
    directory = filedialog.askdirectory(
        parent=parent,
        title="Select Log Directory",
        mustexist=True,
    )
    return directory if directory else ""


def select_output_file(parent=None, default_name="beanfeasa_results.csv") -> str:
    """Open a native 'Save As' dialog for the CSV output."""
    filepath = filedialog.asksaveasfilename(
        parent=parent,
        title="Save Analysis Results",
        defaultextension=".csv",
        initialfile=default_name,
        filetypes=[
            ("CSV Files", "*.csv"),
            ("All Files", "*.*"),
        ],
    )
    return filepath if filepath else ""


def select_rules_directory(parent=None) -> str:
    """Open a native folder selection dialog for custom rules."""
    directory = filedialog.askdirectory(
        parent=parent,
        title="Select Rules Directory",
        mustexist=True,
    )
    return directory if directory else ""


def discover_log_files(directory: str, recursive: bool = True) -> list[str]:
    """Walk a directory and return all supported log file paths.

    Always searches Minidump/ subdirectories for .dmp files,
    even in non-recursive mode, since crash dumps are commonly
    stored in a Minidump subfolder within log collections.
    """
    supported_extensions = {
        ".evtx", ".dmp", ".csv", ".json", ".jsonl", ".log", ".txt", ".xml", ".syslog"
    }
    results = []
    root_path = Path(directory)

    if recursive:
        for fpath in root_path.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in supported_extensions:
                results.append(str(fpath))
    else:
        for fpath in root_path.iterdir():
            if fpath.is_file() and fpath.suffix.lower() in supported_extensions:
                results.append(str(fpath))

        # Always check Minidump/ subdirectories for .dmp files
        for subdir_name in ("Minidump", "minidump", "MiniDump", "MEMORY.DMP"):
            sub = root_path / subdir_name
            if sub.is_dir():
                for fpath in sub.rglob("*.dmp"):
                    if fpath.is_file():
                        results.append(str(fpath))
            # Also check if it's a file (e.g., MEMORY.DMP)
            if sub.is_file() and sub.suffix.lower() == ".dmp":
                results.append(str(sub))

    return sorted(set(results))


# ── File classification: event logs vs inventory/config data ──
# Inventory files should NOT be run through detection rules.
# They are used for context enrichment only.

INVENTORY_FILE_PATTERNS = {
    # Exact filename matches (case-insensitive)
    "drivers.csv", "services.csv", "runningprocesses.csv",
    "installedapps.csv", "scheduledtasks.csv", "prefetchlist.txt",
    "systeminfo.txt", "diskusage.csv", "hotfixes.csv",
    "network_adapters.csv", "network_connections.txt",
    "network_ipconfig.txt", "ipconfig.txt",
    "network_routes.txt", "firewall_rules.csv",
    "startupitems.csv", "environmentvariables.txt",
    "shares.csv", "printers.csv", "usb_devices.csv",
    "bitlocker_status.txt", "gpresult.txt",
    # Hardware inventory files
    "hardware_cpu.txt", "hardware_disks.txt", "hardware_memory.txt",
    "hardware_gpu.txt", "hardware_bios.txt", "hardware_motherboard.txt",
}

SYSTEM_LOG_PATTERNS = {
    # These are structured text logs needing dedicated parsers,
    # NOT keyword-based rule matching
    "cbs.log", "dism.log", "setupact.log", "setuperr.log",
    "windowsupdate.log",
}


def is_event_log(filepath: str) -> bool:
    """
    Classify whether a file is an event log (suitable for rule detection)
    or an inventory/config file (context only, NOT for detection rules).

    Event logs contain timestamped events with sources and IDs.
    Inventory files are static snapshots of system configuration.

    This classification prevents thousands of false positives from
    feeding driver inventories, service lists, and process lists
    through the keyword-based detection engine.
    """
    fname = Path(filepath).name.lower()

    # .evtx and .dmp are always event data
    if fname.endswith((".evtx", ".dmp")):
        return True

    # Check against known inventory filenames
    if fname in INVENTORY_FILE_PATTERNS:
        return False

    # Check against system logs needing dedicated parsers
    if fname in SYSTEM_LOG_PATTERNS:
        return False

    # Files with "EventLog" in the name are event logs
    if "eventlog" in fname:
        return True

    # Files with "reliability" in the name are event-like
    if "reliability" in fname:
        return True

    # JSON/JSONL/XML files are typically structured event data
    if fname.endswith((".json", ".jsonl", ".xml")):
        return True

    # Syslog files are event data
    if fname.endswith(".syslog"):
        return True

    # .log files: check name patterns
    # CBS.log, DISM.log etc. are already excluded above
    if fname.endswith(".log"):
        return True

    # .csv files not in the inventory list are assumed to be event exports
    if fname.endswith((".csv", ".tsv")):
        return True

    # .txt files not in the inventory list: assume event data
    if fname.endswith(".txt"):
        return True

    return True  # Default: treat as event log


def format_file_size(size_bytes: int) -> str:
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def get_file_info(filepath: str) -> dict:
    """Return basic metadata about a file."""
    p = Path(filepath)
    stat = p.stat()
    return {
        "name": p.name,
        "path": str(p.resolve()),
        "extension": p.suffix.lower(),
        "size": stat.st_size,
        "size_human": format_file_size(stat.st_size),
    }
