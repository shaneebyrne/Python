"""
BeanFeasa — Minidump (.dmp) Parser.

Parses Windows minidump files to extract crash forensic data:
  - Exception code and address
  - Faulting module (mapped from exception address → module list)
  - Faulting module version info
  - BugCheck code (from exception code for kernel crashes)
  - All loaded modules with versions (driver inventory)
  - System info (OS version, processor architecture)
  - Thread ID of the crashing thread

This gives BeanFeasa the ability to analyze crash dumps directly
instead of relying solely on WER Event 1001 message parsing.

Requires: pip install minidump
"""

import os
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from parsers.base import BaseParser, ParsedEvent


# ── BugCheck code lookup table ──
BUGCHECK_NAMES = {
    0x0000000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x0000001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x00000024: "NTFS_FILE_SYSTEM",
    0x0000003B: "SYSTEM_SERVICE_EXCEPTION",
    0x00000050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x0000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x0000007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x0000009F: "DRIVER_POWER_STATE_FAILURE",
    0x000000BE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0x000000C2: "BAD_POOL_CALLER",
    0x000000C4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x000000C5: "DRIVER_CORRUPTED_EXPOOL",
    0x000000D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x000000D5: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
    0x000000EF: "CRITICAL_PROCESS_DIED",
    0x000000F4: "CRITICAL_OBJECT_TERMINATION",
    0x00000116: "VIDEO_TDR_FAILURE",
    0x00000119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
    0x00000124: "WHEA_UNCORRECTABLE_ERROR",
    0x00000133: "DPC_WATCHDOG_VIOLATION",
    0x00000139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x0000013A: "KERNEL_MODE_HEAP_CORRUPTION",
    0x00000154: "UNEXPECTED_STORE_EXCEPTION",
    0x000001CA: "SYNTHETIC_WATCHDOG_TIMEOUT",
}

# ── Windows NT status codes ──
NTSTATUS_NAMES = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000006: "STATUS_IN_PAGE_ERROR",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000025: "STATUS_NONCONTINUABLE_EXCEPTION",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000096: "STATUS_PRIVILEGED_INSTRUCTION",
    0x80000003: "STATUS_BREAKPOINT",
}


@dataclass
class DumpAnalysis:
    """Complete analysis result from a minidump file."""
    filepath: str = ""
    filename: str = ""
    timestamp: str = ""

    # Exception info
    exception_code: int = 0
    exception_code_hex: str = ""
    exception_code_name: str = ""
    exception_address: int = 0
    exception_address_hex: str = ""
    crashing_thread_id: int = 0

    # Faulting module (resolved from exception address)
    faulting_module: str = ""
    faulting_module_path: str = ""
    faulting_module_version: str = ""
    faulting_module_base: str = ""
    fault_offset: str = ""

    # BugCheck info (for kernel-mode dumps)
    bugcheck_code: int = 0
    bugcheck_code_hex: str = ""
    bugcheck_code_name: str = ""
    is_kernel_crash: bool = False

    # System info
    os_version: str = ""
    processor_arch: str = ""
    processor_count: int = 0

    # Loaded modules
    loaded_modules: list[dict] = field(default_factory=list)
    module_count: int = 0

    # Raw text summary
    summary: str = ""

    def to_events(self) -> list[ParsedEvent]:
        """Convert the dump analysis into ParsedEvent objects for the pipeline."""
        events = []

        # Main crash event
        module_info = f" in {self.faulting_module}" if self.faulting_module else ""
        version_info = f" (v{self.faulting_module_version})" if self.faulting_module_version else ""
        bugcheck_info = f" BugCheck {self.bugcheck_code_hex} ({self.bugcheck_code_name})" if self.bugcheck_code_name else ""

        events.append(ParsedEvent(
            timestamp=self.timestamp,
            source="Minidump Analysis",
            event_id="DMP",
            level="Critical",
            channel="Crash Dump",
            computer="",
            message=(
                f"BSOD{bugcheck_info}: "
                f"Exception {self.exception_code_hex} ({self.exception_code_name}) "
                f"at {self.exception_address_hex}{module_info}{version_info}. "
                f"Thread: {self.crashing_thread_id}. "
                f"File: {self.filename}"
            ),
            raw_data=self.summary[:2000],
            metadata={
                "faulting_module": self.faulting_module,
                "faulting_module_version": self.faulting_module_version,
                "exception_code": self.exception_code_hex,
                "bugcheck_code": self.bugcheck_code_hex,
                "bugcheck_name": self.bugcheck_code_name,
                "dump_file": self.filepath,
            },
        ))

        # Faulting module detail event
        if self.faulting_module:
            events.append(ParsedEvent(
                timestamp=self.timestamp,
                source="Minidump Analysis",
                event_id="DMP-MOD",
                level="Critical",
                channel="Crash Dump",
                message=(
                    f"Faulting module: {self.faulting_module_path or self.faulting_module} "
                    f"Version: {self.faulting_module_version or 'unknown'} "
                    f"Base: {self.faulting_module_base} "
                    f"Offset: {self.fault_offset}"
                ),
            ))

        return events


class DmpParser(BaseParser):
    """Parse Windows minidump (.dmp) files.

    Handles TWO formats:
      1. Kernel crash dumps (BSOD): start with 'PAGE' / 'PAGEDUMP'
         → Binary extraction of BugCheck code and parameters
      2. User-mode process dumps: start with 'MDMP'
         → Full analysis via the `minidump` Python package
    """

    SUPPORTED_EXTENSIONS = {".dmp"}
    PARSER_NAME = "minidump"

    def parse(self) -> list[ParsedEvent]:
        """Parse a minidump file and return events."""
        # Try kernel dump first (most common for BSOD .dmp files)
        analysis = analyze_kernel_dump(self.filepath)
        if analysis is not None:
            return analysis.to_events()

        # Fall back to user-mode dump
        analysis = analyze_usermode_dump(self.filepath)
        if analysis is not None:
            return analysis.to_events()

        return []


def _detect_dump_type(filepath: str) -> str:
    """Detect whether a .dmp file is a kernel dump or user-mode dump.

    Returns: 'kernel64', 'kernel32', 'usermode', or 'unknown'.
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
    except Exception:
        return "unknown"

    if len(header) < 4:
        return "unknown"

    sig = header[:4]
    if sig == b"MDMP":
        return "usermode"
    elif sig == b"PAGE":
        # Check ValidDump field at offset 4
        valid = header[4:8]
        if valid == b"DU64":
            return "kernel64"
        elif valid == b"DUMP":
            return "kernel32"
        else:
            return "kernel64"  # Assume 64-bit if PAGE but unknown sub-sig
    elif sig == b"PAGE":
        return "kernel64"

    return "unknown"


def analyze_kernel_dump(filepath: str) -> DumpAnalysis | None:
    """
    Parse a Windows kernel crash dump (BSOD minidump).

    These files start with 'PAGE' + 'DU64' (64-bit) or 'PAGE' + 'DUMP' (32-bit).
    Extracts BugCheck code and parameters from known header offsets.

    DUMP_HEADER64 layout (x64, Windows 10/11):
      0x000: Signature       (ULONG)  'PAGE'
      0x004: ValidDump       (ULONG)  'DU64'
      0x008: MajorVersion    (ULONG)
      0x00C: MinorVersion    (ULONG)
      0x030: MachineImageType(ULONG)
      0x034: NumberProcessors(ULONG)
      0x038: BugCheckCode    (ULONG)
      0x040: BugCheckParam1  (ULONG64)
      0x048: BugCheckParam2  (ULONG64)
      0x050: BugCheckParam3  (ULONG64)
      0x058: BugCheckParam4  (ULONG64)
    """
    import struct

    dump_type = _detect_dump_type(filepath)
    if dump_type not in ("kernel64", "kernel32"):
        return None

    result = DumpAnalysis()
    result.filepath = filepath
    result.filename = Path(filepath).name
    result.is_kernel_crash = True

    try:
        with open(filepath, "rb") as f:
            header = f.read(0x70)  # Read enough for all header fields
    except Exception:
        return None

    if len(header) < 0x60:
        return None

    try:
        mtime = os.path.getmtime(filepath)
        result.timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except Exception:
        result.timestamp = ""

    # Also try to extract timestamp from filename (e.g., 022226-17890-01.dmp)
    fname = Path(filepath).stem
    parts = fname.split("-")
    if len(parts) >= 2 and len(parts[0]) == 6 and parts[0].isdigit():
        try:
            mm = int(parts[0][:2])
            dd = int(parts[0][2:4])
            yy = int(parts[0][4:6])
            year = 2000 + yy
            result.timestamp = f"{year:04d}-{mm:02d}-{dd:02d}T00:00:00+00:00"
        except (ValueError, IndexError):
            pass

    if dump_type == "kernel64":
        # 64-bit kernel dump
        try:
            major_ver = struct.unpack_from("<I", header, 0x08)[0]
            minor_ver = struct.unpack_from("<I", header, 0x0C)[0]
            result.os_version = f"{major_ver}.{minor_ver}"

            num_procs = struct.unpack_from("<I", header, 0x34)[0]
            result.processor_count = num_procs

            bugcheck = struct.unpack_from("<I", header, 0x38)[0]
            result.bugcheck_code = bugcheck
            result.bugcheck_code_hex = f"0x{bugcheck:08X}"
            result.bugcheck_code_name = BUGCHECK_NAMES.get(bugcheck, f"UNKNOWN_0x{bugcheck:X}")

            # BugCheck parameters at 0x40 (4 x QWORD)
            p1 = struct.unpack_from("<Q", header, 0x40)[0]
            p2 = struct.unpack_from("<Q", header, 0x48)[0]
            p3 = struct.unpack_from("<Q", header, 0x50)[0]
            p4 = struct.unpack_from("<Q", header, 0x58)[0]

            result.exception_code = bugcheck
            result.exception_code_hex = f"0x{bugcheck:08X}"
            result.exception_code_name = result.bugcheck_code_name

            # For VIDEO_TDR_FAILURE (0x116), P2 points into the faulting driver
            # For DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1), P4 points into faulting driver
            result.exception_address = p2 if bugcheck == 0x116 else p4
            result.exception_address_hex = f"0x{result.exception_address:016X}"

        except (struct.error, IndexError):
            pass

    elif dump_type == "kernel32":
        # 32-bit kernel dump
        try:
            bugcheck = struct.unpack_from("<I", header, 0x38)[0]
            result.bugcheck_code = bugcheck
            result.bugcheck_code_hex = f"0x{bugcheck:08X}"
            result.bugcheck_code_name = BUGCHECK_NAMES.get(bugcheck, f"UNKNOWN_0x{bugcheck:X}")

            p1 = struct.unpack_from("<I", header, 0x3C)[0]
            p2 = struct.unpack_from("<I", header, 0x40)[0]
            p3 = struct.unpack_from("<I", header, 0x44)[0]
            p4 = struct.unpack_from("<I", header, 0x48)[0]

            result.exception_code = bugcheck
            result.exception_code_hex = f"0x{bugcheck:08X}"
            result.exception_code_name = result.bugcheck_code_name

        except (struct.error, IndexError):
            pass

    # ── Module identification via binary scan ───────────────────────────────
    # KASLR randomises kernel base addresses each boot so P4 is different
    # every crash, but the OFFSET WITHIN the driver is fixed (low 12 bits).
    # Strategy:
    #  1. Scan dump binary for Unicode .sys filenames (known Sophos, NVIDIA etc.)
    #  2. Scan for (base_addr, image_size) QWORD pairs bracketing P4 → module size
    #  3. Match image size against a known-driver-size table
    # This approach identified sntp.sys as the RICHLT crash driver.

    if result.exception_address and result.exception_address > 0xFFFF000000000000:
        # Only valid kernel-space addresses (Windows x64 kernel: fffff800_00000000+)
        _scan_for_loaded_modules(result, filepath)

    # ── Build P1-P4 into summary ─────────────────────────────────────────────
    lines = [
        f"Kernel Crash Dump: {result.filename}",
        f"Timestamp: {result.timestamp}",
        f"BugCheck: {result.bugcheck_code_hex} ({result.bugcheck_code_name})",
        f"OS Version: {result.os_version}",
        f"Processors: {result.processor_count}",
    ]
    # Store P1-P4 in metadata (for correlation engine and report)
    try:
        with open(filepath, "rb") as _f:
            _hdr = _f.read(0x70)
        if len(_hdr) >= 0x60 and dump_type == "kernel64":
            _p1 = struct.unpack_from("<Q", _hdr, 0x40)[0]
            _p2 = struct.unpack_from("<Q", _hdr, 0x48)[0]
            _p3 = struct.unpack_from("<Q", _hdr, 0x50)[0]
            _p4 = struct.unpack_from("<Q", _hdr, 0x58)[0]
            lines += [
                f"P1: 0x{_p1:016X}",
                f"P2 (IRQL): 0x{_p2:X}",
                f"P3 (access): 0x{_p3:X}  (1=write, 0=read)",
                f"P4 (faulting instr): 0x{_p4:016X}",
                f"P4 offset (fixed across KASLR): +0x{_p4 & 0xFFFFF:X}",
            ]
            if result.faulting_module:
                lines.append(f"Faulting module (resolved): {result.faulting_module}")
    except Exception:
        pass

    result.summary = "\n".join(lines)
    return result


# ── Known driver image sizes for module identification ──────────────────────
_KNOWN_DRIVER_SIZES = {
    # tcpip.sys — multiple build variants (size varies ±5% by patch level)
    0x32d000: ("tcpip.sys", "Windows TCP/IP stack"),
    0x330000: ("tcpip.sys", "Windows TCP/IP stack"),
    0x328000: ("tcpip.sys", "Windows TCP/IP stack"),
    0x334000: ("tcpip.sys", "Windows TCP/IP stack"),
    # Other key drivers
    0x124000: ("ntoskrnl.exe",    "Windows kernel"),
    0x8e000:  ("ndis.sys",        "NDIS"),
    0x6b000:  ("sntp.sys",        "Sophos NTP kernel driver"),
    0x52000:  ("savonaccess.sys", "Sophos On-Access minifilter"),
    0x3f000:  ("swi_callout.sys", "Sophos Web Intelligence NDIS callout"),
    0x1f000:  ("SophosED.sys",    "Sophos self-protection kernel driver"),
    0x9d0000: ("nvlddmkm.sys",    "NVIDIA Display Driver"),
    0x1c000:  ("atikmpag.sys",    "AMD/ATI Kernel Mode Driver"),
}

# ASCII byte strings to scan for in kernel dump binary
_SOPHOS_ASCII_PATTERNS = [
    b"sntp.sys", b"savonaccess.sys", b"SophosED.sys",
    b"swi_callout.sys", b"sfapm.dll", b"SophosNtp",
    b"Sophos Network Threat",
    # Process-level indicators (user-mode process names in kernel dump process list)
    b"SophosIPS.exe", b"SavService.exe", b"SophosNtpService.exe",
]

_NOTABLE_DRIVER_ASCII = [
    (b"nvlddmkm.sys", "nvlddmkm.sys"),
    (b"atikmpag.sys",  "atikmpag.sys"),
]


def _scan_for_loaded_modules(result: "DumpAnalysis", filepath: str) -> None:
    """
    Scan kernel dump binary for loaded driver names and resolve faulting module.
    Two strategies:
      1. ASCII string scan for known problematic drivers (Sophos, NVIDIA etc.)
      2. QWORD pair scan for (base_addr, image_size) bracketing P4 address
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return

    import struct as _s

    # Strategy 1: ASCII string scan
    confirmed_sophos = []
    for pattern in _SOPHOS_ASCII_PATTERNS:
        if pattern in data:
            name = pattern.decode("ascii", errors="replace")
            if name not in confirmed_sophos:
                confirmed_sophos.append(name)

    if confirmed_sophos:
        result.loaded_modules = [{"name": n, "source": "binary_scan"} for n in confirmed_sophos]

    # Check for notable GPU drivers
    for pattern, name in _NOTABLE_DRIVER_ASCII:
        if pattern in data:
            result.loaded_modules.append({"name": name, "source": "binary_scan"})

    # Strategy 2: (base_addr, image_size) QWORD pair scan bracketing P4
    p4 = result.exception_address
    if p4 and p4 > 0xFFFF000000000000:
        for i in range(0, min(len(data) - 16, 4 * 1024 * 1024), 8):
            try:
                base = _s.unpack_from("<Q", data, i)[0]
                size = _s.unpack_from("<Q", data, i + 8)[0]
                if (0xfffff80000000000 <= base <= 0xfffffc0000000000
                        and 0x1000 <= size <= 0x2000000
                        and base <= p4 < base + size):
                    known = _KNOWN_DRIVER_SIZES.get(size)
                    if known:
                        driver_name, driver_desc = known
                        offset = p4 - base
                        result.fault_offset = f"+0x{offset:X}"
                        if not result.faulting_module:
                            result.faulting_module = driver_name
                        break
            except Exception:
                continue

    # Resolve faulting module from Sophos evidence
    sophos_process_indicators = [
        "SophosIPS.exe", "SavService.exe", "SophosNtpService.exe"
    ]
    sophos_process_found = any(n in confirmed_sophos for n in sophos_process_indicators)
    sophos_driver_found = any(
        p in confirmed_sophos
        for p in ["sntp.sys", "savonaccess.sys", "SophosED.sys",
                  "swi_callout.sys", "SophosNtp", "Sophos Network Threat"]
    )

    if confirmed_sophos:
        if result.faulting_module in ("tcpip.sys", ""):
            # tcpip.sys contains the P4 address but the actual crash driver
            # is sntp.sys via an NDIS callout registered inside tcpip.sys
            if sophos_driver_found or sophos_process_found:
                result.faulting_module = (
                    "tcpip.sys [NDIS callout — Sophos sntp.sys suspected crash driver]"
                )
            elif result.faulting_module == "":
                result.faulting_module = f"Sophos process ({confirmed_sophos[0]}) in dump"
        result.loaded_modules = [{"name": n, "source": "binary_scan"} for n in confirmed_sophos]

    result.module_count = len(result.loaded_modules)



def analyze_usermode_dump(filepath: str) -> DumpAnalysis | None:
    """
    Parse a user-mode process dump (MDMP format).
    Uses the `minidump` Python package for full analysis.
    """
    if _detect_dump_type(filepath) != "usermode":
        return None
    try:
        from minidump.minidumpfile import MinidumpFile
    except ImportError:
        return None

    result = DumpAnalysis()
    result.filepath = filepath
    result.filename = Path(filepath).name

    try:
        mf = MinidumpFile.parse(filepath)
    except Exception as exc:
        return None

    # ── File timestamp (from filename or file mtime) ──
    try:
        mtime = os.path.getmtime(filepath)
        result.timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except Exception:
        result.timestamp = ""

    # ── System Info ──
    if mf.sysinfo:
        si = mf.sysinfo
        try:
            result.processor_arch = str(si.ProcessorArchitecture) if hasattr(si, 'ProcessorArchitecture') else ""
            result.processor_count = si.NumberOfProcessors if hasattr(si, 'NumberOfProcessors') else 0
            if hasattr(si, 'MajorVersion') and hasattr(si, 'MinorVersion') and hasattr(si, 'BuildNumber'):
                result.os_version = f"{si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}"
        except Exception:
            pass

    # ── Module List (loaded drivers and DLLs) ──
    modules = []
    if mf.modules and mf.modules.modules:
        for mod in mf.modules.modules:
            name = str(mod.name) if mod.name else ""
            base = mod.baseaddress if mod.baseaddress else 0
            size = mod.size if mod.size else 0
            end = mod.endaddress if hasattr(mod, 'endaddress') else base + size

            # Extract version from VS_FIXEDFILEINFO
            version = ""
            if mod.versioninfo:
                vi = mod.versioninfo
                try:
                    major = (vi.dwFileVersionMS >> 16) & 0xFFFF
                    minor = vi.dwFileVersionMS & 0xFFFF
                    build = (vi.dwFileVersionLS >> 16) & 0xFFFF
                    patch = vi.dwFileVersionLS & 0xFFFF
                    version = f"{major}.{minor}.{build}.{patch}"
                    if version == "0.0.0.0":
                        version = ""
                except Exception:
                    pass

            mod_entry = {
                "name": name,
                "short_name": name.replace("\\", "/").split("/")[-1] if name else "",
                "base": f"0x{base:016X}",
                "size": f"0x{size:X}",
                "end": f"0x{end:016X}",
                "version": version,
                "base_int": base,
                "end_int": end,
            }
            modules.append(mod_entry)

        result.loaded_modules = modules
        result.module_count = len(modules)

    # ── Exception Info ──
    if mf.exception and mf.exception.exception_records:
        exc_record = mf.exception.exception_records[0]
        exc = exc_record.ExceptionRecord

        result.crashing_thread_id = exc_record.ThreadId or 0
        result.exception_code = exc.ExceptionCode_raw if hasattr(exc, 'ExceptionCode_raw') else 0
        result.exception_address = exc.ExceptionAddress or 0

        result.exception_code_hex = f"0x{result.exception_code:08X}"
        result.exception_address_hex = f"0x{result.exception_address:016X}"

        # Decode exception/bugcheck code
        code = result.exception_code

        # Check if it's a BugCheck code (kernel stop code)
        if code in BUGCHECK_NAMES:
            result.bugcheck_code = code
            result.bugcheck_code_hex = f"0x{code:08X}"
            result.bugcheck_code_name = BUGCHECK_NAMES[code]
            result.is_kernel_crash = True
        # Also try as NTSTATUS
        elif code in NTSTATUS_NAMES:
            result.exception_code_name = NTSTATUS_NAMES[code]
        else:
            # Try unsigned 32-bit interpretation
            unsigned = code & 0xFFFFFFFF
            if unsigned in BUGCHECK_NAMES:
                result.bugcheck_code = unsigned
                result.bugcheck_code_hex = f"0x{unsigned:08X}"
                result.bugcheck_code_name = BUGCHECK_NAMES[unsigned]
                result.is_kernel_crash = True
            elif unsigned in NTSTATUS_NAMES:
                result.exception_code_name = NTSTATUS_NAMES[unsigned]
            else:
                result.exception_code_name = f"0x{unsigned:08X}"

        # ── Map exception address to faulting module ──
        fault_addr = result.exception_address
        if fault_addr and modules:
            for mod in modules:
                if mod["base_int"] <= fault_addr < mod["end_int"]:
                    result.faulting_module = mod["short_name"]
                    result.faulting_module_path = mod["name"]
                    result.faulting_module_version = mod["version"]
                    result.faulting_module_base = mod["base"]
                    offset = fault_addr - mod["base_int"]
                    result.fault_offset = f"0x{offset:X}"
                    break

    # ── Build summary ──
    lines = [
        f"Dump File: {result.filename}",
        f"Timestamp: {result.timestamp}",
        f"OS: {result.os_version}",
        f"Processors: {result.processor_count} ({result.processor_arch})",
        "",
    ]

    if result.bugcheck_code_name:
        lines.append(f"BugCheck: {result.bugcheck_code_hex} ({result.bugcheck_code_name})")
    lines.append(f"Exception: {result.exception_code_hex} ({result.exception_code_name})")
    lines.append(f"Exception Address: {result.exception_address_hex}")
    lines.append(f"Crashing Thread: {result.crashing_thread_id}")
    lines.append("")

    if result.faulting_module:
        lines.append(f"FAULTING MODULE: {result.faulting_module}")
        lines.append(f"  Path: {result.faulting_module_path}")
        lines.append(f"  Version: {result.faulting_module_version}")
        lines.append(f"  Base: {result.faulting_module_base}")
        lines.append(f"  Fault Offset: {result.fault_offset}")
    else:
        lines.append("FAULTING MODULE: (could not resolve from module list)")

    lines.append("")
    lines.append(f"Loaded Modules: {result.module_count}")

    # List top modules (drivers in \SystemRoot\ are most interesting)
    interesting = [m for m in modules if "drivers" in m["name"].lower() or ".sys" in m["name"].lower()]
    if interesting:
        lines.append("Kernel Drivers:")
        for m in interesting[:30]:
            ver = f" v{m['version']}" if m["version"] else ""
            lines.append(f"  {m['short_name']}{ver}  ({m['base']})")

    result.summary = "\n".join(lines)
    return result


def analyze_dump(filepath: str) -> DumpAnalysis | None:
    """
    Analyze any Windows dump file — auto-detects kernel vs user-mode format.

    Tries kernel dump first (BSOD .dmp files from C:\\Windows\\Minidump),
    then falls back to user-mode dump (process crash dumps).
    """
    result = analyze_kernel_dump(filepath)
    if result is not None:
        return result
    return analyze_usermode_dump(filepath)


def analyze_dump_directory(directory: str) -> list[DumpAnalysis]:
    """
    Analyze all .dmp files in a directory.

    Returns a list of DumpAnalysis objects sorted by timestamp.
    """
    results = []
    p = Path(directory)

    for dmp_path in sorted(p.rglob("*.dmp")):
        analysis = analyze_dump(str(dmp_path))
        if analysis:
            results.append(analysis)

    return results
