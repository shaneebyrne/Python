"""
BeanFeasa — WER (Windows Error Reporting) Message Parser.

Parses EventID 1001 message bodies to extract structured crash data:
  - Fault bucket string → module name and version
  - BugCheck parameters (P1–P5)
  - Minidump file paths
  - Event Name (BlueScreen vs APPCRASH)
  - Report ID for cross-referencing

Also extracts faulting module from EventID 1000 (Application Error).

Addresses MISS-06 from the evaluation: "Faulting Module Not Extracted"
"""

import re
from dataclasses import dataclass, field


@dataclass
class CrashInfo:
    """Structured data extracted from a WER or Application Error event."""
    event_name: str = ""            # BlueScreen, APPCRASH, LiveKernelEvent, etc.
    fault_bucket: str = ""          # Full fault bucket string
    faulting_module: str = ""       # Extracted module name (e.g., RtUsbA64.sys)
    faulting_module_version: str = ""
    faulting_app: str = ""          # For APPCRASH: the application name
    exception_code: str = ""        # e.g., 0xc0000005
    bugcheck_code: str = ""         # For BSOD: the stop code
    bugcheck_p1: str = ""
    bugcheck_p2: str = ""
    bugcheck_p3: str = ""
    bugcheck_p4: str = ""
    dump_file: str = ""             # Minidump path
    report_id: str = ""
    clr_exception: bool = False     # True if .NET CLR exception detected


# ── Regex patterns for WER 1001 message parsing ──

# Fault bucket: AV_RtUsbA64_197!unknown_function
FAULT_BUCKET_RE = re.compile(
    r"(?:Fault bucket|P1|Bucket ID)[:\s]+(\S+)",
    re.IGNORECASE,
)

# Module from fault bucket: AV_<ModuleName>_<Version>!<Function>
MODULE_FROM_BUCKET_RE = re.compile(
    r"(?:AV|BEX|BEX64|APPCRASH)_([A-Za-z0-9_.]+?)_(\d+)!",
)

# Generic fault bucket module: <type>_modulename.sys_version
MODULE_FROM_BUCKET_SYS_RE = re.compile(
    r"(?:AV|BEX|BEX64|CLR)_([A-Za-z0-9_]+\.(?:sys|dll|exe))_",
    re.IGNORECASE,
)

# BugCheck code from message
BUGCHECK_RE = re.compile(
    r"(?:BugCheck|Bug Check|Stop)[:\s]+(?:0x)?([0-9A-Fa-f]+)",
    re.IGNORECASE,
)

# BugCheck parameters P1-P4
BUGCHECK_PARAMS_RE = re.compile(
    r"(?:P1|Parameter 1)[:\s]+(?:0x)?([0-9A-Fa-f]+).*?"
    r"(?:P2|Parameter 2)[:\s]+(?:0x)?([0-9A-Fa-f]+).*?"
    r"(?:P3|Parameter 3)[:\s]+(?:0x)?([0-9A-Fa-f]+).*?"
    r"(?:P4|Parameter 4)[:\s]+(?:0x)?([0-9A-Fa-f]+)",
    re.IGNORECASE | re.DOTALL,
)

# Minidump file path
DUMP_FILE_RE = re.compile(
    r"((?:[A-Z]:\\|/)[^\s,\"]+\.dmp)",
    re.IGNORECASE,
)

# Report ID
REPORT_ID_RE = re.compile(
    r"(?:Report Id|ReportId)[:\s]+([0-9a-fA-F-]+)",
    re.IGNORECASE,
)

# Event Name field
EVENT_NAME_RE = re.compile(
    r"(?:Event Name|EventName)[:\s]+(\S+)",
    re.IGNORECASE,
)

# Application Error Event 1000 faulting module
FAULTING_APP_RE = re.compile(
    r"(?:Faulting application name|Application Name)[:\s]+(\S+)",
    re.IGNORECASE,
)
FAULTING_MODULE_RE = re.compile(
    r"(?:Faulting module name|Fault Module Name)[:\s]+(\S+)",
    re.IGNORECASE,
)
EXCEPTION_CODE_RE = re.compile(
    r"(?:Exception code|Exception Code)[:\s]+(0x[0-9A-Fa-f]+)",
    re.IGNORECASE,
)

# CLR / .NET exception codes
CLR_EXCEPTION_CODES = {"0xe0434352", "0x80131623", "0x80131506", "0x80131604"}


def parse_wer_message(message: str, event_id: str = "") -> CrashInfo:
    """
    Parse a WER EventID 1001 or Application Error EventID 1000
    message body and extract structured crash data.
    """
    info = CrashInfo()
    if not message:
        return info

    msg = message

    # Event Name
    m = EVENT_NAME_RE.search(msg)
    if m:
        info.event_name = m.group(1)

    # Fault bucket
    m = FAULT_BUCKET_RE.search(msg)
    if m:
        info.fault_bucket = m.group(1)

        # Extract module from bucket
        m2 = MODULE_FROM_BUCKET_RE.search(info.fault_bucket)
        if m2:
            info.faulting_module = m2.group(1)
            info.faulting_module_version = m2.group(2)
        else:
            m2 = MODULE_FROM_BUCKET_SYS_RE.search(info.fault_bucket)
            if m2:
                info.faulting_module = m2.group(1)

    # BugCheck code
    m = BUGCHECK_RE.search(msg)
    if m:
        info.bugcheck_code = f"0x{m.group(1).upper()}"

    # BugCheck parameters
    m = BUGCHECK_PARAMS_RE.search(msg)
    if m:
        info.bugcheck_p1 = f"0x{m.group(1).upper()}"
        info.bugcheck_p2 = f"0x{m.group(2).upper()}"
        info.bugcheck_p3 = f"0x{m.group(3).upper()}"
        info.bugcheck_p4 = f"0x{m.group(4).upper()}"

    # Dump file
    m = DUMP_FILE_RE.search(msg)
    if m:
        info.dump_file = m.group(1)

    # Report ID
    m = REPORT_ID_RE.search(msg)
    if m:
        info.report_id = m.group(1)

    # Application Error 1000 fields
    m = FAULTING_APP_RE.search(msg)
    if m:
        info.faulting_app = m.group(1)

    m = FAULTING_MODULE_RE.search(msg)
    if m:
        if not info.faulting_module:
            info.faulting_module = m.group(1)

    m = EXCEPTION_CODE_RE.search(msg)
    if m:
        info.exception_code = m.group(1).lower()

    # CLR detection
    if info.exception_code in CLR_EXCEPTION_CODES:
        info.clr_exception = True

    return info


def count_unique_dumps(messages: list[str]) -> tuple[int, list[str]]:
    """
    Count unique minidump file references across multiple WER messages.
    Returns (count, list_of_dump_paths).

    Addresses MISS-01: "Second BSOD not detected."
    """
    dumps = set()
    for msg in messages:
        for m in DUMP_FILE_RE.finditer(msg):
            dumps.add(m.group(1).lower())
    return len(dumps), sorted(dumps)


def extract_crash_process_frequency(events) -> dict[str, int]:
    """
    Count crashes per process name from EventID 1000 events.
    Returns {process_name: crash_count}.

    Addresses MISS-02/MISS-03: "Chronic crash detection."
    """
    from collections import Counter
    counts = Counter()
    for evt in events:
        if str(evt.event_id) == "1000" and "Application Error" in (evt.source or ""):
            info = parse_wer_message(evt.message, "1000")
            if info.faulting_app:
                counts[info.faulting_app] += 1
    return dict(counts)
