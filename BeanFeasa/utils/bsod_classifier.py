"""
BeanFeasa — utils/bsod_classifier.py

BugCheck Classification — LPBH vs Genuine Crash
Added post USVIS-952KC14 (R-06).

In USVIS-952KC14, 44 live dump events with BugCheck 0x1A8 were generated
by users holding the power button (LONG_POWER_PRESS_HALT). Without parameter
inspection, these were misclassified as GPU crashes and produced a false
primary finding. This classifier checks Arg1 and FAILURE_BUCKET_ID to
distinguish LPBH dumps from genuine crashes before a finding is emitted.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class BugCheckResult:
    code_hex: str
    category: str        # lpbh | gpu_crash | kernel_crash | memory | process_crash | unknown
    severity: str        # critical | high | medium | informational
    label: str
    explanation: str
    suppress_gpu: bool   # True → do NOT treat this as a GPU crash
    is_live_dump: bool


# BugCheck code database: normalised 8-char hex → (category, severity, label, explanation, suppress_gpu, is_live_dump)
_DB: dict[str, tuple] = {
    "000001A8": ("lpbh_or_live_dump", "informational", "Live Dump / LPBH Candidate",
                 "Live diagnostic dump. Check Arg1 and FAILURE_BUCKET_ID. "
                 "Arg1=0x8 confirms LONG_POWER_PRESS_HALT (user power-button hold).", True, True),
    "000001B8": ("lpbh_or_live_dump", "informational", "Live Dump (alternate)",
                 "Alternate live dump code. Same LPBH interpretation as 0x1A8.", True, True),
    "00000116": ("gpu_crash", "high", "VIDEO_TDR_FAILURE",
                 "GPU driver failed to recover from TDR timeout.", False, False),
    "00000117": ("gpu_crash", "high", "VIDEO_TDR_TIMEOUT_DETECTED",
                 "GPU did not respond within the TDR window.", False, False),
    "00000141": ("gpu_crash", "high", "VIDEO_ENGINE_TIMEOUT_DETECTED",
                 "Specific GPU engine timed out.", False, False),
    "00000142": ("gpu_crash", "high", "VIDEO_TDR_APPLICATION_BLOCKED",
                 "Application blocked GPU TDR recovery.", False, False),
    "00000119": ("gpu_crash", "critical", "VIDEO_SCHEDULER_INTERNAL_ERROR",
                 "GPU scheduler internal error — severe driver or hardware fault.", False, False),
    "0000003B": ("kernel_crash", "critical", "SYSTEM_SERVICE_EXCEPTION",
                 "Kernel-mode driver raised an unhandled exception.", False, False),
    "0000007E": ("kernel_crash", "critical", "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
                 "Kernel thread threw an unhandled exception.", False, False),
    "00000050": ("memory", "critical", "PAGE_FAULT_IN_NONPAGED_AREA",
                 "Invalid memory address access — possible RAM fault or driver corruption.", False, False),
    "000000EF": ("process_crash", "critical", "CRITICAL_PROCESS_DIED",
                 "Critical process (lsass, csrss, smss) terminated unexpectedly.", False, False),
}

_LPBH_ARG1 = {
    "0x8":  "LONG_POWER_PRESS_HALT — user held power button (confirmed)",
    "0x1":  "Task-triggered live dump",
    "0x2":  "Process-initiated live dump",
    "0x4":  "Device/hardware-triggered live dump",
    "0x10": "Watchdog-triggered live dump",
}


def classify(
    code: str | int,
    arg1: Optional[str] = None,
    failure_bucket_id: Optional[str] = None,
    dump_filename: Optional[str] = None,
) -> BugCheckResult:
    """
    Classify a BugCheck event.

    Parameters
    ----------
    code              BugCheck code as hex string or int.
    arg1              BugCheck parameter 1 (P1) — critical for LPBH detection.
    failure_bucket_id FAILURE_BUCKET_ID from WinDbg /analyze or WER message.
    dump_filename     Dump filename — 'WATCHDOG' in name hints at LPBH.
    """
    norm = _normalise(code)
    entry = _DB.get(norm)

    if entry is None:
        return BugCheckResult(
            code_hex=f"0x{norm}",
            category="unknown", severity="medium",
            label="Unrecognised BugCheck",
            explanation=f"Code 0x{norm} not in classifier database. Review manually.",
            suppress_gpu=False, is_live_dump=False,
        )

    category, severity, label, explanation, suppress_gpu, is_live_dump = entry

    if is_live_dump:
        lpbh_confirmed = False
        lpbh_detail = ""

        if arg1:
            arg1_norm = arg1.strip().lower()
            for key, desc in _LPBH_ARG1.items():
                if arg1_norm == key.lower():
                    lpbh_detail = desc
                    if key == "0x8":
                        lpbh_confirmed = True
                    break

        if failure_bucket_id and "LONG_POWER_PRESS" in failure_bucket_id.upper():
            lpbh_confirmed = True
            lpbh_detail = lpbh_detail or "LONG_POWER_PRESS in FAILURE_BUCKET_ID"

        if dump_filename and "WATCHDOG" in dump_filename.upper() and not lpbh_confirmed:
            lpbh_detail = lpbh_detail or "WATCHDOG in dump filename (check Arg1)"

        if lpbh_confirmed:
            label = "LONG_POWER_PRESS_HALT — User Power-Button Hold"
            explanation = (
                f"Confirmed LPBH: {lpbh_detail}. NOT a crash — user held power button "
                "for 7+ seconds. Do not classify as GPU failure."
            )
            severity = "informational"
            category = "lpbh"
        elif lpbh_detail:
            explanation = f"{explanation} Detail: {lpbh_detail}."

    return BugCheckResult(
        code_hex=f"0x{norm}",
        category=category, severity=severity,
        label=label, explanation=explanation,
        suppress_gpu=suppress_gpu, is_live_dump=is_live_dump,
    )


def _normalise(code: str | int) -> str:
    if isinstance(code, int):
        return f"{code:08X}"
    s = str(code).strip().upper()
    if s.startswith("0X"):
        s = s[2:]
    return s.zfill(8)
