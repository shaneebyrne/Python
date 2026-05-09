# BeanFeasa — Log Analysis & Threat Detection Toolkit

A modular, cross-platform Python tool for parsing and analyzing Windows diagnostic logs using Sigma-inspired detection rules, evidence-gated multi-event correlation, statistical anomaly detection, minidump crash analysis, and an integrated remediation knowledge base.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-green)
![License](https://img.shields.io/badge/license-MIT-purple)

---

## What Makes This Different

BeanFeasa runs **four analysis engines** in sequence, with automatic device profiling and inventory file exclusion to keep the signal-to-noise ratio high:

1. **Rule-Based Detection** — 169 Sigma-inspired YAML rules match events by Event ID, source, and specific error patterns. Rules support `filter` blocks (`condition: selection and not filter`) to suppress known false-positive patterns per-event before a detection fires.

2. **Correlation Engine** — 21 evidence-gated event chains link multi-event sequences within time windows. Chains only fire when required evidence is confirmed present. Post-crash suppression automatically downgrades downstream events (e.g., Netlogon 5719 after a BSOD) as artifacts. Post-boot suppression suppresses expected transient failures (e.g., Netlogon within 120 seconds of boot).

3. **Anomaly Detector** — Nine statistical methods surface outliers: error bursts, frequency spikes, rare events, severity escalation, unusual sources, chronic application crashes, service install loops, MSI failure loops, and **periodic crash pattern detection** (timer-driven failure identification).

4. **Minidump Parser** — Reads Windows crash dumps directly. Handles kernel BSOD dumps (PAGE/DU64 format — extracts BugCheck code and parameters) and user-mode process dumps (MDMP format — maps exception address to faulting module with version). LONG_POWER_PRESS_HALT live dumps are classified separately and never inflate the crash count.

Every detection is filtered by a **Device Context** system that auto-detects machine profile from SystemInfo.txt (WORKGROUP vs domain, Teams Room, VBS-enabled, OEM hardware) and suppresses inapplicable rules.

**Inventory files** (Drivers.csv, Services.csv, RunningProcesses.csv, CBS.log, etc.) are automatically excluded from all analysis engines — only event log files produce detections.

---

## Quick Start

### GUI Mode

**Windows:** Double-click `run_beanfeasa.bat`

**Linux/macOS:**
```bash
chmod +x run_beanfeasa.sh && ./run_beanfeasa.sh
```

### CLI Mode

```bash
python main.py C:\Users\Public\LogCollect\ --full-report -o report.csv
python main.py EventLog_System.csv -v
python main.py logs/ -q                    # Exit code: 0=clean, 1=critical, 2=high
python main.py logs/ --no-correlate --no-anomaly
```

### Requirements

| Package | Required | Purpose |
|---|---|---|
| Python 3.10+ | Yes | Core runtime |
| pyyaml | Yes | Loads detection rules |
| python-evtx | Optional | Native .evtx file parsing |
| minidump | Optional | User-mode .dmp analysis |
| tkinter | Optional | GUI (bundled on Windows) |

All optional dependencies are auto-installed by the launcher scripts.

---

## Supported Formats

| Format | Extension | Source |
|---|---|---|
| CSV event exports | .csv, .tsv | CollectLogs, PowerShell Get-WinEvent |
| Windows Event Log | .evtx | Direct event log files |
| Kernel crash dumps | .dmp | C:\Windows\Minidump (BSOD) |
| User-mode dumps | .dmp | Application crash dumps |
| JSON/JSONL | .json, .jsonl | Structured log exports |
| XML | .xml | Event log XML exports |
| Syslog/text | .log, .syslog, .txt | Linux syslog, plain text logs |

---

## Analysis Engines

### Rule-Based Detection — 169 rules across 13 files

| Rule File | Rules | Coverage |
|---|---|---|
| hardware_failures.yml | 18 | Disk, WHEA/MCE, CPU, GPU/TDR, NIC, USB, PCI |
| software_failures.yml | 24 | BSOD, crashes, services, drivers, .NET, MSI, lsass restart, LPBH |
| lsa_gpo_security.yml | 2 | LsaSrv 5000 (Kerberos SSP exception), GPO Event 1502 (new settings) |
| bios_firmware.yml | 17 | UEFI, Secure Boot, TPM, ACPI, WDAC, Intel ME |
| storage_filesystem.yml | 12 | NTFS, RAID, VSS, BitLocker |
| network_infrastructure.yml | 15 | DNS, DHCP, WiFi, VPN, Kerberos, TLS |
| performance_resources.yml | 16 | Memory, disk space, boot perf, spooler |
| endpoint_management.yml | 13 | Teams Rooms, RDP, AV/EDR, Hyper-V |
| windows_security.yml | 10 | Logon failures, PowerShell, service installs |
| linux_cross_platform.yml | 8 | SSH, sudo, cron, network indicators |
| tempo_environment.yml | 13 | SentinelOne, StorPort, IntelTACD, MCore |
| evaluation_fixes.yml | 12 | WER parsing, boot diagnostics, UAC, NTFS recovery |
| sidekick_fixes.yml | 9 | KP566 standby, SysMain, lockups, WDAC, driver loops |

### Correlation Engine — 21 evidence-gated chains

| Chain | Severity | Key Evidence |
|---|---|---|
| **Kerberos SSP → lsass Crash** | **Critical** | **LsaSrv 5000 + App Error 1000 (lsass.exe)** |
| **GPO Change → Crash** | **Critical** | **GroupPolicy 1502 (new settings) + crash within 60 min** |
| BSOD Cascade | Critical | KP41 + WER 1001 (faulting module extracted, LPBH excluded) |
| GPU TDR Failure | Critical | KP41 + VIDEO_TDR/nvlddmkm evidence |
| Hard System Lockup | Critical | KP41 + 6008 + NTFS 98 |
| WHEA → BSOD | Critical | WHEA source + KP41 |
| Brute Force (Network) | Critical | 4625 (no consent.exe) + 4624 Type 3 |
| Brute Force (RDP) | Critical | 4625 (no consent.exe) + 4624 Type 10 |
| BitLocker Recovery | Critical | BitLocker source required |
| SentinelOne Injection | High | App Error 1000 + InProcessClient DLL |
| AD Communication Failure | High | NETLOGON 5719 — suppressed within 120s of boot AND within 10min of crash |
| Recurring Service Crash | Medium | SCM 7034 across multiple boots |

All network/AD chains support **crash artifact suppression** (events within 10 minutes of a KP41 are auto-downgraded) and **boot artifact suppression** (Netlogon/AD failures within 120 seconds of boot are flagged as transient, not independent incidents).

### Anomaly Detector — 9 methods

| Method | Detection |
|---|---|
| Burst Detection | 10+ errors in 5 minutes |
| Frequency Spike | Event count > 2.5σ above baseline |
| Rare Event | Error Event IDs with ≤3 occurrences |
| Severity Escalation | Sources with >50% error events |
| Unusual Source | Rare providers producing errors |
| Chronic Crash | Process crashing 3+ times (same faulting module) |
| Service Install Loop | 7045 install + 7000 failure for same service |
| MSI Failure Loop | Same product failing 5+ times (status ≠ 0) |
| **Periodic Crash Pattern** | **3+ crashes at a regular interval — matches known timers (Kerberos TGT, GP refresh, etc.)** |

### BSOD Classifier

`utils/bsod_classifier.py` classifies BugCheck events by inspecting `Arg1` / `FAILURE_BUCKET_ID` before any finding is emitted:

| Code | Arg1=0x8 / LONG_POWER_PRESS | Classification |
|---|---|---|
| 0x1A8, 0x1B8 | Yes | LPBH — Informational, suppress GPU rule |
| 0x1A8, 0x1B8 | No | Live dump — Informational, suppress GPU rule |
| 0x116, 0x117 | — | GPU crash — High |
| 0x141, 0x142 | — | GPU engine timeout — High |
| 0x119 | — | GPU scheduler error — Critical |
| 0xEF | — | Critical process died — Critical |

Without this, tools misclassify LPBH live dumps as GPU crashes and produce false primary findings.

### Minidump Parser

| Format | Signature | Extraction |
|---|---|---|
| Kernel BSOD | PAGE+DU64 | BugCheck code, 4 parameters, processor count |
| User-mode | MDMP | Exception, faulting module, version, loaded modules |

Auto-detects format from file header. Kernel dumps use pure binary `struct.unpack` (no dependencies). Minidump subdirectories are auto-discovered.

### Remediation KB — 47 entries

Covers all major event types including:
- **LsaSrv 5000** — Kerberos SSP exception, step-by-step encryption policy diagnosis
- **Event 1502** — GPO new settings, ADMX blank-name investigation
- **LPBH** — Power button hold, how to confirm vs genuine crash
- **Periodic crash** — Timer-matching, Kerberos ticket lifetime investigation

### Device Context

Auto-reads SystemInfo.txt and suppresses inapplicable rules:

| Detection | Suppression |
|---|---|
| Domain = WORKGROUP | Kerberos, LDAP, AD, GPO rules |
| VBS = Running | Hyper-V "error" rules |
| Teams Room (MCore) | WiFi failure rules |
| OEM = Yealink | Dell/HP/Lenovo OEM rules |

---

## Writing Custom Rules

```yaml
---
id: custom-001
title: Suspicious Service Name
level: high
detection:
  source_check:
    source|contains:
      - "Service Control Manager"
  keyword:
    message|contains:
      - "psexec"
      - "cobalt"
  filter:
    message|contains:
      - "expected keyword to exclude"
  condition: source_check and keyword and not filter
```

Use `condition: X and Y` (all must match), `condition: X or Y` (any can match), or `condition: X and not filter` (exclude events matching the filter block).

---

## Collection Requirements for New Rules

Some rules require additional log sources in your collection script:

| Rule | Required Source | Collection Command |
|---|---|---|
| `lsa-krb-crash-001` | LsaSrv Event 5000 in System log | `Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='LsaSrv'; Id=5000}` |
| `gpo-change-001` | GroupPolicy/Operational log | `Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational'` |
| `net-krb-001` | Security log Kerberos events | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4768,4769,4771)}` |

If these log sources are not in the collection package, the rules will produce zero matches regardless of whether the events occurred.

---

## Project Structure

```
BeanFeasa/
├── main.py                    Entry point (GUI/CLI auto-routing)
├── cli.py                     Command-line interface
├── gui/app.py                 Tkinter GUI (Catppuccin Mocha)
├── parsers/
│   ├── registry.py            Parser auto-detection
│   ├── csv_parser.py          CSV/TSV event parser
│   ├── dmp_parser.py          Minidump parser (kernel + user-mode)
│   ├── supplemental.py        SystemInfo, Drivers, CBS/DISM
│   └── ...                    JSON, XML, text, EVTX parsers
├── analyzers/
│   ├── detection_engine.py    Rule matching (with filter/exclusion support)
│   ├── correlation_engine.py  Evidence-gated correlation (21 chains)
│   ├── anomaly_detector.py    Statistical analysis (9 methods)
│   ├── wer_parser.py          WER message body parser
│   └── remediation_kb.py      47-entry knowledge base
├── utils/
│   ├── platform_utils.py      File discovery + classification
│   ├── device_context.py      Device profile auto-detection
│   └── bsod_classifier.py     BugCheck Arg1/LPBH classifier
├── rules/
│   ├── software_failures.yml  (includes lsass-restart-001, bsod-lpbh-001)
│   ├── lsa_gpo_security.yml   NEW — LsaSrv 5000, GPO Event 1502
│   └── ...                    12 other rule files
└── requirements.txt
```

## CLI Exit Codes

| Code | Meaning |
|---|---|
| 0 | No critical or high-severity findings |
| 1 | Critical-severity findings detected |
| 2 | High-severity findings (no critical) |

---

## Changelog

### v3 — post USVIS-952KC14

**New rules:**
- `lsa-krb-crash-001` — LsaSrv Event 5000 (Kerberos SSP exception in lsass). Would have identified root cause in USVIS-952KC14 on first crash without WinDbg.
- `lsass-restart-001` — wininit Event 1074 with lsass comment field. Standalone Critical detection of lsass-induced restarts.
- `gpo-change-001` — GroupPolicy Event 1502 with "new settings". Requires GroupPolicy/Operational log in collection.
- `bsod-lpbh-001` — LONG_POWER_PRESS_HALT live dumps classified as Informational. Prevents false GPU-crash primary findings.

**Rule fixes (false positives eliminated):**
- `net-krb-002` — Scoped to `Microsoft-Windows-Security-Kerberos` provider + explicit event IDs. Removed keyword matching on `0x6`, `0x17`, `0x25` etc. that was hitting VBScript deprecation alerts and lsass crash records. ~213 FP events eliminated.
- `sw-drv-002` — Scoped to SCM (7000/7009/7023/7034) and Kernel-PnP (219) event IDs. Removed keyword matching on crash report terminology. ~234 FP events eliminated.
- `hw-mem-001` — Scoped to WHEA source. Previously matching fault bucket records in Application log. ~12 FP events eliminated.
- `stor-raid-001` — Scoped to storage-specific sources. Previously matching fault bucket crash metadata.
- `stor-bl-001` — Added filter excluding Kernel-Boot Event 27 with "cannot be found" (missing message DLL, not BitLocker). ~4 FP events eliminated.
- `sw-bsod-003` — Added filter block excluding LONG_POWER_PRESS. Previously classified 44 LPBH dumps as GPU crashes.

**New correlation chains:**
- `chain-lsass-krb-001` — LsaSrv 5000 → App Error 1000 (lsass.exe) → wininit 1074. Confirms root cause without WinDbg. Critical with High confidence.
- `chain-gpo-crash-001` — GroupPolicy 1502 (new settings) → crash within 60 minutes. Medium confidence configuration-change root cause.

**Correlation engine fixes:**
- `chain-ad-001` — Added boot artifact suppression (`suppress_if_boot_artifact=True`, `boot_window_seconds=120`). Netlogon 5719 within 120 seconds of boot is now tagged [POST-BOOT TRANSIENT] at Low severity instead of firing as an independent High-severity AD incident.
- `_enrich_bsod` — Integrated BSOD classifier. LONG_POWER_PRESS dumps are detected and excluded from crash count. Root cause text rewritten when all dumps are LPBH.

**New anomaly detector:**
- `_detect_crash_periodicity` — Computes inter-event deltas for crash events, detects clustering within ±10% tolerance, matches against known timer intervals (Kerberos TGT renewal, GP refresh, etc.). Would have flagged the 4-hour lsass crash cycle in USVIS-952KC14 with label "Kerberos TGT renewal (4 h — common GPO setting)".

**New utility:**
- `utils/bsod_classifier.py` — BugCheck parameter parser. Classifies by Arg1 and FAILURE_BUCKET_ID. Returns `suppress_gpu=True` for LPBH events.

**Remediation KB — 47 entries (was 42):**
- LsaSrv 5000 — Kerberos SSP exception
- wininit 1074 (lsass) — lsass-induced restart
- GroupPolicy 1502 — GPO new settings investigation
- LONG_POWER_PRESS — LPBH confirmation and interpretation
- Periodic crash — Timer-matching and Kerberos ticket lifetime investigation

**Rule engine:**
- `rule_loader.py` — Added `exclude_conditions` field and parser. Blocks named `filter*` or referenced with `not` in the condition string are treated as exclusion conditions.
- `detection_engine.py` — Added exclusion pre-check in `_evaluate_rule`. If any `exclude_condition` matches the event, the rule is suppressed before selection conditions are checked.

## License

MIT
