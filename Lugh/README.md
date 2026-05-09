# Lugh — Cybersecurity Toolkit v3.0

**Tempo Communications IT Department**

*Named after Lugh Lámhfhada — the Irish god of skill, craft, and mastery of all arts.*

A standalone, offline-first cybersecurity toolkit with both GUI and CLI interfaces. No server, no cloud — everything runs locally.

---

## Quick Start

### GUI (Windows)
```
Double-click Run_Lugh.bat
```

### GUI (Linux / macOS)
```bash
chmod +x run_lugh.sh
./run_lugh.sh
```

### CLI — Analyze Email Headers
```
lugh headers suspicious.eml --all
lugh headers phish.eml --auth --json
lugh headers inbox/ --batch
```

---

## CLI Usage

The `lugh` command provides email header analysis from the command line. Point it at an `.eml` file and get parsed results instantly.

### Setup for System PATH (Windows)

1. Copy `lugh.bat` to a folder that's already in your PATH (e.g., `C:\Windows` or a custom tools folder)
2. Edit `lugh.bat` and set `LUGH_HOME` to your install location
3. Now call `lugh` from any directory

Or add the Lugh folder itself to your PATH:
```
setx PATH "%PATH%;C:\Users\Shane.Byrne\OneDrive - Tempo Communications Inc\Code\Python\Tools\Lugh"
```

### Commands

```
lugh headers <file.eml>              Full analysis (summary + hops + auth + anti-spam)
lugh headers <file.eml> --hops       Show received hop chain with delays
lugh headers <file.eml> --auth       Show SPF/DKIM/DMARC authentication only
lugh headers <file.eml> --json       Output as JSON (pipe to jq, save to file, etc.)
lugh headers <file.eml> --raw        Dump raw headers only
lugh headers <dir/> --batch          Analyze all .eml/.msg/.txt files in a directory
lugh gui                             Launch the GUI
lugh --help                          Show help
```

### Shortcuts

```
lugh suspicious.eml                  (auto-detects file, same as lugh headers)
lugh suspicious.eml --json > out.json
lugh headers C:\Cases\ --batch --json
```

### Example Output

```
  ==============================================================
  ⚔ LUGH — Email Header Analysis
  File: phish.eml
  ==============================================================

  From           Attacker <fake@evil.xyz>
  To             victim@tempocom.com
  Subject        [EXTERNAL] Urgent: Verify Account

  RECEIVED HOPS
  ────────────────────────────────────────────────────────────
  Hop 1:
    From:     mail.evil.xyz
    By:       mx.protection.outlook.com
    Protocol: ESMTPS
    Time:     2026-03-06 21:58:53+00:00

  AUTHENTICATION
  ────────────────────────────────────────────────────────────
  ❌ SPF        FAIL        (sender IP not authorized)
  ⚠ DKIM       NONE
  ❌ DMARC      FAIL

  ── 1 hops | Auth: 0 pass, 2 fail | ❌ SUSPICIOUS
```

---

## Requirements

| Dependency | Required? | Purpose |
|---|---|---|
| **Python 3.8+** | Yes | Runtime |
| **tkinter** | Yes (GUI only) | GUI framework. Not needed for CLI |
| customtkinter | Optional | Modern dark themed UI |
| python-evtx | Optional | .evtx parsing — auto-installs on first use |
| yara-python | Optional | YARA rule scanning |

```bash
pip install customtkinter       # Modern UI
pip install python-evtx         # .evtx support
pip install yara-python         # YARA engine
```

---

## GUI Tabs

### Tab 1: Email Header Analyzer
Paste raw email headers (Outlook: message → File → Properties → Internet Headers). Parsed into 7 sub-sections: Summary, Received Hops, Authentication (SPF/DKIM/DMARC), Anti-Spam (SCL/BCL/SFV), Other Headers, Raw View, Input.

### Tab 2: Homograph / IDN Detector
Unicode homograph attack detection. Flags non-Latin characters impersonating Latin lookalikes in domains.

### Tab 3: File Type Checker
Magic number scanner (49 signatures). Identifies files by header bytes, flags extension mismatches.

### Tab 4: Hash Checker
MD5, SHA-1, SHA-256 computation with comparison, directory scanning, CSV export.

### Tab 5: Event Log Parser
Batch triage: load .evtx/.csv/.xml/.log files, auto-filter to troublesome events only (54 notable Event IDs + Critical/Error/Warning levels + Audit Failures). Export filtered results to CSV.

### Tab 6: Malicious Link Analyzer
URL extraction and 12-check scoring (0–100): suspicious TLDs, shorteners, phishing keywords, IP-based URLs, double extensions, Unicode domains, etc. Defang-all to clipboard.

### Tab 7: Advanced Tools
Deep Analyzer (PE parser), YARA Engine, Risk Scoring (18 indicators), PowerShell Static Analyzer, Archive Extractor (recursive ZIP/TAR/GZ/BZ2/XZ).

---

## Project Structure

```
Lugh/
├── main.py              ← GUI entry point (also routes CLI args to lugh.py)
├── lugh.py              ← CLI entry point
├── lugh.bat             ← Drop in PATH for system-wide CLI access
├── config.py            ← Theme, version, imports
├── Run_Lugh.bat         ← Windows GUI launcher
├── run_lugh.sh          ← Linux/macOS launcher (GUI + CLI)
├── README.md
│
├── engines/             ← Analysis engines (standalone, no GUI dependency)
│   ├── __init__.py
│   ├── email_data.py        email_parser.py
│   ├── homograph.py         file_checker.py
│   ├── deep_analyzer.py     yara_engine.py
│   ├── risk_scoring.py      ps_analyzer.py
│   ├── archive_extractor.py
│   ├── event_log.py         link_analyzer.py
│
└── gui/                 ← GUI tab modules (mixin pattern)
    ├── __init__.py      app.py
    ├── tab_email.py     tab_homograph.py    tab_filechecker.py
    ├── tab_hash.py      tab_eventlog.py     tab_links.py
    └── tab_advanced.py
```

---

## Using Engines in Scripts

```python
from engines.event_log import EventLogParser, NOTABLE_EVENT_IDS

parser = EventLogParser()
parser.parse_file("Security.evtx")
for ev in parser.events:
    eid = int(ev.get("event_id", 0))
    if eid in NOTABLE_EVENT_IDS:
        print(f"[{ev['time']}] {NOTABLE_EVENT_IDS[eid][1]}")
```

```python
from engines.link_analyzer import LinkAnalyzer

la = LinkAnalyzer()
for r in la.analyze_bulk(open("email.eml").read()):
    if r["risk_level"] in ("HIGH", "CRITICAL"):
        print(f"  {r['risk_level']}: {r['url']}")
```

---

## Antivirus Notes

`engines/ps_analyzer.py` contains PowerShell attack pattern strings for detection purposes. AV products may quarantine it. Add an exclusion for the Lugh project folder.

---

## Version History

| Version | Changes |
|---|---|
| 1.0–1.5 | Email Headers, Homograph, File Checker, Hash Checker, Advanced Tools |
| 2.0 | Event Log Parser, 54 notable Event IDs |
| 2.1 | Link Analyzer, Event Log rewrite, CSV BOM fixes, modularized codebase |
| **3.0** | **Rebranded to Lugh. Added CLI with `lugh headers` command for .eml analysis (--all, --hops, --auth, --json, --raw, --batch). PATH-ready lugh.bat wrapper. Summary + hops + auth + anti-spam + verdict output.** |
