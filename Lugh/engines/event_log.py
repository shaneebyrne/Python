"""
Lugh v3.0 - Event Log Parser (Troublesome Event Filter)
"""
import re, csv, sys
import xml.etree.ElementTree as ET
from pathlib import Path

HAS_EVTX = False
evtx = None

def _ensure_evtx():
    """Check for python-evtx, install if missing, return True if available."""
    global HAS_EVTX, evtx
    if HAS_EVTX:
        return True
    try:
        import Evtx.Evtx as _evtx
        evtx = _evtx; HAS_EVTX = True
        return True
    except ImportError:
        pass
    try:
        import subprocess as _sp
        _sp.check_call([sys.executable, "-m", "pip", "install", "python-evtx", "--quiet"],
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        import Evtx.Evtx as _evtx
        evtx = _evtx; HAS_EVTX = True
        return True
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════
# EVENT LOG PARSER
# ══════════════════════════════════════════════════════════════
# Notable Windows Event IDs for security analysis
NOTABLE_EVENT_IDS = {
    1102:("Security","Audit log cleared","CRITICAL"),
    4624:("Security","Successful logon","INFO"),
    4625:("Security","Failed logon","WARNING"),
    4634:("Security","Logoff","INFO"),
    4648:("Security","Explicit credential logon","WARNING"),
    4656:("Security","Handle to object requested","INFO"),
    4663:("Security","Attempt to access object","INFO"),
    4672:("Security","Special privileges assigned","WARNING"),
    4688:("Security","Process creation","INFO"),
    4689:("Security","Process termination","INFO"),
    4697:("Security","Service installed","WARNING"),
    4698:("Security","Scheduled task created","WARNING"),
    4699:("Security","Scheduled task deleted","INFO"),
    4700:("Security","Scheduled task enabled","INFO"),
    4719:("Security","Audit policy changed","CRITICAL"),
    4720:("Security","User account created","WARNING"),
    4722:("Security","User account enabled","INFO"),
    4724:("Security","Password reset attempted","WARNING"),
    4725:("Security","User account disabled","INFO"),
    4726:("Security","User account deleted","WARNING"),
    4728:("Security","Member added to global group","WARNING"),
    4732:("Security","Member added to local group","WARNING"),
    4735:("Security","Local group changed","WARNING"),
    4738:("Security","User account changed","WARNING"),
    4740:("Security","Account locked out","WARNING"),
    4756:("Security","Member added to universal group","WARNING"),
    4767:("Security","Account unlocked","INFO"),
    4776:("Security","NTLM credential validation","INFO"),
    4798:("Security","Local group membership enumerated","INFO"),
    4799:("Security","Security-enabled group enumerated","INFO"),
    5140:("Security","Network share accessed","INFO"),
    5145:("Security","Share object checked","INFO"),
    5156:("Security","Network connection permitted","INFO"),
    5157:("Security","Network connection blocked","WARNING"),
    7034:("System","Service crashed","WARNING"),
    7036:("System","Service state change","INFO"),
    7040:("System","Service start type changed","WARNING"),
    7045:("System","Service installed","WARNING"),
    1:("Sysmon","Process creation","INFO"),
    3:("Sysmon","Network connection","INFO"),
    7:("Sysmon","Image loaded","INFO"),
    8:("Sysmon","CreateRemoteThread","CRITICAL"),
    10:("Sysmon","Process accessed","WARNING"),
    11:("Sysmon","File created","INFO"),
    12:("Sysmon","Registry object add/delete","INFO"),
    13:("Sysmon","Registry value set","INFO"),
    22:("Sysmon","DNS query","INFO"),
    23:("Sysmon","File delete archived","INFO"),
    25:("Sysmon","Process tamper","CRITICAL"),
    4104:("PowerShell","Script block logging","WARNING"),
    4103:("PowerShell","Module logging","INFO"),
    400:("PowerShell","Engine start","INFO"),
    403:("PowerShell","Engine stop","INFO"),
    800:("PowerShell","Pipeline execution","INFO"),
}

EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

class EventLogParser:
    """Parses Windows Event Logs from .evtx, .csv, .xml, and .log files."""

    def __init__(self):
        self.events = []; self.errors = []; self.stop_requested = False

    def reset(self):
        self.events = []; self.errors = []; self.stop_requested = False

    def parse_file(self, filepath, prog_cb=None):
        """Parse a single file and append to self.events."""
        fp = Path(filepath); ext = fp.suffix.lower()
        try:
            if ext == ".evtx":
                self._parse_evtx(fp, prog_cb)
            elif ext == ".csv":
                self._parse_csv(fp, prog_cb)
            elif ext == ".xml":
                self._parse_xml(fp, prog_cb)
            elif ext in (".log", ".txt"):
                self._parse_text(fp, prog_cb)
            else:
                # Try CSV first, then text
                try: self._parse_csv(fp, prog_cb)
                except: self._parse_text(fp, prog_cb)
        except Exception as e:
            self.errors.append({"file":str(fp),"error":str(e)})

    def _base_event(self, source_file):
        return {"source_file":str(source_file),"event_id":"","time":"","provider":"",
                "level":"","keywords":"","channel":"","computer":"","message":"","raw":""}

    def _parse_evtx(self, fp, prog_cb):
        if not _ensure_evtx():
            self.errors.append({"file":str(fp),"error":"python-evtx could not be installed. Run: pip install python-evtx"})
            return
        with evtx.Evtx(str(fp)) as log:
            count = 0
            for record in log.records():
                if self.stop_requested: return
                ev = self._base_event(fp.name)
                try:
                    xml_str = record.xml()
                    ev["raw"] = xml_str[:500]
                    root = ET.fromstring(xml_str)
                    sys_el = root.find(f"{EVTX_NS}System")
                    if sys_el is not None:
                        eid_el = sys_el.find(f"{EVTX_NS}EventID")
                        if eid_el is not None: ev["event_id"] = eid_el.text or ""
                        tc_el = sys_el.find(f"{EVTX_NS}TimeCreated")
                        if tc_el is not None: ev["time"] = tc_el.get("SystemTime","")
                        prov_el = sys_el.find(f"{EVTX_NS}Provider")
                        if prov_el is not None: ev["provider"] = prov_el.get("Name","")
                        lv_el = sys_el.find(f"{EVTX_NS}Level")
                        if lv_el is not None:
                            lv_map = {"0":"LogAlways","1":"Critical","2":"Error","3":"Warning","4":"Information","5":"Verbose"}
                            ev["level"] = lv_map.get(lv_el.text, lv_el.text or "")
                        kw_el = sys_el.find(f"{EVTX_NS}Keywords")
                        if kw_el is not None: ev["keywords"] = kw_el.text or ""
                        ch_el = sys_el.find(f"{EVTX_NS}Channel")
                        if ch_el is not None: ev["channel"] = ch_el.text or ""
                        comp_el = sys_el.find(f"{EVTX_NS}Computer")
                        if comp_el is not None: ev["computer"] = comp_el.text or ""
                    ed_el = root.find(f"{EVTX_NS}EventData")
                    if ed_el is not None:
                        parts = []
                        for data in ed_el.findall(f"{EVTX_NS}Data"):
                            nm = data.get("Name",""); val = data.text or ""
                            if nm: parts.append(f"{nm}={val}")
                            elif val: parts.append(val)
                        ev["message"] = "; ".join(parts)[:500]
                except Exception as e:
                    ev["message"] = f"Parse error: {e}"
                self.events.append(ev); count += 1
                if prog_cb and count % 200 == 0: prog_cb(count, fp.name)

    def _parse_csv(self, fp, prog_cb):
        # Read raw bytes to detect encoding
        raw = open(fp, 'rb').read(4096)
        enc = 'utf-8'
        if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
            enc = 'utf-16'
        elif raw[:3] == b'\xef\xbb\xbf':
            enc = 'utf-8-sig'
        # Detect delimiter (comma, tab, semicolon, pipe)
        sample = raw[:2048].decode(enc, errors='replace')
        delim = ','
        for d in ['\t', ';', '|']:
            if sample.count(d) > sample.count(delim):
                delim = d
        with open(fp, 'r', encoding=enc, errors='replace') as f:
            reader = csv.DictReader(f, delimiter=delim)
            if not reader.fieldnames:
                raise ValueError("Empty or invalid CSV")
            # CRITICAL: Clean ALL field names - strip BOM (\ufeff), quotes, whitespace
            clean_fn = []
            for fn in reader.fieldnames:
                c = fn.strip().strip('\ufeff').strip('"').strip("'").strip()
                clean_fn.append(c)
            reader.fieldnames = clean_fn
            count = 0
            for row in reader:
                if self.stop_requested: return
                ev = self._base_event(fp.name)
                # Clean keys: strip BOM/quotes/whitespace, lowercase
                lrow = {}
                for k, v in row.items():
                    ck = (k or "").strip().strip('\ufeff').strip('"').strip("'").strip().lower()
                    lrow[ck] = (v or "").strip().strip('"').strip("'").strip()
                ev["event_id"] = (lrow.get("event id") or lrow.get("eventid") or
                                  lrow.get("event_id") or lrow.get("id") or "").strip()
                ev["time"] = (lrow.get("date and time") or lrow.get("timecreated") or
                              lrow.get("time") or lrow.get("timestamp") or
                              lrow.get("datetime") or lrow.get("date") or "").strip()
                ev["provider"] = (lrow.get("source") or lrow.get("provider") or
                                  lrow.get("providername") or lrow.get("provider name") or "").strip()
                ev["level"] = (lrow.get("level") or lrow.get("type") or
                               lrow.get("severity") or "").strip()
                ev["keywords"] = (lrow.get("keywords") or "").strip()
                ev["channel"] = (lrow.get("log name") or lrow.get("logname") or
                                 lrow.get("channel") or lrow.get("log") or "").strip()
                ev["computer"] = (lrow.get("computer") or lrow.get("computername") or
                                  lrow.get("machine") or lrow.get("hostname") or "").strip()
                ev["message"] = (lrow.get("description") or lrow.get("message") or
                                 lrow.get("task category") or "")[:500].strip()
                ev["raw"] = str(row)[:500]
                self.events.append(ev); count += 1
                if prog_cb and count % 500 == 0: prog_cb(count, fp.name)

    def _parse_xml(self, fp, prog_cb):
        try:
            tree = ET.parse(str(fp)); root = tree.getroot()
        except ET.ParseError:
            # Try wrapping in root element for fragments
            with open(fp,'r',encoding='utf-8',errors='replace') as f:
                content = f"<Events>{f.read()}</Events>"
            root = ET.fromstring(content)
        count = 0
        for event_el in root.iter():
            if self.stop_requested: return
            tag = event_el.tag.split("}")[-1] if "}" in event_el.tag else event_el.tag
            if tag != "Event": continue
            ev = self._base_event(fp.name)
            ns = ""
            # Detect namespace
            if event_el.tag.startswith("{"): ns = event_el.tag.split("}")[0] + "}"
            sys_el = event_el.find(f"{ns}System")
            if sys_el is not None:
                eid_el = sys_el.find(f"{ns}EventID")
                if eid_el is not None: ev["event_id"] = eid_el.text or ""
                tc_el = sys_el.find(f"{ns}TimeCreated")
                if tc_el is not None: ev["time"] = tc_el.get("SystemTime","")
                prov_el = sys_el.find(f"{ns}Provider")
                if prov_el is not None: ev["provider"] = prov_el.get("Name","")
                lv_el = sys_el.find(f"{ns}Level")
                if lv_el is not None:
                    lv_map = {"0":"LogAlways","1":"Critical","2":"Error","3":"Warning","4":"Information","5":"Verbose"}
                    ev["level"] = lv_map.get(lv_el.text, lv_el.text or "")
                ch_el = sys_el.find(f"{ns}Channel")
                if ch_el is not None: ev["channel"] = ch_el.text or ""
                comp_el = sys_el.find(f"{ns}Computer")
                if comp_el is not None: ev["computer"] = comp_el.text or ""
            ed_el = event_el.find(f"{ns}EventData")
            if ed_el is not None:
                parts = []
                for data in ed_el:
                    nm = data.get("Name",""); val = data.text or ""
                    if nm: parts.append(f"{nm}={val}")
                    elif val: parts.append(val)
                ev["message"] = "; ".join(parts)[:500]
            ev["raw"] = ET.tostring(event_el, encoding='unicode')[:500]
            self.events.append(ev); count += 1
            if prog_cb and count % 200 == 0: prog_cb(count, fp.name)

    def _parse_text(self, fp, prog_cb):
        """Parse generic text log files with common timestamp patterns."""
        patterns = [
            # Syslog-style: "Feb 14 10:30:22 hostname service[pid]: message"
            re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'),
            # ISO timestamp: "2025-01-15T10:30:22 ..."
            re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+(\S+)\s+(\S+)\s*(.*)$'),
            # Windows-style: "01/15/2025 10:30:22 AM,Source,EventID,Level,Message"
            re.compile(r'^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*\w*),([^,]*),([^,]*),([^,]*),(.*)$'),
            # Generic timestamp + message
            re.compile(r'^(\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[?(\w+)\]?\s*(.*)$'),
        ]
        with open(fp, 'r', encoding='utf-8', errors='replace') as f:
            count = 0
            for line in f:
                if self.stop_requested: return
                line = line.rstrip()
                if not line: continue
                ev = self._base_event(fp.name)
                matched = False
                for i, pat in enumerate(patterns):
                    m = pat.match(line)
                    if m:
                        g = m.groups()
                        if i == 0:  # syslog
                            ev["time"],ev["computer"],ev["provider"],ev["message"] = g[0],g[1],g[2],g[3]
                        elif i == 1:  # ISO
                            ev["time"],ev["computer"],ev["provider"],ev["message"] = g[0],g[1],g[2],g[3]
                        elif i == 2:  # Windows-style
                            ev["time"],ev["provider"],ev["event_id"],ev["level"],ev["message"] = g
                        elif i == 3:  # generic
                            ev["time"],ev["level"],ev["message"] = g[0],g[1],g[2]
                        matched = True; break
                if not matched:
                    ev["message"] = line; ev["time"] = ""
                ev["raw"] = line[:500]
                self.events.append(ev); count += 1
                if prog_cb and count % 1000 == 0: prog_cb(count, fp.name)

    def export_csv(self, filepath):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["Source File","Event ID","Time","Provider","Level","Channel",
                         "Computer","Message","Notable","Notable Category"])
            for ev in self.events:
                eid = ev.get("event_id","")
                notable = ""
                notable_cat = ""
                try:
                    eid_int = int(eid)
                    if eid_int in NOTABLE_EVENT_IDS:
                        n = NOTABLE_EVENT_IDS[eid_int]
                        notable = n[1]; notable_cat = n[2]
                except (ValueError, TypeError): pass
                w.writerow([ev.get("source_file",""),eid,ev.get("time",""),ev.get("provider",""),
                            ev.get("level",""),ev.get("channel",""),ev.get("computer",""),
                            ev.get("message","")[:300],notable,notable_cat])

    def stats(self):
        total = len(self.events)
        files = set(ev.get("source_file","") for ev in self.events)
        levels = {}; providers = {}; notable_counts = {"CRITICAL":0,"WARNING":0,"INFO":0}
        eid_counts = {}
        for ev in self.events:
            lv = ev.get("level","Unknown"); levels[lv] = levels.get(lv,0) + 1
            prov = ev.get("provider","Unknown"); providers[prov] = providers.get(prov,0) + 1
            eid = ev.get("event_id","")
            if eid: eid_counts[eid] = eid_counts.get(eid,0) + 1
            try:
                eid_int = int(eid)
                if eid_int in NOTABLE_EVENT_IDS:
                    cat = NOTABLE_EVENT_IDS[eid_int][2]
                    notable_counts[cat] = notable_counts.get(cat,0) + 1
            except (ValueError, TypeError): pass
        # Top event IDs
        top_eids = sorted(eid_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        return {"total":total,"files":len(files),"file_names":sorted(files),
                "levels":levels,"providers":providers,"notable":notable_counts,
                "top_event_ids":top_eids,"errors":len(self.errors)}

    def stop(self): self.stop_requested = True

