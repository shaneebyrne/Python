"""
Lugh v3.0 - YARA Engine Wrapper
"""
import os
from pathlib import Path

try:
    import yara; HAS_YARA = True
except ImportError:
    HAS_YARA = False; yara = None

# ══════════════════════════════════════════════════════════════
# YARA ENGINE WRAPPER
# ══════════════════════════════════════════════════════════════
YARA_TEMPLATES = {
"Suspicious PE": """rule Suspicious_PE {
    meta:
        description = "Detects PE with high-entropy section or suspicious imports"
        author = "Lugh"
    strings:
        $mz = { 4D 5A }
        $api1 = "VirtualAllocEx" ascii wide nocase
        $api2 = "WriteProcessMemory" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase
        $api4 = "NtUnmapViewOfSection" ascii wide nocase
    condition:
        $mz at 0 and 2 of ($api*)
}""",
"Encoded Script": """rule Encoded_Script {
    meta:
        description = "Detects base64-encoded PowerShell or script blocks"
        author = "Lugh"
    strings:
        $b64ps = /[A-Za-z0-9+\\/]{40,}={0,2}/ ascii
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-encodedcommand" ascii wide nocase
        $ps3 = "-enc " ascii wide nocase
        $ps4 = "FromBase64String" ascii wide nocase
    condition:
        any of ($ps*) and $b64ps
}""",
"Web Shell": """rule Web_Shell_Generic {
    meta:
        description = "Generic web shell detection"
        author = "Lugh"
    strings:
        $php1 = "eval(" ascii nocase
        $php2 = "base64_decode(" ascii nocase
        $php3 = "system(" ascii nocase
        $php4 = "exec(" ascii nocase
        $php5 = "passthru(" ascii nocase
        $php6 = "shell_exec(" ascii nocase
        $asp1 = "Execute(" ascii nocase
        $asp2 = "CreateObject" ascii nocase
    condition:
        2 of them
}""",
"Ransomware Indicators": """rule Ransomware_Indicators {
    meta:
        description = "Common ransomware behavioral indicators"
        author = "Lugh"
    strings:
        $r1 = "vssadmin delete shadows" ascii wide nocase
        $r2 = "bcdedit /set" ascii wide nocase
        $r3 = "wbadmin delete" ascii wide nocase
        $r4 = "CryptEncrypt" ascii wide
        $r5 = ".onion" ascii wide
        $r6 = "YOUR FILES HAVE BEEN" ascii wide nocase
        $r7 = "DECRYPT" ascii wide nocase
        $r8 = "BITCOIN" ascii wide nocase
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypto" ascii
    condition:
        3 of them
}""",
"Empty Template": """rule My_Rule {
    meta:
        description = "Custom rule"
        author = "Analyst"
        date = "2026-01-01"
    strings:
        $s1 = "example" ascii wide nocase
    condition:
        $s1
}""",
}

class YaraEngine:
    """Wrapper around yara-python for rule compilation and scanning."""

    def __init__(self):
        self.compiled = None; self.last_error = None

    def compile_source(self, source):
        if not HAS_YARA:
            self.last_error = "yara-python not installed.\npip install yara-python"; return False
        try:
            self.compiled = yara.compile(source=source); self.last_error = None; return True
        except Exception as e:
            self.last_error = str(e); self.compiled = None; return False

    def compile_file(self, filepath):
        if not HAS_YARA:
            self.last_error = "yara-python not installed.\npip install yara-python"; return False
        try:
            self.compiled = yara.compile(filepath=filepath); self.last_error = None; return True
        except Exception as e:
            self.last_error = str(e); self.compiled = None; return False

    def scan_file(self, filepath):
        if not self.compiled: return []
        try:
            matches = self.compiled.match(filepath=filepath)
            results = []
            for m in matches:
                strs = []
                for s in m.strings:
                    for inst in s.instances:
                        strs.append({"offset":inst.offset,"identifier":s.identifier,
                                     "data":inst.matched_data[:64].hex()})
                results.append({"rule":m.rule,"tags":list(m.tags),"meta":dict(m.meta),"strings":strs})
            return results
        except Exception as e:
            self.last_error = str(e); return []

    def scan_dir(self, dirpath, recursive=True, prog_cb=None):
        results = []; files = []
        dp = Path(dirpath)
        try:
            if recursive:
                for root, _, fns in os.walk(dp):
                    for fn in fns: files.append(Path(root)/fn)
            else: files = [f for f in dp.iterdir() if f.is_file()]
        except PermissionError: pass
        for i, fp in enumerate(files):
            try:
                fmatches = self.scan_file(str(fp))
                if fmatches: results.append({"file":str(fp),"matches":fmatches})
            except: pass
            if prog_cb: prog_cb(i+1, len(files))
        return results

