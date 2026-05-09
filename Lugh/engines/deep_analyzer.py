"""
Lugh v3.0 - Deep Analyzer (Windows PE / General Binary)
"""
import struct, math, re, os
from pathlib import Path
from datetime import datetime, timezone

# ══════════════════════════════════════════════════════════════
# DEEP ANALYZER ENGINE  (Windows PE / General Binary)
# ══════════════════════════════════════════════════════════════
SUSPICIOUS_APIS = [
    "VirtualAlloc","VirtualAllocEx","VirtualProtect","WriteProcessMemory",
    "CreateRemoteThread","NtUnmapViewOfSection","QueueUserAPC",
    "SetThreadContext","ResumeThread","IsDebuggerPresent","CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess","GetTickCount","Sleep","OutputDebugString",
    "CreateProcess","ShellExecute","WinExec","URLDownloadToFile",
    "InternetOpen","HttpSendRequest","WSAStartup","connect","send","recv",
    "RegSetValueEx","RegCreateKey","CreateService","OpenSCManager",
    "CryptEncrypt","CryptDecrypt","CryptAcquireContext","CryptGenKey",
    "FindFirstFile","FindNextFile","GetWindowsDirectory","GetSystemDirectory",
    "GetTempPath","CreateFile","ReadFile","WriteFile","DeleteFile",
    "AdjustTokenPrivileges","LookupPrivilegeValue","OpenProcessToken",
    "CreateToolhelp32Snapshot","Process32First","Process32Next",
    "LoadLibrary","GetProcAddress","FreeLibrary",
]

SUSPICIOUS_STRINGS_PAT = [
    (r'https?://[\w./-]+', "URL"),
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "IP Address"),
    (r'[A-Za-z]:\\[\w\\. -]+', "File Path"),
    (r'HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)[\\A-Za-z_0-9]*', "Registry Key"),
    (r'(\w+\.exe|\w+\.dll|\w+\.bat|\w+\.cmd|\w+\.ps1|\w+\.vbs)', "Executable Reference"),
    (r'cmd\.exe|powershell|wscript|cscript|mshta|rundll32', "Shell/LOLBin"),
]

class DeepAnalyzer:
    """Analyzes PE (Windows) executables and general binaries."""

    def analyze(self, filepath):
        fp = Path(filepath)
        r = {"filepath":str(fp),"filename":fp.name,"size":0,"hashes":{},"is_pe":False,
             "pe_info":{},"entropy":0.0,"section_entropy":[],"strings":[],"suspicious_apis":[],
             "suspicious_strings":[],"error":None}
        try:
            data = fp.read_bytes(); r["size"] = len(data)
        except Exception as e:
            r["error"] = str(e); return r
        # Hashes
        r["hashes"] = {"MD5":hashlib.md5(data).hexdigest(),"SHA1":hashlib.sha1(data).hexdigest(),
                        "SHA256":hashlib.sha256(data).hexdigest()}
        # Whole-file entropy
        r["entropy"] = self._entropy(data)
        # PE parsing
        if len(data) >= 64 and data[:2] == b'MZ':
            r["is_pe"] = True
            try: self._parse_pe(data, r)
            except Exception as e: r["pe_info"]["parse_error"] = str(e)
        # String extraction
        r["strings"] = self._extract_strings(data)
        # Suspicious API matches
        api_lower = {a.lower():a for a in SUSPICIOUS_APIS}
        for s in r["strings"]:
            sl = s.lower()
            if sl in api_lower: r["suspicious_apis"].append(api_lower[sl])
        # Suspicious patterns
        text = "\n".join(r["strings"])
        for pat, desc in SUSPICIOUS_STRINGS_PAT:
            for m in re.finditer(pat, text, re.I):
                r["suspicious_strings"].append({"type":desc,"value":m.group()})
        # Deduplicate
        seen = set()
        dedup = []
        for s in r["suspicious_strings"]:
            k = (s["type"], s["value"])
            if k not in seen: seen.add(k); dedup.append(s)
        r["suspicious_strings"] = dedup
        return r

    def _entropy(self, data):
        if not data: return 0.0
        freq = [0]*256
        for b in data: freq[b] += 1
        ln = len(data); ent = 0.0
        for f in freq:
            if f > 0:
                p = f / ln; ent -= p * math.log2(p)
        return round(ent, 4)

    def _parse_pe(self, data, r):
        pe = r["pe_info"]
        # DOS header -> PE offset
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b'PE\x00\x00':
            pe["valid_pe"] = False; return
        pe["valid_pe"] = True
        # COFF header
        machine = struct.unpack_from('<H', data, pe_off+4)[0]
        machines = {0x14c:"x86 (i386)",0x8664:"x64 (AMD64)",0x1c0:"ARM",0xAA64:"ARM64"}
        pe["machine"] = machines.get(machine, f"0x{machine:04X}")
        num_sections = struct.unpack_from('<H', data, pe_off+6)[0]
        pe["num_sections"] = num_sections
        timestamp = struct.unpack_from('<I', data, pe_off+8)[0]
        try: pe["compile_time"] = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
        except: pe["compile_time"] = f"raw: {timestamp}"
        opt_hdr_size = struct.unpack_from('<H', data, pe_off+20)[0]
        chars = struct.unpack_from('<H', data, pe_off+22)[0]
        flags = []
        if chars & 0x0002: flags.append("EXECUTABLE")
        if chars & 0x2000: flags.append("DLL")
        if chars & 0x0020: flags.append("LARGE_ADDRESS_AWARE")
        if chars & 0x0100: flags.append("32BIT")
        pe["characteristics"] = flags
        # Optional header
        opt_off = pe_off + 24
        if opt_off + 2 <= len(data):
            magic = struct.unpack_from('<H', data, opt_off)[0]
            pe["pe_type"] = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else f"0x{magic:04X}"
            if magic == 0x10B and opt_off+40 <= len(data):
                pe["image_base"] = f"0x{struct.unpack_from('<I', data, opt_off+28)[0]:08X}"
                pe["entry_point"] = f"0x{struct.unpack_from('<I', data, opt_off+16)[0]:08X}"
            elif magic == 0x20B and opt_off+48 <= len(data):
                pe["image_base"] = f"0x{struct.unpack_from('<Q', data, opt_off+24)[0]:016X}"
                pe["entry_point"] = f"0x{struct.unpack_from('<I', data, opt_off+16)[0]:08X}"
        # Sections
        sec_off = opt_off + opt_hdr_size
        for i in range(num_sections):
            so = sec_off + i * 40
            if so + 40 > len(data): break
            name = data[so:so+8].rstrip(b'\x00').decode('ascii','replace')
            vsize = struct.unpack_from('<I', data, so+8)[0]
            rsize = struct.unpack_from('<I', data, so+16)[0]
            rptr = struct.unpack_from('<I', data, so+20)[0]
            sec_data = data[rptr:rptr+rsize] if rptr+rsize <= len(data) else b''
            ent = self._entropy(sec_data) if sec_data else 0.0
            r["section_entropy"].append({"name":name,"virtual_size":vsize,"raw_size":rsize,"entropy":ent})

    def _extract_strings(self, data, min_len=5):
        """Extract ASCII and wide strings."""
        strs = set()
        # ASCII
        for m in re.finditer(rb'[\x20-\x7E]{%d,}' % min_len, data):
            strs.add(m.group().decode('ascii','replace'))
        # UTF-16 LE
        for m in re.finditer(rb'(?:[\x20-\x7E]\x00){%d,}' % min_len, data):
            try: strs.add(m.group().decode('utf-16-le').rstrip('\x00'))
            except: pass
        return sorted(strs)

