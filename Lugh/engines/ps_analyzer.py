"""
Lugh v3.0 - PowerShell Static Analyzer
"""
import re, os
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# POWERSHELL STATIC ANALYZER
# ══════════════════════════════════════════════════════════════
PS_OBFUSCATION_PAT = [
    (r'-[Ee][Nn][Cc][Oo]?[Dd]?[Ee]?[Dd]?[Cc]?[Oo]?[Mm]?[Mm]?[Aa]?[Nn]?[Dd]?\b', "Encoded Command Flag"),
    (r'\[System\.Convert\]::FromBase64String', "Base64 Decode"),
    (r'\[System\.Text\.Encoding\]::\w+\.GetString', "String Decode"),
    (r'-replace\s*[\'\"]\w[\'\"],[\'\"]', "Character Replacement Chain"),
    (r'\$\w+\s*=\s*[\'\"][A-Za-z0-9+/=]{40,}[\'\"]', "Long Base64 Variable"),
    (r'(\$\w{1,2}\s*\+\s*){4,}', "String Concatenation Chain"),
    (r'\[char\]\s*\d+', "Char-code Obfuscation"),
    (r'-join\s*\(\s*[\'\"\d,\s]+\s*\|\s*%\s*\{', "Join/ForEach Deobfuscation"),
    (r'`[a-zA-Z]', "Backtick Obfuscation"),
    (r'\(\s*[\'\"][^\'\"]{1,3}[\'\"]\s*\+\s*[\'\"][^\'\"]{1,3}[\'\"]', "Micro-concat Obfuscation"),
]
PS_SUSPICIOUS_CMDLETS = [
    ("Invoke-Expression","iex","Code Execution - runs arbitrary code"),
    ("Invoke-Command","icm","Remote/local code execution"),
    ("Invoke-WebRequest","iwr","Web download"),
    ("Invoke-RestMethod","irm","REST API call (potential C2)"),
    ("Start-Process","saps","Process execution"),
    ("New-Object Net.WebClient","","WebClient download cradle"),
    ("DownloadString","","In-memory download execution"),
    ("DownloadFile","","File download to disk"),
    ("Start-BitsTransfer","","BITS download (evasion)"),
    ("Add-Type","","Compile/load .NET code at runtime"),
    ("New-Object IO.MemoryStream","","In-memory stream (fileless)"),
    ("New-Object IO.StreamReader","","Stream reading (fileless)"),
    ("Set-ItemProperty","sp","Registry/property modification"),
    ("New-ItemProperty","","Registry key creation"),
    ("Register-ScheduledTask","","Persistence via scheduled task"),
    ("New-Service","","Persistence via service creation"),
    ("Set-MpPreference","","Defender exclusion/config change"),
    ("Add-MpPreference","","Defender exclusion addition"),
    ("Stop-Service","","Service manipulation"),
    ("Disable-WindowsOptionalFeature","","Feature disabling"),
    ("Get-Process","gps","Process enumeration"),
    ("Get-WmiObject","gwmi","WMI queries (recon/execution)"),
    ("Get-CimInstance","gcim","CIM queries (recon)"),
    ("Get-Credential","","Credential harvesting prompt"),
    ("[Runtime.InteropServices.Marshal]","","Unmanaged memory access"),
    ("VirtualAlloc","","Win32 memory allocation"),
    ("CreateThread","","Win32 thread creation"),
    ("memset","","Memory write (shellcode)"),
    ("[Reflection.Assembly]::Load","","Assembly loading (fileless)"),
    ("ConvertTo-SecureString","","Secure string manipulation"),
    ("Get-Content","gc","File reading"),
    ("Out-File","","File writing"),
    ("Copy-Item","cp","File copy"),
    ("Remove-Item","rm","File/evidence deletion"),
    ("Clear-EventLog","","Log clearing (anti-forensics)"),
    ("wevtutil","","Event log manipulation"),
    ("[System.Net.Sockets.TcpClient]","","Raw TCP connection"),
    ("New-Object Net.Sockets.TcpClient","","TCP reverse shell pattern"),
]
PS_DANGER_PATTERNS = [
    (r'(Invoke-Expression|iex)\s*\(\s*(Invoke-WebRequest|iwr|New-Object\s+Net\.WebClient)', "Download Cradle (download + execute)"),
    (r'\$\w+\s*=\s*New-Object\s+Net\.WebClient.*?\.Download(String|File)', "WebClient Download"),
    (r'-WindowStyle\s+Hidden', "Hidden Window Execution"),
    (r'-ExecutionPolicy\s+(Bypass|Unrestricted)', "Execution Policy Bypass"),
    (r'-NoProfile\s+-NonInteractive', "Non-interactive (scripted attack)"),
    (r'AMSI.*Bypass|amsiInitFailed|AmsiUtils', "AMSI Bypass Attempt"),
    (r'Disable-.*Logging|Set-PSReadLine.*-HistorySavePath\s+""', "Logging Evasion"),
    (r'FromBase64String.*Invoke-Expression', "Base64 Decode + Execute"),
    (r'Invoke-Mimikatz|Invoke-Kerberoast|Invoke-BloodHound', "Known Attack Tool"),
    (r'New-Object\s+Net\.Sockets\.TcpClient.*\.GetStream', "Reverse Shell Pattern"),
    (r'Get-Content.*-Stream|Set-Content.*-Stream', "Alternate Data Stream Access"),
    (r'\$env:TEMP|\$env:APPDATA|\$env:LOCALAPPDATA', "Temp/AppData Path (staging)"),
    (r'Test-Path.*-PathType\s+Leaf.*Remove-Item', "File Check + Delete Pattern"),
    (r'whoami|hostname|ipconfig|systeminfo|net\s+user|net\s+group', "Reconnaissance Command"),
    (r'reg\s+(add|query|delete|export)', "Registry Manipulation via reg.exe"),
    (r'schtasks\s+/create', "Scheduled Task Creation"),
    (r'sc\s+(create|config|start)', "Service Manipulation via sc.exe"),
    (r'certutil.*-urlcache.*-split.*-f', "Certutil Download (LOLBin)"),
    (r'bitsadmin.*\/transfer', "BITSAdmin Download (LOLBin)"),
    (r'mshta\s+', "MSHTA Execution (LOLBin)"),
    (r'rundll32\s+', "Rundll32 Execution (LOLBin)"),
    (r'wmic\s+.*call\s+create', "WMIC Process Creation"),
]

class PowerShellAnalyzer:
    """Static analysis of PowerShell scripts for suspicious patterns."""

    def analyze(self, content, filename="<input>"):
        r = {"filename":filename,"lines":content.count('\n')+1,"size":len(content),
             "obfuscation":[],"suspicious_cmdlets":[],"danger_patterns":[],
             "strings":[],"variables":[],"comments":[],"functions":[],
             "score":0,"risk_level":"CLEAN","error":None}
        if not content.strip(): r["error"]="Empty input"; return r
        try: self._analyze(content, r)
        except Exception as e: r["error"]=str(e)
        return r

    def _analyze(self, content, r):
        # Extract comments
        for m in re.finditer(r'#.*$', content, re.M):
            r["comments"].append(m.group().strip()[:120])
        for m in re.finditer(r'<#.*?#>', content, re.S):
            r["comments"].append(m.group()[:120].replace('\n',' '))
        # Extract functions
        for m in re.finditer(r'function\s+([\w-]+)', content, re.I):
            r["functions"].append(m.group(1))
        # Extract variables
        for m in re.finditer(r'(\$[\w]+)\s*=', content):
            if m.group(1) not in r["variables"] and not m.group(1).startswith('$_'):
                r["variables"].append(m.group(1))
        # Extract strings
        for m in re.finditer(r'[\'\"]([^\'\"\n]{8,120})[\'\"]', content):
            r["strings"].append(m.group(1))
        # Check obfuscation patterns
        score = 0
        for pat, desc in PS_OBFUSCATION_PAT:
            matches = re.findall(pat, content, re.I|re.M)
            if matches:
                r["obfuscation"].append({"pattern":desc,"count":len(matches),"samples":[str(m)[:60] for m in matches[:3]]})
                score += len(matches) * 10
        # Check suspicious cmdlets
        content_lower = content.lower()
        for cmdlet, alias, desc in PS_SUSPICIOUS_CMDLETS:
            found = False
            if cmdlet.lower() in content_lower: found = True
            elif alias and alias.lower() in content_lower: found = True
            if found:
                r["suspicious_cmdlets"].append({"cmdlet":cmdlet,"alias":alias,"description":desc})
                score += 8
        # Check danger patterns
        for pat, desc in PS_DANGER_PATTERNS:
            matches = re.findall(pat, content, re.I|re.M|re.S)
            if matches:
                r["danger_patterns"].append({"pattern":desc,"count":len(matches),
                    "samples":[str(m)[:80] if isinstance(m,str) else str(m) for m in matches[:3]]})
                score += len(matches) * 20
        # Calculate risk
        r["score"] = min(score, 100)
        if score >= 60: r["risk_level"] = "CRITICAL"
        elif score >= 35: r["risk_level"] = "HIGH"
        elif score >= 15: r["risk_level"] = "MEDIUM"
        elif score > 0: r["risk_level"] = "LOW"
        else: r["risk_level"] = "CLEAN"

