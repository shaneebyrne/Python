"""
Lugh v3.0 - File Type Checker (Magic Number Scanner)
"""
import os
from pathlib import Path
from collections import Counter

# ══════════════════════════════════════════════════════════════
# FILE TYPE CHECKER ENGINE
# ══════════════════════════════════════════════════════════════
MAGIC_SIGS = [
    {"n":"JPEG","ext":[".jpg",".jpeg",".jpe",".jfif"],"m":"FFD8FF","o":0,"c":"Image"},
    {"n":"PNG","ext":[".png"],"m":"89504E470D0A1A0A","o":0,"c":"Image"},
    {"n":"GIF87a","ext":[".gif"],"m":"474946383761","o":0,"c":"Image"},
    {"n":"GIF89a","ext":[".gif"],"m":"474946383961","o":0,"c":"Image"},
    {"n":"BMP","ext":[".bmp",".dib"],"m":"424D","o":0,"c":"Image"},
    {"n":"TIFF (LE)","ext":[".tif",".tiff"],"m":"49492A00","o":0,"c":"Image"},
    {"n":"TIFF (BE)","ext":[".tif",".tiff"],"m":"4D4D002A","o":0,"c":"Image"},
    {"n":"WebP","ext":[".webp"],"m":"52494646","o":0,"c":"Image","s":"57454250","so":8},
    {"n":"ICO","ext":[".ico"],"m":"00000100","o":0,"c":"Image"},
    {"n":"PSD","ext":[".psd"],"m":"38425053","o":0,"c":"Image"},
    {"n":"PDF","ext":[".pdf"],"m":"25504446","o":0,"c":"Document"},
    {"n":"ZIP/OOXML","ext":[".zip",".docx",".xlsx",".pptx",".jar",".apk"],"m":"504B0304","o":0,"c":"Archive"},
    {"n":"ZIP Empty","ext":[".zip"],"m":"504B0506","o":0,"c":"Archive"},
    {"n":"MS Office OLE2","ext":[".doc",".xls",".ppt",".msg"],"m":"D0CF11E0A1B11AE1","o":0,"c":"Document"},
    {"n":"RTF","ext":[".rtf"],"m":"7B5C727466","o":0,"c":"Document"},
    {"n":"RAR v1.5+","ext":[".rar"],"m":"526172211A0700","o":0,"c":"Archive"},
    {"n":"RAR v5.0+","ext":[".rar"],"m":"526172211A070100","o":0,"c":"Archive"},
    {"n":"7-Zip","ext":[".7z"],"m":"377ABCAF271C","o":0,"c":"Archive"},
    {"n":"GZIP","ext":[".gz",".tgz"],"m":"1F8B08","o":0,"c":"Archive"},
    {"n":"BZIP2","ext":[".bz2"],"m":"425A68","o":0,"c":"Archive"},
    {"n":"XZ","ext":[".xz"],"m":"FD377A585A00","o":0,"c":"Archive"},
    {"n":"TAR","ext":[".tar"],"m":"7573746172","o":257,"c":"Archive"},
    {"n":"Windows EXE (MZ)","ext":[".exe",".dll",".sys",".drv",".ocx",".scr"],"m":"4D5A","o":0,"c":"Executable"},
    {"n":"ELF (Linux)","ext":[".elf",".so",".o",""],"m":"7F454C46","o":0,"c":"Executable"},
    {"n":"Mach-O 32","ext":[".dylib",""],"m":"FEEDFACE","o":0,"c":"Executable"},
    {"n":"Mach-O 64","ext":[".dylib",""],"m":"FEEDFACF","o":0,"c":"Executable"},
    {"n":"Java Class","ext":[".class"],"m":"CAFEBABE","o":0,"c":"Executable"},
    {"n":"Windows LNK","ext":[".lnk"],"m":"4C00000001140200","o":0,"c":"Executable"},
    {"n":"DEX (Android)","ext":[".dex"],"m":"6465780A","o":0,"c":"Executable"},
    {"n":"MP3 (ID3)","ext":[".mp3"],"m":"494433","o":0,"c":"Audio"},
    {"n":"MP3 (Sync)","ext":[".mp3"],"m":"FFFB","o":0,"c":"Audio"},
    {"n":"WAV","ext":[".wav"],"m":"52494646","o":0,"c":"Audio","s":"57415645","so":8},
    {"n":"FLAC","ext":[".flac"],"m":"664C6143","o":0,"c":"Audio"},
    {"n":"OGG","ext":[".ogg",".oga",".ogv"],"m":"4F676753","o":0,"c":"Audio"},
    {"n":"MIDI","ext":[".mid",".midi"],"m":"4D546864","o":0,"c":"Audio"},
    {"n":"MP4","ext":[".mp4",".m4a",".m4v"],"m":"66747970","o":4,"c":"Video"},
    {"n":"AVI","ext":[".avi"],"m":"52494646","o":0,"c":"Video","s":"41564920","so":8},
    {"n":"MKV/WebM","ext":[".mkv",".webm"],"m":"1A45DFA3","o":0,"c":"Video"},
    {"n":"FLV","ext":[".flv"],"m":"464C5601","o":0,"c":"Video"},
    {"n":"WMV/ASF","ext":[".wmv",".wma",".asf"],"m":"3026B2758E66CF11","o":0,"c":"Video"},
    {"n":"SQLite","ext":[".db",".sqlite",".sqlite3"],"m":"53514C69746520666F726D6174203300","o":0,"c":"Database"},
    {"n":"TrueType Font","ext":[".ttf"],"m":"00010000","o":0,"c":"Font"},
    {"n":"OpenType Font","ext":[".otf"],"m":"4F54544F","o":0,"c":"Font"},
    {"n":"WOFF","ext":[".woff"],"m":"774F4646","o":0,"c":"Font"},
    {"n":"WOFF2","ext":[".woff2"],"m":"774F4632","o":0,"c":"Font"},
    {"n":"CAB","ext":[".cab"],"m":"4D534346","o":0,"c":"Archive"},
    {"n":"ISO","ext":[".iso"],"m":"4344303031","o":32769,"c":"Disk Image"},
    {"n":"Python .pyc","ext":[".pyc"],"m":"420D0D0A","o":0,"c":"Compiled"},
    {"n":"CHM Help","ext":[".chm"],"m":"495453460300000060000000","o":0,"c":"Document"},
]

TEXT_PATS = {
    "Python":{".py":r'^(import |from |def |class |#!)'},
    "JavaScript":{".js":r'^(const |let |var |function |import |export )'},
    "TypeScript":{".ts":r'^(interface |type |enum |import )'},
    "C/C++":{".c":r'^#include ',".h":r'^#include ',".cpp":r'^#include ',".hpp":r'^#include '},
    "C#":{".cs":r'^(using |namespace )'},
    "Java":{".java":r'^(package |import java)'},
    "Go":{".go":r'^package '},
    "Rust":{".rs":r'^(use |fn |mod |pub |impl |struct |enum )'},
    "PowerShell":{".ps1":r'^(\$\w+|function |param|\[Cmdlet)'},
    "Batch":{".bat":r'^(@echo |rem |set |if )',".cmd":r'^(@echo |rem |set )'},
    "Shell":{".sh":r'^#!/bin/(ba)?sh',".bash":r'^#!/bin/bash'},
    "SQL":{".sql":r'^(SELECT|INSERT|CREATE|ALTER|DROP|-- )'},
    "JSON":{".json":r'^\s*[\{\[]'},
    "YAML":{".yml":r'^(---|\\w+: )',".yaml":r'^(---|\\w+: )'},
    "XML":{".xml":r'^<\\?xml '},
    "HTML":{".html":r'^(<!DOCTYPE|<html)',".htm":r'^(<!DOCTYPE|<html)'},
    "CSS":{".css":r'^\\s*[.#@*\\w].*\\{'},
    "Markdown":{".md":r'^# ',".markdown":r'^# '},
    "INI/Config":{".ini":r'^\\[\\w+\\]',".cfg":r'^\\[\\w+\\]',".conf":r'^\\[\\w+\\]'},
    "Log":{".log":r'^(\\d{4}-\\d{2}|\\[\\d)'},
}

DANGEROUS_EXTS = {".exe",".dll",".sys",".scr",".bat",".cmd",".com",".msi",".ps1",".vbs",".js",".wsf",".hta"}
IMAGE_EXTS = {".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".webp",".ico",".svg"}
DOC_EXTS = {".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pdf",".rtf",".txt"}

class FileTypeChecker:
    def __init__(self):
        self.results = []; self.stop_requested = False

    def read_header(self, fp, sz=65536):
        try:
            with open(fp, 'rb') as f: return f.read(sz)
        except: return None

    def detect_text(self, fp):
        ext = fp.suffix.lower()
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f: head = f.read(4096)
        except: return None
        for tname, extpats in TEXT_PATS.items():
            for text, pat in extpats.items():
                if ext == text:
                    return {"name":tname,"category":"Text/Source","extensions":list(extpats.keys())}
                try:
                    if re.search(pat, head, re.M|re.I):
                        return {"name":tname,"category":"Text/Source","extensions":list(extpats.keys())}
                except: pass
        # Generic text
        try:
            head[:1000].encode('ascii')
            return {"name":"Plain Text","category":"Text","extensions":[".txt"]}
        except: pass
        return None

    def identify(self, fp):
        r = {'filepath':str(fp),'filename':fp.name,'extension':fp.suffix.lower(),'size':0,
             'identified':False,'type_name':'Unknown','category':'Unknown',
             'extension_match':True,'mismatch_severity':None,'mismatch_description':None,
             'header_hex':'','error':None}
        try: r['size'] = fp.stat().st_size
        except: pass
        hdr = self.read_header(fp)
        if hdr is None: r['error']='Cannot read'; return r
        if len(hdr)==0: r['error']='Empty'; return r
        r['header_hex'] = hdr[:32].hex().upper()
        for sig in MAGIC_SIGS:
            mb = bytes.fromhex(sig['m']); off = sig.get('o',0)
            if off+len(mb) > len(hdr): continue
            if hdr[off:off+len(mb)] == mb:
                if 's' in sig:
                    sb = bytes.fromhex(sig['s']); so = sig.get('so',0)
                    if so+len(sb)>len(hdr) or hdr[so:so+len(sb)]!=sb: continue
                r['identified']=True; r['type_name']=sig['n']; r['category']=sig['c']
                ext = r['extension']
                if ext and ext not in [e.lower() for e in sig['ext']]:
                    r['extension_match']=False
                    r['mismatch_severity']=self._sev(sig,ext)
                    r['mismatch_description']=f"File is {sig['n']} but has '{ext}' extension"
                return r
        tm = self.detect_text(fp)
        if tm:
            r['identified']=True; r['type_name']=tm['name']; r['category']=tm['category']
            if r['extension'] and r['extension'] not in tm['extensions']:
                r['extension_match']=False; r['mismatch_severity']='Low'
                r['mismatch_description']=f"Content is {tm['name']} but ext is '{r['extension']}'"
        return r

    def _sev(self, sig, ext):
        if sig['c']=="Executable" and ext in IMAGE_EXTS|DOC_EXTS: return "Critical"
        if sig['c']=="Executable": return "High"
        if ext in DANGEROUS_EXTS: return "High"
        if ext in IMAGE_EXTS: return "Medium"
        return "Low"

    def scan_dir(self, d, recursive=True, prog_cb=None, file_cb=None):
        self.results=[]; self.stop_requested=False; files=[]
        try:
            if recursive:
                for root,_,fns in os.walk(d):
                    if self.stop_requested: break
                    for fn in fns: files.append(Path(root)/fn)
            else: files=[f for f in d.iterdir() if f.is_file()]
        except PermissionError: pass
        tot=len(files)
        for i,fp in enumerate(files):
            if self.stop_requested: break
            try:
                r=self.identify(fp); self.results.append(r)
                if file_cb: file_cb(r)
            except Exception as e:
                self.results.append({'filepath':str(fp),'filename':fp.name,'error':str(e)})
            if prog_cb: prog_cb(i+1, tot)
        return self.results

    def stop(self): self.stop_requested = True
    def suspicious(self): return [r for r in self.results if not r.get('extension_match',True)]
    def stats(self):
        t=len(self.results); idn=sum(1 for r in self.results if r.get('identified'))
        mis=sum(1 for r in self.results if not r.get('extension_match',True))
        err=sum(1 for r in self.results if r.get('error'))
        cats={}; sevs={}
        for r in self.results:
            c=r.get('category','Unknown'); cats[c]=cats.get(c,0)+1
            s=r.get('mismatch_severity'); 
            if s: sevs[s]=sevs.get(s,0)+1
        return {"total":t,"identified":idn,"mismatched":mis,"errors":err,"categories":cats,"severities":sevs}

