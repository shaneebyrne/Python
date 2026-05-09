"""
Lugh v3.0 - Homograph / IDN Attack Detector
"""
import unicodedata

# ══════════════════════════════════════════════════════════════
# HOMOGRAPH ENGINE
# ══════════════════════════════════════════════════════════════
HOMOGLYPH_MAP = {
    "CYRILLIC": [
        ("\u0430","a","Cyrillic Small A"),("\u0410","A","Cyrillic Capital A"),
        ("\u0435","e","Cyrillic Small Ie"),("\u0415","E","Cyrillic Capital Ie"),
        ("\u043E","o","Cyrillic Small O"),("\u041E","O","Cyrillic Capital O"),
        ("\u0440","p","Cyrillic Small Er"),("\u0420","P","Cyrillic Capital Er"),
        ("\u0441","c","Cyrillic Small Es"),("\u0421","C","Cyrillic Capital Es"),
        ("\u0443","y","Cyrillic Small U"),("\u0423","Y","Cyrillic Capital U"),
        ("\u0445","x","Cyrillic Small Kha"),("\u0425","X","Cyrillic Capital Kha"),
        ("\u0455","s","Cyrillic Small Dze"),("\u0405","S","Cyrillic Capital Dze"),
        ("\u0456","i","Cyrillic Small I"),("\u0406","I","Cyrillic Capital I"),
        ("\u0458","j","Cyrillic Small Je"),("\u0408","J","Cyrillic Capital Je"),
        ("\u04BB","h","Cyrillic Small Shha"),("\u04BA","H","Cyrillic Capital Shha"),
        ("\u0432","B","Cyrillic Small Ve"),("\u043C","m","Cyrillic Small Em"),
        ("\u041C","M","Cyrillic Capital Em"),("\u043D","H","Cyrillic Small En"),
        ("\u0442","T","Cyrillic Small Te"),("\u0422","T","Cyrillic Capital Te"),
        ("\u043A","k","Cyrillic Small Ka"),("\u041A","K","Cyrillic Capital Ka"),
    ],
    "GREEK": [
        ("\u03B1","a","Greek Alpha"),("\u0391","A","Greek Capital Alpha"),
        ("\u03B5","e","Greek Epsilon"),("\u0395","E","Greek Capital Epsilon"),
        ("\u03B7","n","Greek Eta"),("\u0397","H","Greek Capital Eta"),
        ("\u03B9","i","Greek Iota"),("\u0399","I","Greek Capital Iota"),
        ("\u03BA","k","Greek Kappa"),("\u039A","K","Greek Capital Kappa"),
        ("\u03BF","o","Greek Omicron"),("\u039F","O","Greek Capital Omicron"),
        ("\u03C1","p","Greek Rho"),("\u03A1","P","Greek Capital Rho"),
        ("\u03C4","t","Greek Tau"),("\u03A4","T","Greek Capital Tau"),
        ("\u03C5","u","Greek Upsilon"),("\u03A5","Y","Greek Capital Upsilon"),
        ("\u03C7","x","Greek Chi"),("\u03A7","X","Greek Capital Chi"),
        ("\u03BD","v","Greek Nu"),("\u039D","N","Greek Capital Nu"),
    ],
    "LATIN_EXT": [
        ("\u00E0","a","A+Grave"),("\u00E1","a","A+Acute"),("\u00E2","a","A+Circumflex"),
        ("\u00E4","a","A+Diaeresis"),("\u00E9","e","E+Acute"),("\u00E8","e","E+Grave"),
        ("\u00EA","e","E+Circumflex"),("\u00ED","i","I+Acute"),("\u00F3","o","O+Acute"),
        ("\u00F6","o","O+Diaeresis"),("\u00FA","u","U+Acute"),("\u00FC","u","U+Diaeresis"),
        ("\u0131","i","Dotless I"),("\u0142","l","L+Stroke"),
    ],
    "OTHER": [
        ("\u2013","-","En Dash"),("\u2014","-","Em Dash"),
        ("\uFF0E",".","Fullwidth Stop"),("\uFF20","@","Fullwidth At"),
        ("\u2044","/","Fraction Slash"),("\u0251","a","Latin Alpha"),
    ],
    "FULLWIDTH": [
        ("\uFF41","a","FW a"),("\uFF42","b","FW b"),("\uFF43","c","FW c"),
        ("\uFF44","d","FW d"),("\uFF45","e","FW e"),("\uFF46","f","FW f"),
        ("\uFF47","g","FW g"),("\uFF48","h","FW h"),("\uFF49","i","FW i"),
        ("\uFF4A","j","FW j"),("\uFF4B","k","FW k"),("\uFF4C","l","FW l"),
        ("\uFF4D","m","FW m"),("\uFF4E","n","FW n"),("\uFF4F","o","FW o"),
        ("\uFF50","p","FW p"),("\uFF51","q","FW q"),("\uFF52","r","FW r"),
        ("\uFF53","s","FW s"),("\uFF54","t","FW t"),("\uFF55","u","FW u"),
        ("\uFF56","v","FW v"),("\uFF57","w","FW w"),("\uFF58","x","FW x"),
        ("\uFF59","y","FW y"),("\uFF5A","z","FW z"),
    ],
}
CONFUSABLES_LOOKUP = {}
for _sn, _cl in HOMOGLYPH_MAP.items():
    for _lk, _le, _ds in _cl:
        CONFUSABLES_LOOKUP[_lk] = (_le, _sn, _ds)

COMMON_TARGETS = [
    "google.com","microsoft.com","apple.com","amazon.com","facebook.com",
    "paypal.com","netflix.com","chase.com","wellsfargo.com","bankofamerica.com",
    "linkedin.com","twitter.com","instagram.com","dropbox.com","icloud.com",
    "office.com","outlook.com","live.com","yahoo.com","gmail.com",
    "github.com","slack.com","zoom.us",
]

class HomographDetector:
    @staticmethod
    def get_char_script(char):
        try:
            name = unicodedata.name(char, "UNKNOWN")
            if char in string.ascii_letters: return "LATIN"
            if char in string.digits or char in string.punctuation or char in " \t\n\r": return "COMMON"
            for pfx in ["CYRILLIC","GREEK","ARABIC","HEBREW","HANGUL","CJK","HIRAGANA",
                         "KATAKANA","THAI","DEVANAGARI","ARMENIAN","GEORGIAN","FULLWIDTH","MATHEMATICAL"]:
                if pfx in name: return pfx
            if "LATIN" in name:
                return "LATIN_EXT" if any(m in name for m in ["WITH","SMALL CAPITAL","MODIFIER","TURNED"]) else "LATIN"
            return f"OTHER({name[:15]})"
        except: return "UNKNOWN"

    @staticmethod
    def analyze_text(text):
        r = {"input":text,"clean_text":"","is_safe":True,"risk_level":"SAFE",
             "findings":[],"scripts_detected":set(),"char_analysis":[],
             "mixed_script":False,"punycode":"","deceptive_target":None}
        if not text.strip(): return r
        domain = text.strip()
        if "://" in domain: domain = domain.split("://",1)[1]
        if "/" in domain: domain = domain.split("/")[0]
        if "@" in domain: domain = domain.rsplit("@",1)[1]
        clean, scripts, suspicious = [], set(), []
        for i, ch in enumerate(text):
            sc = HomographDetector.get_char_script(ch); scripts.add(sc)
            info = {"position":i,"character":ch,"unicode":f"U+{ord(ch):04X}",
                    "name":unicodedata.name(ch,"UNKNOWN"),"script":sc,
                    "category":unicodedata.category(ch),"is_suspicious":False,
                    "latin_equivalent":None,"description":None}
            if ch in CONFUSABLES_LOOKUP:
                le, cs, ds = CONFUSABLES_LOOKUP[ch]
                info.update(is_suspicious=True,latin_equivalent=le,description=ds)
                clean.append(le); suspicious.append(info)
            else: clean.append(ch)
            r["char_analysis"].append(info)
        r["clean_text"] = "".join(clean)
        r["scripts_detected"] = scripts - {"COMMON"}
        if len(scripts - {"COMMON"}) > 1: r["mixed_script"] = True
        if suspicious:
            r["is_safe"] = False
            for s in suspicious:
                r["findings"].append({"type":"CONFUSABLE","position":s["position"],
                    "character":s["character"],"unicode":s["unicode"],
                    "looks_like":s["latin_equivalent"],"script":s["script"],"description":s["description"]})
        if r["mixed_script"]:
            r["is_safe"] = False
            r["findings"].append({"type":"MIXED_SCRIPT","scripts":list(scripts-{"COMMON"})})
        try:
            dp = domain.split("/")[0].split("?")[0]
            if any(ord(c)>127 for c in dp):
                r["punycode"] = ".".join(
                    lb.encode("idna").decode("ascii") if any(ord(c)>127 for c in lb) else lb
                    for lb in dp.split("."))
        except: pass
        cl = r["clean_text"].lower()
        for t in COMMON_TARGETS:
            if t in cl or cl.endswith(t): r["deceptive_target"] = t; break
        if not suspicious and not r["mixed_script"]: r["risk_level"] = "SAFE"
        elif r.get("deceptive_target"): r["risk_level"] = "CRITICAL"
        elif len(suspicious) <= 2: r["risk_level"] = "MEDIUM"
        else: r["risk_level"] = "HIGH"
        return r

    @staticmethod
    def generate_examples(domain):
        subs = {'a':('\u0430','Cyrillic a'),'c':('\u0441','Cyrillic c'),
                'e':('\u0435','Cyrillic e'),'o':('\u043E','Cyrillic o'),
                'p':('\u0440','Cyrillic p'),'s':('\u0455','Cyrillic s'),
                'x':('\u0445','Cyrillic x'),'y':('\u0443','Cyrillic y'),
                'i':('\u0456','Cyrillic i')}
        ex = []; base = domain.lower().split(".")[0]; sfx = domain[len(base):]
        for i, ch in enumerate(base):
            if ch in subs:
                fk, ds = subs[ch]
                ex.append({"original":domain,"spoofed":base[:i]+fk+base[i+1:]+sfx,
                           "position":i,"original_char":ch,"replaced_with":fk,
                           "description":ds,"unicode":f"U+{ord(fk):04X}"})
        return ex

