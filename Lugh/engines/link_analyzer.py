"""
Lugh v3.0 - Malicious Link Analyzer
"""
import re

# ══════════════════════════════════════════════════════════════
# MALICIOUS LINK ANALYZER
# ══════════════════════════════════════════════════════════════
SUSPICIOUS_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".top",".xyz",".buzz",".club",".icu",".work",
    ".cam",".monster",".surf",".click",".link",".rest",".fit",".gdn",".online",
    ".site",".store",".pw",".cc",".ws",".su",".bid",".trade",".win",".loan",
    ".racing",".review",".science",".stream",".download",".date",".faith",
    ".party",".cricket",".accountant",".zip",".mov",
}
URL_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","is.gd","buff.ly","ow.ly","rebrand.ly",
    "cutt.ly","tiny.cc","shorte.st","v.gd","qr.ae","lnkd.in","db.tt","adf.ly",
    "bl.ink","soo.gd","s2r.co","clck.ru","u.to","t.ly","rb.gy","shorturl.at",
    "za.gl","trib.al",
}
PHISH_KEYWORDS = [
    "login","signin","sign-in","verify","account","update","secure","banking",
    "confirm","password","credential","authenticate","validation","wallet",
    "paypal","microsoft","apple","google","amazon","netflix","facebook",
    "dropbox","instagram","linkedin","outlook","office365","onedrive",
    "wellsfargo","chase","citibank","bankofamerica",
]

class LinkAnalyzer:
    """Analyzes URLs for malicious indicators."""

    URL_RE = re.compile(
        r'(?:https?://|hxxps?://|ftp://|ftps://)'  # scheme
        r'(?:[^\s<>\[\]\"\'{}|\\^`\x00-\x1f])+',   # rest of URL
        re.I
    )
    BARE_RE = re.compile(
        r'(?<![/@\w])(?:[\w-]+\.)+(?:com|net|org|io|co|info|biz|us|uk|de|fr|ru|cn|br|'
        r'tk|ml|ga|cf|gq|top|xyz|buzz|club|icu|online|site|store|pw|cc|zip|mov)'
        r'(?:/[^\s<>\[\]\"\']*)?',
        re.I
    )

    def extract_urls(self, text):
        """Extract URLs from text, including defanged ones."""
        # Refang first
        t = text.replace("hxxp","http").replace("[.]",".").replace("[:]",":")
        t = t.replace("(dot)",".").replace("[dot]",".").replace("{.}",".")
        urls = set()
        for m in self.URL_RE.finditer(t): urls.add(m.group())
        for m in self.BARE_RE.finditer(t):
            u = m.group()
            if "." in u and not u.startswith("http"): u = "http://" + u
            urls.add(u)
        return sorted(urls)

    def analyze(self, url):
        r = {"url":url,"defanged":"","domain":"","tld":"","risk_score":0,
             "risk_level":"SAFE","flags":[],"details":{}}
        # Defang
        r["defanged"] = url.replace("http","hxxp").replace(".","{.}")
        # Parse domain
        try:
            clean = re.sub(r'^https?://', '', url, flags=re.I)
            host_port = clean.split("/")[0].split("?")[0].split("#")[0]
            host = host_port.split(":")[0]
            r["domain"] = host
            parts = host.split(".")
            if len(parts) >= 2:
                r["tld"] = "." + parts[-1]
                if len(parts[-1]) <= 3 and len(parts) >= 3:
                    r["tld"] = "." + ".".join(parts[-2:])
        except: pass
        score = 0
        # Check IP-based URL
        if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url, re.I):
            r["flags"].append(("IP-based URL", "HIGH", "URL uses raw IP address instead of domain"))
            score += 30
        # Check suspicious TLD
        dom = r["domain"].lower()
        for tld in SUSPICIOUS_TLDS:
            if dom.endswith(tld):
                r["flags"].append(("Suspicious TLD", "MEDIUM", f"TLD '{tld}' commonly abused"))
                score += 20; break
        # Check URL shortener
        for short in URL_SHORTENERS:
            if dom == short or dom.endswith("." + short):
                r["flags"].append(("URL Shortener", "MEDIUM", f"Redirector '{short}' hides true destination"))
                score += 15; break
        # Check excessive subdomains
        sub_count = len(r["domain"].split(".")) - 2
        if sub_count >= 3:
            r["flags"].append(("Excessive Subdomains", "MEDIUM", f"{sub_count+2} levels deep"))
            score += 15
        # Check phishing keywords in domain
        dom_lower = dom.replace("-","").replace(".","")
        for kw in PHISH_KEYWORDS:
            if kw in dom_lower and kw not in dom.split(".")[-2:-1]:
                r["flags"].append(("Phishing Keyword", "HIGH", f"Brand/keyword '{kw}' in domain"))
                score += 25; break
        # Check URL encoding
        encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        if encoded > 5:
            r["flags"].append(("Heavy URL Encoding", "MEDIUM", f"{encoded} encoded chars"))
            score += 15
        # Check suspicious port
        pm = re.search(r'://[^/]+:(\d+)', url)
        if pm:
            port = int(pm.group(1))
            if port not in (80,443,8080,8443):
                r["flags"].append(("Unusual Port", "MEDIUM", f"Port {port}"))
                score += 15
        # Check @ in URL (credential phishing)
        if "@" in url.split("//")[-1].split("/")[0]:
            r["flags"].append(("@ in URL", "HIGH", "Possible credential/redirect phishing"))
            score += 30
        # Check for data URI
        if url.lower().startswith("data:"):
            r["flags"].append(("Data URI", "HIGH", "Embedded data, no external server"))
            score += 25
        # Check double extensions
        path = url.split("?")[0]
        if re.search(r'\.\w{2,4}\.\w{2,4}$', path.split("/")[-1]):
            r["flags"].append(("Double Extension", "HIGH", "e.g. file.pdf.exe"))
            score += 25
        # Check unicode/homograph in domain
        try:
            ascii_dom = r["domain"].encode("ascii")
        except UnicodeEncodeError:
            r["flags"].append(("Unicode/IDN Domain", "HIGH", "Non-ASCII characters (possible homograph)"))
            score += 30
        # Check for very long URL (>200 chars)
        if len(url) > 200:
            r["flags"].append(("Very Long URL", "LOW", f"{len(url)} chars"))
            score += 5
        # Calculate risk
        r["risk_score"] = min(score, 100)
        if score >= 60: r["risk_level"] = "CRITICAL"
        elif score >= 35: r["risk_level"] = "HIGH"
        elif score >= 15: r["risk_level"] = "MEDIUM"
        elif score > 0: r["risk_level"] = "LOW"
        else: r["risk_level"] = "SAFE"
        return r

    def analyze_bulk(self, text):
        urls = self.extract_urls(text)
        return [self.analyze(u) for u in urls]

