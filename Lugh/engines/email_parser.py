"""
Lugh v3.0 - Email Header Parser
"""
import re
from datetime import datetime, timezone, timedelta
from engines.email_data import ReceivedHop, AuthenticationResult, AntiSpamData, ParsedHeaders

# ══════════════════════════════════════════════════════════════
# EMAIL HEADER PARSER
# ══════════════════════════════════════════════════════════════
class EmailHeaderParser:
    TS_FMTS = ["%a, %d %b %Y %H:%M:%S %z","%d %b %Y %H:%M:%S %z",
               "%a, %d %b %Y %H:%M:%S %Z","%d %b %Y %H:%M:%S %Z","%a, %d %b %Y %H:%M:%S"]

    def parse(self, raw):
        pd = ParsedHeaders()
        uf = re.sub(r'\r?\n[ \t]+', ' ', raw)
        hd = {}; hdl = {}  # hd=original case, hdl=lowercase keys for lookup
        for ln in uf.split('\n'):
            ln = ln.strip()
            if ':' in ln:
                k,_,v = ln.partition(':'); k=k.strip(); v=v.strip()
                if k and not k.startswith(' '):
                    hd[k]=v; hdl[k.lower()]=v
        pd.summary = {}
        for k in ["Subject","From","To","Date","Message-ID","Reply-To","Return-Path","Content-Type"]:
            pd.summary[k] = hdl.get(k.lower(), "")
        pd.received_hops = self._hops(raw)
        pd.authentication = self._auth(hdl)
        pd.antispam = self._spam(hdl)
        ff=hdl.get("x-forefront-antispam-report","")
        if ff: pd.forefront_antispam = self._spairs(ff)
        ms=hdl.get("x-microsoft-antispam","")
        if ms: pd.microsoft_antispam = self._spairs(ms)
        for h in ["X-Mailer","X-Originating-IP","X-MS-Exchange-Organization-SCL",
                   "X-MS-Exchange-Organization-AuthSource","X-MS-Exchange-Organization-AuthAs",
                   "X-MS-Has-Attach","X-MS-Exchange-Organization-Network-Message-Id",
                   "X-MS-Exchange-CrossTenant-id","X-OriginatorOrg","MIME-Version","Thread-Topic"]:
            v = hdl.get(h.lower())
            if v: pd.other_headers[h]=v
        return pd

    def _hops(self, raw):
        hops=[]; recs=re.findall(r'Received:\s*(.*?)(?=\nReceived:|\n[A-Z][\w-]*:|\Z)',raw,re.I|re.S)
        for i,r in enumerate(reversed(recs)):
            h=ReceivedHop(hop_number=i+1,raw_header=r.strip())
            m=re.search(r'from\s+(\S+)',r,re.I);
            if m: h.from_host=m.group(1)
            m=re.search(r'by\s+(\S+)',r,re.I);
            if m: h.by_host=m.group(1)
            m=re.search(r'with\s+(\S+)',r,re.I);
            if m: h.with_protocol=m.group(1)
            m=re.search(r';\s*(.+?)$',r,re.M)
            if m:
                ts=re.sub(r'\s*\(.*?\)\s*',' ',m.group(1)).strip()
                for fmt in self.TS_FMTS:
                    try: h.timestamp=datetime.strptime(ts,fmt); break
                    except: continue
            hops.append(h)
        for i in range(1,len(hops)):
            if hops[i].timestamp and hops[i-1].timestamp:
                try:
                    t1,t2=hops[i-1].timestamp,hops[i].timestamp
                    if t1.tzinfo is None: t1=t1.replace(tzinfo=timezone.utc)
                    if t2.tzinfo is None: t2=t2.replace(tzinfo=timezone.utc)
                    d=(t2-t1).total_seconds(); hops[i].delay_seconds=d
                    if d<0: hops[i].delay=f"{abs(d):.0f}s(skew)"
                    elif d<60: hops[i].delay=f"{d:.0f}s"
                    elif d<3600: hops[i].delay=f"{d/60:.1f}m"
                    else: hops[i].delay=f"{d/3600:.1f}h"
                except: hops[i].delay="N/A"
        return hops

    def _auth(self, hd):
        a=AuthenticationResult(); ar=hd.get("authentication-results","")
        if ar:
            for fn,at in [("spf","spf"),("dkim","dkim"),("dmarc","dmarc"),("compauth","compauth")]:
                m=re.search(rf'{fn}=(\w+)',ar,re.I)
                if m: setattr(a,f"{at}_result",m.group(1))
                dm=re.search(rf'{fn}=\w+\s*\(([^)]+)\)',ar,re.I)
                if dm and hasattr(a,f"{at}_details"): setattr(a,f"{at}_details",dm.group(1))
            rm=re.search(r'reason=(\d+)',ar,re.I)
            if rm: a.compauth_reason=rm.group(1)
        # Received-SPF fallback
        rspf=hd.get("received-spf","")
        if rspf and not a.spf_result:
            sm=re.search(r'^(\w+)',rspf)
            if sm: a.spf_result=sm.group(1); a.spf_details=rspf
        arc=hd.get("arc-authentication-results","")
        if arc:
            m=re.search(r'arc=(\w+)',arc,re.I)
            if m: a.arc_result=m.group(1)
        return a

    def _spam(self, hd):
        a=AntiSpamData()
        c=hd.get("x-forefront-antispam-report","")+";"+hd.get("x-microsoft-antispam","")
        for attr,pat in {"scl":r'SCL[=:]([^;\s]+)',"pcl":r'PCL[=:]([^;\s]+)',"bcl":r'BCL[=:]([^;\s]+)',
                         "sfv":r'SFV[=:]([^;\s]+)',"cat":r'CAT[=:]([^;\s]+)',"cip":r'CIP[=:]([^;\s]+)',
                         "country":r'CTRY[=:]([^;\s]+)',"h_value":r'(?<![A-Z])H[=:]([^;\s]+)',"ptr":r'PTR[=:]([^;\s]+)'}.items():
            m=re.search(pat,c,re.I)
            if m: setattr(a,attr,m.group(1).rstrip(';'))
        return a

    def _spairs(self, v):
        r={}
        for p in v.split(';'):
            p=p.strip()
            if ':' in p: k,_,vl=p.partition(':'); r[k.strip()]=vl.strip()
            elif '=' in p: k,_,vl=p.partition('='); r[k.strip()]=vl.strip()
        return r

SCL_DESC = {"-1":"Safe sender bypass","0":"Clean","1":"Very low","5":"Spam","6":"Spam",
            "7":"High Confidence Spam","8":"High Confidence Spam","9":"High Confidence Spam"}
SFV_DESC = {"BLK":"Blocked sender","NSPM":"Not Spam","SFE":"Safe sender","SKA":"Allow policy",
            "SKB":"Block policy","SKN":"Pre-filter: clean","SKQ":"From quarantine","SPM":"Spam"}

