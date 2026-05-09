"""
Lugh v3.0 - Weighted Risk Scoring Engine
"""

# ══════════════════════════════════════════════════════════════
# WEIGHTED RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════
DEFAULT_INDICATORS = [
    # Email Auth indicators
    {"id":"spf_fail","name":"SPF Fail/Softfail","category":"Email Auth","weight":15,"desc":"SPF did not pass for sender"},
    {"id":"dkim_fail","name":"DKIM Fail/Missing","category":"Email Auth","weight":15,"desc":"DKIM verification failed or absent"},
    {"id":"dmarc_fail","name":"DMARC Fail/None","category":"Email Auth","weight":20,"desc":"DMARC policy did not pass"},
    {"id":"spoof_from","name":"From Spoofing Suspected","category":"Email Auth","weight":25,"desc":"Return-Path / From mismatch"},
    # File indicators
    {"id":"ext_mismatch","name":"Extension Mismatch","category":"File Analysis","weight":30,"desc":"File extension does not match magic bytes"},
    {"id":"high_entropy","name":"High Entropy (>7.0)","category":"File Analysis","weight":20,"desc":"File/section entropy suggests packing or encryption"},
    {"id":"sus_imports","name":"Suspicious API Imports","category":"File Analysis","weight":25,"desc":"Process injection / evasion APIs detected"},
    {"id":"embedded_exe","name":"Embedded Executable","category":"File Analysis","weight":35,"desc":"PE/ELF header found inside non-executable file"},
    # Network indicators
    {"id":"known_bad_ip","name":"Known Bad IP/Domain","category":"Network","weight":30,"desc":"IP or domain appears on threat intel lists"},
    {"id":"unusual_port","name":"Unusual Port Activity","category":"Network","weight":15,"desc":"Communication on non-standard ports"},
    {"id":"c2_pattern","name":"C2 Beacon Pattern","category":"Network","weight":40,"desc":"Regular interval callbacks resembling C2"},
    # Behavioral
    {"id":"persistence","name":"Persistence Mechanism","category":"Behavioral","weight":25,"desc":"Registry run keys, scheduled tasks, services"},
    {"id":"defense_evasion","name":"Defense Evasion","category":"Behavioral","weight":30,"desc":"Anti-debug, anti-VM, process hollowing"},
    {"id":"priv_escalation","name":"Privilege Escalation","category":"Behavioral","weight":35,"desc":"Token manipulation, exploit indicators"},
    {"id":"data_exfil","name":"Data Exfiltration Signs","category":"Behavioral","weight":30,"desc":"Large outbound transfers, staging directories"},
    # Homograph / Phishing
    {"id":"homograph","name":"Homograph Attack","category":"Phishing","weight":25,"desc":"Unicode lookalike characters in URL/domain"},
    {"id":"brand_impersonation","name":"Brand Impersonation","category":"Phishing","weight":30,"desc":"Known brand targeted by spoofed domain"},
    {"id":"urgency_language","name":"Urgency/Threat Language","category":"Phishing","weight":10,"desc":"Threatening or urgent phrasing in email"},
]

class RiskScoringEngine:
    """Calculates weighted risk scores from multiple indicators."""

    def __init__(self):
        self.indicators = [dict(ind) for ind in DEFAULT_INDICATORS]
        for ind in self.indicators: ind["active"] = False

    def reset(self):
        for ind in self.indicators: ind["active"] = False

    def set_active(self, ind_id, active=True):
        for ind in self.indicators:
            if ind["id"] == ind_id: ind["active"] = active; return

    def calculate(self):
        active = [i for i in self.indicators if i["active"]]
        if not active:
            return {"score":0,"max_possible":0,"pct":0.0,"level":"NONE","active":[],"breakdown":{}}
        total = sum(i["weight"] for i in active)
        max_w = sum(i["weight"] for i in self.indicators)
        pct = (total / max_w * 100) if max_w else 0
        if pct >= 70: level = "CRITICAL"
        elif pct >= 45: level = "HIGH"
        elif pct >= 20: level = "MEDIUM"
        elif pct > 0: level = "LOW"
        else: level = "NONE"
        breakdown = {}
        for i in active:
            cat = i["category"]
            if cat not in breakdown: breakdown[cat] = {"items":[],"subtotal":0}
            breakdown[cat]["items"].append(i)
            breakdown[cat]["subtotal"] += i["weight"]
        return {"score":total,"max_possible":max_w,"pct":round(pct,1),"level":level,
                "active":active,"breakdown":breakdown}

