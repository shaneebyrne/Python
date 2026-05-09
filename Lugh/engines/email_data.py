"""
Lugh v3.0 - Email Header Data Classes
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime

@dataclass
class ReceivedHop:
    hop_number: int = 0; from_host: str = ""; by_host: str = ""
    with_protocol: str = ""; timestamp: Optional[datetime] = None
    delay: str = ""; delay_seconds: float = 0.0; raw_header: str = ""

@dataclass
class AuthenticationResult:
    spf_result: str = ""; spf_details: str = ""; dkim_result: str = ""
    dkim_details: str = ""; dmarc_result: str = ""; dmarc_details: str = ""
    compauth_result: str = ""; compauth_reason: str = ""; arc_result: str = ""

@dataclass
class AntiSpamData:
    scl: str = ""; pcl: str = ""; bcl: str = ""; sfv: str = ""
    sfp: str = ""; sfs: str = ""; cat: str = ""; source_ip: str = ""
    country: str = ""; h_value: str = ""; ptr: str = ""; cip: str = ""

@dataclass
class ParsedHeaders:
    summary: dict = field(default_factory=dict)
    received_hops: list = field(default_factory=list)
    authentication: AuthenticationResult = field(default_factory=AuthenticationResult)
    antispam: AntiSpamData = field(default_factory=AntiSpamData)
    other_headers: dict = field(default_factory=dict)
    forefront_antispam: dict = field(default_factory=dict)
    microsoft_antispam: dict = field(default_factory=dict)

