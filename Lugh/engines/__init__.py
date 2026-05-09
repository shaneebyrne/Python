"""
Lugh v3.0 - Engine Modules
All analysis engines are importable standalone (no GUI dependency).
"""
from engines.email_data import ReceivedHop, AuthenticationResult, AntiSpamData, ParsedHeaders
from engines.email_parser import EmailHeaderParser
from engines.homograph import HomographDetector, HOMOGLYPH_MAP
from engines.file_checker import FileTypeChecker, MAGIC_SIGS
from engines.deep_analyzer import DeepAnalyzer, SUSPICIOUS_APIS
from engines.yara_engine import YaraEngine, YARA_TEMPLATES
from engines.risk_scoring import RiskScoringEngine, DEFAULT_INDICATORS
from engines.ps_analyzer import PowerShellAnalyzer
from engines.archive_extractor import ArchiveExtractor
from engines.event_log import EventLogParser, NOTABLE_EVENT_IDS, EVTX_NS, _ensure_evtx
from engines.link_analyzer import LinkAnalyzer, SUSPICIOUS_TLDS, URL_SHORTENERS, PHISH_KEYWORDS
