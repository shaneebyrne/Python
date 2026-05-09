"""
BeanFeasa — Parser Registry.

Auto-detects file types and dispatches to the correct parser.
Extensible: drop a new parser module into parsers/ and register it here.
"""

from pathlib import Path
from parsers.base import BaseParser, ParsedEvent
from parsers.evtx_parser import EvtxParser
from parsers.csv_parser import CsvParser
from parsers.json_parser import JsonParser
from parsers.text_parser import TextParser
from parsers.xml_parser import XmlParser
from parsers.dmp_parser import DmpParser


# Ordered list of available parsers (checked in order)
PARSER_CLASSES: list[type[BaseParser]] = [
    DmpParser,    # Minidump before others (binary format, unique extension)
    EvtxParser,
    CsvParser,
    JsonParser,
    XmlParser,
    TextParser,  # TextParser is the broadest — keep it last
]

# Extension → parser class lookup (built from parser metadata)
_EXT_MAP: dict[str, type[BaseParser]] = {}
for cls in PARSER_CLASSES:
    for ext in cls.SUPPORTED_EXTENSIONS:
        _EXT_MAP.setdefault(ext, cls)


def get_parser(filepath: str) -> BaseParser | None:
    """Return the appropriate parser instance for a file, or None."""
    ext = Path(filepath).suffix.lower()
    cls = _EXT_MAP.get(ext)
    if cls:
        return cls(filepath)
    return None


def parse_file(filepath: str) -> tuple[list[ParsedEvent], list[str]]:
    """
    Parse a single file and return (events, errors).

    Convenience wrapper that handles parser selection.
    """
    parser = get_parser(filepath)
    if parser is None:
        return [], [f"Unsupported file type: {Path(filepath).suffix}"]

    events = parser.parse()
    return events, parser.errors


def get_supported_extensions() -> set[str]:
    """Return the set of all supported file extensions."""
    return set(_EXT_MAP.keys())


def get_parser_name(filepath: str) -> str:
    """Return the parser name that would handle a given file."""
    parser = get_parser(filepath)
    return parser.PARSER_NAME if parser else "unknown"
