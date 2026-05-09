"""
BeanFeasa — Text / Syslog Parser.

Parses plain-text log files including traditional syslog, application logs,
Apache/Nginx access/error logs, and generic timestamped text logs.
"""

import re
from pathlib import Path
from parsers.base import BaseParser, ParsedEvent


# ── Regex patterns for common log formats ──

# Traditional syslog: "Mar 19 14:22:01 hostname process[pid]: message"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<source>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# ISO-prefixed: "2025-03-19T14:22:01.123Z hostname source: message"
ISO_PREFIX_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<source>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# Generic timestamp + message: "2025-03-19 14:22:01 [LEVEL] message"
GENERIC_TS_RE = re.compile(
    r"^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:\[?(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE|NOTICE|ALERT|EMERG)\]?\s+)?"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)

# Apache / Nginx combined log format
APACHE_RE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<message>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

# Windows-style: "MM/DD/YYYY HH:MM:SS AM/PM  Source  EventID  Description"
WIN_TEXT_RE = re.compile(
    r"^(?P<timestamp>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<event_id>\d+)\s+"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)

PATTERNS = [
    ("syslog", SYSLOG_RE),
    ("iso_prefix", ISO_PREFIX_RE),
    ("apache", APACHE_RE),
    ("win_text", WIN_TEXT_RE),
    ("generic", GENERIC_TS_RE),
]


class TextParser(BaseParser):
    """Parse plain-text and syslog log files."""

    SUPPORTED_EXTENSIONS = {".log", ".txt", ".syslog"}
    PARSER_NAME = "text"

    def parse(self) -> list[ParsedEvent]:
        events = []
        try:
            raw = Path(self.filepath).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self.errors.append(f"Failed to read text file: {exc}")
            return events

        lines = raw.splitlines()
        if not lines:
            self.errors.append("Text file is empty.")
            return events

        # Auto-detect the dominant pattern from the first 20 non-empty lines
        detected_format = self._detect_format(lines[:50])

        current_event_lines: list[str] = []
        for line in lines:
            if not line.strip():
                continue

            # Check if this line starts a new event (has a timestamp)
            if self._is_new_event(line, detected_format):
                if current_event_lines:
                    evt = self._parse_block(current_event_lines, detected_format)
                    if evt:
                        events.append(evt)
                current_event_lines = [line]
            else:
                # Continuation of previous event (multi-line message)
                current_event_lines.append(line)

        # Don't forget the last event
        if current_event_lines:
            evt = self._parse_block(current_event_lines, detected_format)
            if evt:
                events.append(evt)

        return events

    def _detect_format(self, sample_lines: list[str]) -> str:
        """Score each pattern against sample lines and return the best match."""
        scores = {name: 0 for name, _ in PATTERNS}
        for line in sample_lines:
            if not line.strip():
                continue
            for name, pattern in PATTERNS:
                if pattern.match(line):
                    scores[name] += 1

        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "generic"

    def _is_new_event(self, line: str, fmt: str) -> bool:
        """Check if a line starts a new log event."""
        for name, pattern in PATTERNS:
            if name == fmt and pattern.match(line):
                return True
        return False

    def _parse_block(self, lines: list[str], fmt: str) -> ParsedEvent | None:
        """Parse a (possibly multi-line) log event block."""
        first_line = lines[0]
        full_message = "\n".join(lines)

        # Try the detected format first, then fall back to others
        for name, pattern in PATTERNS:
            m = pattern.match(first_line)
            if m:
                return self._match_to_event(m, name, full_message)

        # Unparsed — store as raw
        return ParsedEvent(
            message=full_message[:2000],
            raw_data=full_message[:2000],
            source=self.path.name,
        )

    def _match_to_event(self, m: re.Match, fmt: str, full_message: str) -> ParsedEvent:
        """Convert a regex match to a ParsedEvent."""
        g = m.groupdict()
        level = g.get("level", "")
        message = g.get("message", "")

        # For multi-line events, append continuation lines
        first_msg = message
        if "\n" in full_message:
            rest = full_message.split("\n", 1)[1] if "\n" in full_message else ""
            if rest.strip():
                message = first_msg + " " + rest.strip()

        # Apache-specific: embed status code
        if fmt == "apache":
            status = g.get("status", "")
            if status:
                level = "Error" if status.startswith(("4", "5")) else "Information"
                message = f"[{status}] {message}"

        return ParsedEvent(
            timestamp=self._safe_timestamp(g.get("timestamp", "")),
            source=g.get("source", self.path.name),
            event_id=g.get("event_id", ""),
            level=level,
            channel="",
            computer=g.get("host", ""),
            message=message[:2000],
            raw_data=full_message[:2000],
        )
