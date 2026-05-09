"""
BeanFeasa — CSV Parser.

Parses CSV log files with auto-detection of delimiter and column mapping.
Handles exports from Event Viewer, Splunk, Sysmon, SentinelOne, etc.
"""

import csv
import io
from pathlib import Path
from parsers.base import BaseParser, ParsedEvent


# Common column name mappings → normalized field
COLUMN_MAP = {
    # Timestamps — covers Event Viewer CSV, PowerShell Get-WinEvent, Splunk, etc.
    "timestamp": "timestamp", "time": "timestamp", "date": "timestamp",
    "datetime": "timestamp", "date/time": "timestamp", "date and time": "timestamp",
    "timecreated": "timestamp", "time created": "timestamp",
    "utc time": "timestamp", "eventtime": "timestamp",
    "createdat": "timestamp", "created_at": "timestamp",
    "logged": "timestamp", "system time": "timestamp",
    "timegenerated": "timestamp", "time generated": "timestamp",
    "writtentime": "timestamp", "written": "timestamp",
    "generatedtime": "timestamp", "recordwrittentime": "timestamp",

    # Source / Provider
    "source": "source", "provider": "source", "providername": "source",
    "provider name": "source", "sourcename": "source", "source name": "source",
    "application": "source", "process": "source", "processname": "source",

    # Event ID
    "event id": "event_id", "eventid": "event_id", "event_id": "event_id",
    "id": "event_id", "eid": "event_id", "eventcode": "event_id",

    # Level / Severity — covers Get-EventLog (EntryType) and Get-WinEvent (LevelDisplayName)
    "level": "level", "severity": "level", "type": "level",
    "loglevel": "level", "log_level": "level", "priority": "level",
    "event type": "level", "eventtype": "level",
    "entrytype": "level",          # Get-EventLog output column
    "leveldisplayname": "level",   # Get-WinEvent output column
    "entry type": "level", "level display name": "level",

    # Channel / Log
    "channel": "channel", "log": "channel", "logname": "channel",
    "log name": "channel", "log_name": "channel", "facility": "channel",
    "category": "channel",

    # Computer / Host
    "computer": "computer", "hostname": "computer", "host": "computer",
    "computername": "computer", "computer name": "computer",
    "machine": "computer", "node": "computer", "device": "computer",

    # Message
    "message": "message", "msg": "message", "description": "message",
    "details": "message", "text": "message", "data": "message",
    "event": "message", "info": "message", "summary": "message",
}


class CsvParser(BaseParser):
    """Parse CSV / TSV log files."""

    SUPPORTED_EXTENSIONS = {".csv", ".tsv"}
    PARSER_NAME = "csv"

    def parse(self) -> list[ParsedEvent]:
        events = []
        try:
            raw = Path(self.filepath).read_text(encoding="utf-8-sig", errors="replace")
        except Exception as exc:
            self.errors.append(f"Failed to read CSV: {exc}")
            return events

        # Auto-detect delimiter
        try:
            dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",\t;|")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = "," if self.path.suffix.lower() == ".csv" else "\t"

        reader = csv.DictReader(io.StringIO(raw), delimiter=delimiter)
        if not reader.fieldnames:
            self.errors.append("CSV has no headers or is empty.")
            return events

        # Build column mapping
        field_map = self._build_field_map(reader.fieldnames)

        for row_num, row in enumerate(reader, start=2):
            try:
                event = self._row_to_event(row, field_map)
                events.append(event)
            except Exception as exc:
                self.errors.append(f"Row {row_num}: {exc}")

        return events

    def _build_field_map(self, headers: list[str]) -> dict[str, str]:
        """Map CSV column names to normalized ParsedEvent fields."""
        mapping = {}
        for header in headers:
            normalized = header.strip().lower()
            if normalized in COLUMN_MAP:
                target = COLUMN_MAP[normalized]
                if target not in mapping.values():
                    mapping[header] = target
        return mapping

    def _row_to_event(self, row: dict, field_map: dict[str, str]) -> ParsedEvent:
        """Convert a CSV row to a ParsedEvent using the field map."""
        fields = {}
        unmapped_parts = []

        for col, value in row.items():
            if col in field_map:
                fields[field_map[col]] = (value or "").strip()
            elif value and value.strip():
                unmapped_parts.append(f"{col}={value.strip()}")

        # Build message from explicit message field + any unmapped columns
        message = fields.get("message", "")
        if unmapped_parts and not message:
            message = " | ".join(unmapped_parts)

        return ParsedEvent(
            timestamp=self._safe_timestamp(fields.get("timestamp", "")),
            source=fields.get("source", ""),
            event_id=fields.get("event_id", ""),
            level=fields.get("level", ""),
            channel=fields.get("channel", ""),
            computer=fields.get("computer", ""),
            message=message,
            raw_data=str(row)[:2000],
        )
