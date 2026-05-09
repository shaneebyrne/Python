"""
BeanFeasa — JSON / JSONL Parser.

Parses JSON and JSONL (newline-delimited JSON) log files.
Handles structured logs from ELK, Splunk JSON export, Sysmon, etc.
"""

import json
from pathlib import Path
from parsers.base import BaseParser, ParsedEvent


# Keys to probe for each normalized field (order = priority)
FIELD_PROBES = {
    "timestamp": [
        "timestamp", "@timestamp", "time", "datetime", "date",
        "TimeCreated", "EventTime", "created_at", "ts", "logged",
        "SystemTime",
    ],
    "source": [
        "source", "SourceName", "Provider", "ProviderName",
        "provider_name", "process", "ProcessName", "app",
        "application", "logger",
    ],
    "event_id": [
        "EventID", "event_id", "eventId", "EventCode", "id", "eid",
    ],
    "level": [
        "level", "Level", "severity", "Severity", "log_level",
        "loglevel", "priority", "type",
    ],
    "channel": [
        "channel", "Channel", "log", "LogName", "log_name",
        "facility", "category",
    ],
    "computer": [
        "computer", "Computer", "ComputerName", "hostname", "host",
        "node", "machine", "device",
    ],
    "message": [
        "message", "Message", "msg", "description", "text",
        "details", "data", "info", "summary",
    ],
}


class JsonParser(BaseParser):
    """Parse JSON and JSONL log files."""

    SUPPORTED_EXTENSIONS = {".json", ".jsonl"}
    PARSER_NAME = "json"

    def parse(self) -> list[ParsedEvent]:
        events = []
        try:
            raw = Path(self.filepath).read_text(encoding="utf-8-sig", errors="replace")
        except Exception as exc:
            self.errors.append(f"Failed to read JSON file: {exc}")
            return events

        raw = raw.strip()
        if not raw:
            self.errors.append("JSON file is empty.")
            return events

        records = self._load_records(raw)
        for i, record in enumerate(records):
            try:
                event = self._record_to_event(record)
                events.append(event)
            except Exception as exc:
                self.errors.append(f"Record {i}: {exc}")

        return events

    def _load_records(self, raw: str) -> list[dict]:
        """Load records from JSON array, single object, or JSONL."""
        records = []

        # Try as JSON array or single object first
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
                if records:
                    return records
            elif isinstance(data, dict):
                # Could be a wrapper with a "records"/"events"/"hits" key
                for key in ("records", "events", "hits", "data", "logs", "entries"):
                    if key in data and isinstance(data[key], list):
                        records = [r for r in data[key] if isinstance(r, dict)]
                        if records:
                            return records
                # Single event object
                return [data]
        except json.JSONDecodeError:
            pass

        # Fall back to JSONL (one JSON object per line)
        for line_num, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError as exc:
                self.errors.append(f"Line {line_num}: invalid JSON — {exc}")

        return records

    def _record_to_event(self, record: dict) -> ParsedEvent:
        """Map a flat or nested JSON object to a ParsedEvent."""
        # Flatten one level of nesting for common wrappers
        flat = {}
        for k, v in record.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    flat[sub_k] = sub_v
            else:
                flat[k] = v

        fields = {}
        for target_field, probes in FIELD_PROBES.items():
            for probe in probes:
                if probe in flat and flat[probe] is not None:
                    val = flat[probe]
                    # Handle nested timestamp objects like {"SystemTime": "..."}
                    if isinstance(val, dict):
                        val = val.get("SystemTime", val.get("$date", str(val)))
                    fields[target_field] = str(val).strip()
                    break

        return ParsedEvent(
            timestamp=self._safe_timestamp(fields.get("timestamp", "")),
            source=fields.get("source", ""),
            event_id=fields.get("event_id", ""),
            level=fields.get("level", ""),
            channel=fields.get("channel", ""),
            computer=fields.get("computer", ""),
            message=fields.get("message", ""),
            raw_data=json.dumps(record, default=str)[:2000],
        )
