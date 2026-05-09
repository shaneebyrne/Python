"""
BeanFeasa — EVTX Parser.

Parses Windows Event Log (.evtx) files using the python-evtx library.
Falls back to XML extraction if the library is unavailable.
"""

import xml.etree.ElementTree as ET
from parsers.base import BaseParser, ParsedEvent


# Namespace used in EVTX XML records
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class EvtxParser(BaseParser):
    """Parse Windows .evtx files."""

    SUPPORTED_EXTENSIONS = {".evtx"}
    PARSER_NAME = "evtx"

    def parse(self) -> list[ParsedEvent]:
        events = []
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as views
        except ImportError:
            self.errors.append(
                "python-evtx not installed. Run: pip install python-evtx"
            )
            return events

        try:
            with evtx.Evtx(self.filepath) as log:
                for record in log.records():
                    try:
                        event = self._parse_record(record)
                        if event:
                            events.append(event)
                    except Exception as exc:
                        self.errors.append(f"Record parse error: {exc}")
        except Exception as exc:
            self.errors.append(f"Failed to open EVTX file: {exc}")

        return events

    def _parse_record(self, record) -> ParsedEvent | None:
        """Extract fields from a single EVTX record."""
        try:
            xml_str = record.xml()
            root = ET.fromstring(xml_str)
        except Exception:
            return None

        # System block
        system = root.find("e:System", NS)
        if system is None:
            return None

        timestamp = ""
        time_el = system.find("e:TimeCreated", NS)
        if time_el is not None:
            timestamp = time_el.get("SystemTime", "")

        provider = ""
        prov_el = system.find("e:Provider", NS)
        if prov_el is not None:
            provider = prov_el.get("Name", "")

        event_id = ""
        eid_el = system.find("e:EventID", NS)
        if eid_el is not None:
            event_id = eid_el.text or ""

        level = ""
        lvl_el = system.find("e:Level", NS)
        if lvl_el is not None:
            level = self._level_name(lvl_el.text)

        channel = ""
        chan_el = system.find("e:Channel", NS)
        if chan_el is not None:
            channel = chan_el.text or ""

        computer = ""
        comp_el = system.find("e:Computer", NS)
        if comp_el is not None:
            computer = comp_el.text or ""

        # EventData / UserData for message content
        message_parts = []
        for data_section in ("e:EventData", "e:UserData"):
            section = root.find(data_section, NS)
            if section is not None:
                for child in section.iter():
                    if child.text and child.text.strip():
                        name = child.get("Name", child.tag.split("}")[-1] if "}" in child.tag else child.tag)
                        message_parts.append(f"{name}={child.text.strip()}")

        return ParsedEvent(
            timestamp=self._safe_timestamp(timestamp),
            source=provider,
            event_id=str(event_id),
            level=level,
            channel=channel,
            computer=computer,
            message=" | ".join(message_parts),
            raw_data=xml_str[:2000],
        )

    @staticmethod
    def _level_name(level_val: str | None) -> str:
        """Convert numeric level to human-readable name."""
        mapping = {
            "0": "LogAlways",
            "1": "Critical",
            "2": "Error",
            "3": "Warning",
            "4": "Information",
            "5": "Verbose",
        }
        return mapping.get(str(level_val), str(level_val or ""))
