"""
BeanFeasa — XML Parser.

Parses XML log files including exported Windows Event Viewer XML,
Sysmon XML output, and generic XML-structured logs.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from parsers.base import BaseParser, ParsedEvent


# Common Windows Event XML namespace
WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class XmlParser(BaseParser):
    """Parse XML-formatted log files."""

    SUPPORTED_EXTENSIONS = {".xml"}
    PARSER_NAME = "xml"

    def parse(self) -> list[ParsedEvent]:
        events = []
        try:
            raw = Path(self.filepath).read_text(encoding="utf-8-sig", errors="replace")
        except Exception as exc:
            self.errors.append(f"Failed to read XML file: {exc}")
            return events

        raw = raw.strip()
        if not raw:
            self.errors.append("XML file is empty.")
            return events

        # Wrap in a root tag if the file has multiple top-level elements
        # (common for exported Event Viewer XML)
        if not raw.startswith("<?xml") and not raw.startswith("<Events"):
            raw = f"<Events>{raw}</Events>"
        elif raw.startswith("<?xml"):
            # Check if there's a root element after the declaration
            decl_end = raw.find("?>")
            if decl_end != -1:
                remainder = raw[decl_end + 2:].strip()
                if not remainder.startswith("<Events"):
                    raw = raw[:decl_end + 2] + f"\n<Events>{remainder}</Events>"

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            self.errors.append(f"XML parse error: {exc}")
            return events

        # Find all Event elements (with or without namespace)
        event_elements = (
            root.findall(".//e:Event", WIN_NS)
            or root.findall(".//Event")
            or root.findall(".")  # If root itself is an event
        )

        if not event_elements or (len(event_elements) == 1 and event_elements[0] is root and root.tag in ("Events", "Logs")):
            # Try treating each child as an event/log record
            event_elements = list(root)

        for i, elem in enumerate(event_elements):
            try:
                event = self._parse_element(elem)
                if event:
                    events.append(event)
            except Exception as exc:
                self.errors.append(f"Element {i}: {exc}")

        return events

    def _parse_element(self, elem: ET.Element) -> ParsedEvent | None:
        """Parse a single XML element into a ParsedEvent."""
        # Try Windows Event XML format first
        system = elem.find("e:System", WIN_NS) or elem.find("System")
        if system is not None:
            return self._parse_windows_event(elem, system)

        # Generic XML record — extract any recognizable fields
        return self._parse_generic_xml(elem)

    def _parse_windows_event(self, root: ET.Element, system: ET.Element) -> ParsedEvent:
        """Parse a Windows Event XML structure."""
        ns = WIN_NS

        timestamp = ""
        tc = system.find("e:TimeCreated", ns) or system.find("TimeCreated")
        if tc is not None:
            timestamp = tc.get("SystemTime", "")

        provider = ""
        prov = system.find("e:Provider", ns) or system.find("Provider")
        if prov is not None:
            provider = prov.get("Name", prov.text or "")

        event_id = ""
        eid = system.find("e:EventID", ns) or system.find("EventID")
        if eid is not None:
            event_id = eid.text or ""

        level = ""
        lvl = system.find("e:Level", ns) or system.find("Level")
        if lvl is not None:
            level_map = {"0": "LogAlways", "1": "Critical", "2": "Error",
                         "3": "Warning", "4": "Information", "5": "Verbose"}
            level = level_map.get(lvl.text, lvl.text or "")

        channel = ""
        chan = system.find("e:Channel", ns) or system.find("Channel")
        if chan is not None:
            channel = chan.text or ""

        computer = ""
        comp = system.find("e:Computer", ns) or system.find("Computer")
        if comp is not None:
            computer = comp.text or ""

        # Extract EventData / UserData
        message_parts = []
        for section_name in ("e:EventData", "EventData", "e:UserData", "UserData"):
            section = root.find(section_name, ns) if "e:" in section_name else root.find(section_name)
            if section is not None:
                for child in section.iter():
                    if child.text and child.text.strip():
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        name = child.get("Name", tag)
                        message_parts.append(f"{name}={child.text.strip()}")

        return ParsedEvent(
            timestamp=self._safe_timestamp(timestamp),
            source=provider,
            event_id=str(event_id),
            level=level,
            channel=channel,
            computer=computer,
            message=" | ".join(message_parts),
            raw_data=ET.tostring(root, encoding="unicode")[:2000],
        )

    def _parse_generic_xml(self, elem: ET.Element) -> ParsedEvent:
        """Best-effort parse of a generic XML log element."""
        fields = {}
        message_parts = []

        # Walk all children and try to map known field names
        known_ts = {"timestamp", "time", "datetime", "date", "timecreated"}
        known_src = {"source", "provider", "process", "application", "logger"}
        known_id = {"eventid", "event_id", "id", "code"}
        known_lvl = {"level", "severity", "type", "priority"}
        known_host = {"computer", "hostname", "host", "machine", "node"}
        known_msg = {"message", "msg", "description", "text", "details"}

        for child in elem.iter():
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            tag_lower = tag.lower()
            value = (child.text or "").strip()
            if not value:
                continue

            if tag_lower in known_ts and "timestamp" not in fields:
                fields["timestamp"] = value
            elif tag_lower in known_src and "source" not in fields:
                fields["source"] = value
            elif tag_lower in known_id and "event_id" not in fields:
                fields["event_id"] = value
            elif tag_lower in known_lvl and "level" not in fields:
                fields["level"] = value
            elif tag_lower in known_host and "computer" not in fields:
                fields["computer"] = value
            elif tag_lower in known_msg and "message" not in fields:
                fields["message"] = value
            else:
                message_parts.append(f"{tag}={value}")

        message = fields.get("message", "")
        if not message and message_parts:
            message = " | ".join(message_parts)

        return ParsedEvent(
            timestamp=self._safe_timestamp(fields.get("timestamp", "")),
            source=fields.get("source", ""),
            event_id=fields.get("event_id", ""),
            level=fields.get("level", ""),
            channel="",
            computer=fields.get("computer", ""),
            message=message[:2000],
            raw_data=ET.tostring(elem, encoding="unicode")[:2000],
        )
