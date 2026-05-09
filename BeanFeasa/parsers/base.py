"""
BeanFeasa — Base parser interface.

All log parsers inherit from BaseParser and implement the `parse()` method,
returning a list of normalized event dictionaries.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime


class ParsedEvent:
    """A single normalized log event."""

    __slots__ = (
        "timestamp", "source", "event_id", "level", "channel",
        "computer", "message", "raw_data", "metadata",
    )

    def __init__(
        self,
        timestamp: str = "",
        source: str = "",
        event_id: str = "",
        level: str = "",
        channel: str = "",
        computer: str = "",
        message: str = "",
        raw_data: str = "",
        metadata: dict | None = None,
    ):
        self.timestamp = timestamp
        self.source = source
        self.event_id = event_id
        self.level = level
        self.channel = channel
        self.computer = computer
        self.message = message
        self.raw_data = raw_data
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_id": self.event_id,
            "level": self.level,
            "channel": self.channel,
            "computer": self.computer,
            "message": self.message,
            "raw_data": self.raw_data,
            "metadata": str(self.metadata) if self.metadata else "",
        }


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    # Subclasses set this
    SUPPORTED_EXTENSIONS: set[str] = set()
    PARSER_NAME: str = "base"

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.path = Path(filepath)
        self.errors: list[str] = []

    def can_parse(self) -> bool:
        """Check if this parser can handle the given file."""
        return self.path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    @abstractmethod
    def parse(self) -> list[ParsedEvent]:
        """Parse the file and return a list of normalized events."""
        ...

    def _safe_timestamp(self, value) -> str:
        """Attempt to normalize a timestamp value to ISO format."""
        if not value:
            return ""
        if isinstance(value, datetime):
            return value.isoformat()
        raw = str(value).strip()
        # Try common formats — ordered by likelihood in Windows log exports
        for fmt in (
            # ISO variants (most log exporters)
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            # Windows Event Viewer / PowerShell CSV export (US locale)
            "%m/%d/%Y %I:%M:%S %p",    # 4/29/2026 3:09:40 PM
            "%m/%d/%Y %H:%M:%S",       # 4/29/2026 15:09:40
            "%m/%d/%Y %I:%M %p",       # 4/29/2026 3:09 PM
            # European variants
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %I:%M:%S %p",
            # Other common formats
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(raw[:26], fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt.isoformat()
            except ValueError:
                continue
        return raw  # Return as-is if we can't parse it
