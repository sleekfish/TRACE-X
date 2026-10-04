"""Common parser contracts and normalised data structures.

Every forensic tool produces a different output format.  Parsers convert that
raw output into a list of *records* (plain dicts).  The normalisation engine
then turns records into the common TRACE-X data model.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


class EventType:
    """Canonical event types used across all adapters."""

    DNS_QUERY = "DNS_QUERY"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    HTTP_REQUEST = "HTTP_REQUEST"
    TLS_SESSION = "TLS_SESSION"
    FILE_OBSERVED = "FILE_OBSERVED"
    YARA_MATCH = "YARA_MATCH"
    AUTHENTICATION = "AUTHENTICATION"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    LOG_ENTRY = "LOG_ENTRY"
    ARTIFACT = "ARTIFACT"
    GENERIC_EVENT = "GENERIC_EVENT"


@dataclass
class NormalizedIndicator:
    """A single indicator extracted from evidence, with provenance."""

    type: str
    value: str
    normalized_value: str
    confidence: float = 0.5
    source: str = "unknown"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class NormalizedEvent:
    """A single timeline event, with provenance."""

    event_type: str
    description: str
    source: str
    timestamp: Optional[datetime] = None
    raw_reference: str = ""
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    indicators: List[NormalizedIndicator] = field(default_factory=list)


@dataclass
class NormalizationResult:
    """Aggregate output of the normalisation engine for one evidence item."""

    events: List[NormalizedEvent] = field(default_factory=list)
    indicators: List[NormalizedIndicator] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class BaseParser(abc.ABC):
    """Interface every parser must implement."""

    name: str = "base"

    @abc.abstractmethod
    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Parse raw tool output into a list of record dicts."""
        raise NotImplementedError

    @staticmethod
    def _as_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            for item in value:
                text = BaseParser._as_text(item)
                if text:
                    return text
            return ""
        return str(value).strip()

    @staticmethod
    def _first(value: Any) -> Any:
        """tshark often wraps values in single-element lists."""
        if isinstance(value, (list, tuple)):
            return value[0] if value else None
        return value