"""Generic CSV / TSV parser."""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

from app.parsers.base import BaseParser, EventType
from app.utils.timestamps import parse_timestamp

_TIMESTAMP_KEYS = ("timestamp", "time", "ts", "date", "datetime", "event_time")

# Columns that carry the human-readable meaning of a row.  When one of these is
# present the description is taken from it instead of being a key=value dump.
_MESSAGE_KEYS = (
    "description",
    "message",
    "msg",
    "detail",
    "summary",
    "text",
    "event",
    "event_description",
    "artifact",
    "path",
    "name",
)

_SOURCE_KEYS = ("source", "tool", "artifact", "parser", "origin")

# Row values that indicate an event type, checked case-insensitively.
_EVENT_TYPE_HINTS = (
    ("yara", EventType.YARA_MATCH),
    ("malware", EventType.YARA_MATCH),
    ("dns", EventType.DNS_QUERY),
    ("http", EventType.HTTP_REQUEST),
    ("tls", EventType.TLS_SESSION),
    ("ssl", EventType.TLS_SESSION),
    ("logon", EventType.AUTHENTICATION),
    ("login", EventType.AUTHENTICATION),
    ("auth", EventType.AUTHENTICATION),
    ("process", EventType.PROCESS_EXECUTION),
    ("exec", EventType.PROCESS_EXECUTION),
    ("file", EventType.FILE_OBSERVED),
    ("network", EventType.NETWORK_CONNECTION),
    ("connection", EventType.NETWORK_CONNECTION),
)


class CsvParser(BaseParser):
    name = "csv"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        content = (content or "").strip()
        if not content:
            return []
        sample = content[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(io.StringIO(content), dialect=dialect)
        records: List[Dict[str, Any]] = []
        for row in reader:
            if not row:
                continue
            clean = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            if not any(clean.values()):
                continue
            records.append(self._record_from_row(clean))
        return records

    def _record_from_row(self, row: Dict[str, str]) -> Dict[str, Any]:
        timestamp = None
        for key in _TIMESTAMP_KEYS:
            for column, value in row.items():
                if column.lower() == key and value:
                    timestamp = parse_timestamp(value)
                    if timestamp:
                        break
            if timestamp:
                break

        lowered = {k.lower(): v for k, v in row.items()}
        description = ""
        for key in _MESSAGE_KEYS:
            if lowered.get(key):
                description = str(lowered[key]).strip()
                break
        if not description:
            description = " | ".join(f"{k}={v}" for k, v in row.items() if v)
        description = description[:4000]

        event_type = EventType.LOG_ENTRY
        haystack = " ".join(str(v) for v in row.values()).lower()
        for needle, candidate in _EVENT_TYPE_HINTS:
            if needle in haystack:
                event_type = candidate
                break

        raw_reference = "csv"
        for key in _SOURCE_KEYS:
            if lowered.get(key):
                raw_reference = str(lowered[key]).strip()[:200]
                break

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "raw_reference": raw_reference,
            "confidence": 0.55,
            "metadata": dict(row),
        }