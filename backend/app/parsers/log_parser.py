"""Generic plain-text / log parser.

Extracts timestamps and IOCs line by line.  Event type is inferred from
keywords so that logs produce meaningful timeline entries.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from app.parsers.base import BaseParser, EventType
from app.utils.timestamps import parse_timestamp

_LEADING_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"
)
_BRACKET_TS_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]")


def _infer_event_type(text: str) -> str:
    lowered = text.lower()
    if "dns" in lowered or "query" in lowered:
        return EventType.DNS_QUERY
    if "http" in lowered or "get /" in lowered or "post /" in lowered:
        return EventType.HTTP_REQUEST
    if "tls" in lowered or "ssl" in lowered or "handshake" in lowered:
        return EventType.TLS_SESSION
    # Authentication logs vary widely: sshd uses "password for"/"Accepted"/"Failed",
    # Windows uses "logon"/"4624", web stacks use "login"/"signin".
    auth_markers = (
        "login",
        "auth",
        "logon",
        "password for",
        "accepted password",
        "failed password",
        "invalid user",
        "authentication",
        "signin",
        "sign-in",
        "session opened",
        "session closed",
    )
    if any(marker in lowered for marker in auth_markers):
        return EventType.AUTHENTICATION
    if "connect" in lowered or "connection" in lowered:
        return EventType.NETWORK_CONNECTION
    if "process" in lowered or "exec" in lowered:
        return EventType.PROCESS_EXECUTION
    if "file" in lowered:
        return EventType.FILE_OBSERVED
    return EventType.LOG_ENTRY


class LogParser(BaseParser):
    name = "log"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        line_number = 0
        for raw_line in (content or "").splitlines():
            line_number += 1
            line = raw_line.strip()
            if not line:
                continue
            timestamp = None
            remainder = line
            match = _LEADING_TS_RE.match(line) or _BRACKET_TS_RE.match(line)
            if match:
                timestamp = parse_timestamp(match.group("ts"))
                remainder = line[match.end():].strip(" \t-|") or line
            records.append(
                {
                    "timestamp": timestamp,
                    "event_type": _infer_event_type(line),
                    "description": remainder[:4000],
                    "raw_reference": f"line={line_number}",
                    "confidence": 0.5,
                    "metadata": {"line_number": line_number, "raw_line": line[:4000]},
                }
            )
        return records