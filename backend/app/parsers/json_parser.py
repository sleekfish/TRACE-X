"""Generic JSON / NDJSON parser."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from app.parsers.base import BaseParser, EventType
from app.utils.timestamps import parse_timestamp

_TIMESTAMP_KEYS = ("timestamp", "@timestamp", "time", "ts", "date", "datetime", "event_time")
_MESSAGE_KEYS = ("message", "description", "msg", "event", "detail", "summary", "text")


class JsonParser(BaseParser):
    name = "json"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        content = (content or "").strip()
        if not content:
            return []

        try:
            payload = json.loads(content)
            items = self._as_items(payload)
        except json.JSONDecodeError:
            items = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    items.append(obj)
                elif isinstance(obj, list):
                    items.extend(o for o in obj if isinstance(o, dict))

        records: List[Dict[str, Any]] = []
        for item in items:
            record = self._record_from_object(item)
            if record:
                records.append(record)
        return records

    @staticmethod
    def _as_items(payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("events", "records", "logs", "entries", "data", "results"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [payload]
        return []

    def _record_from_object(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = None
        for key in _TIMESTAMP_KEYS:
            if key in obj:
                timestamp = parse_timestamp(obj[key])
                if timestamp:
                    break

        description = ""
        for key in _MESSAGE_KEYS:
            if obj.get(key):
                description = self._as_text(obj[key])
                break
        if not description:
            description = self._as_text(obj)

        event_type = self._as_text(
            obj.get("event_type") or obj.get("event") or obj.get("type")
        ) or EventType.LOG_ENTRY
        source = self._as_text(obj.get("source") or obj.get("tool")) or "json"

        return {
            "timestamp": timestamp,
            "event_type": str(event_type).upper().replace(" ", "_")[:64],
            "description": description[:4000],
            "raw_reference": source,
            "confidence": 0.6,
            "metadata": {k: v for k, v in obj.items() if k not in _MESSAGE_KEYS},
        }