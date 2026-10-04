"""Generic parser dispatcher.

Selects the most appropriate concrete parser for text-based evidence
(JSON, NDJSON, CSV, LOG, TXT) without requiring any external tool.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.parsers.base import BaseParser
from app.parsers.csv_parser import CsvParser
from app.parsers.json_parser import JsonParser
from app.parsers.log_parser import LogParser
from app.utils.file_detection import (
    EVIDENCE_CSV,
    EVIDENCE_JSON,
    EVIDENCE_LOG,
    EVIDENCE_NDJSON,
    detect_evidence_type,
)


class GenericParser(BaseParser):
    """Dispatches to a concrete parser based on detected content type."""

    name = "generic"

    def parse(self, content: str, **kwargs: Any) -> List[Dict[str, Any]]:
        filename = kwargs.get("filename", "evidence.txt")
        evidence_type = kwargs.get("evidence_type")
        if not evidence_type:
            evidence_type, _ = detect_evidence_type(
                filename, content.encode("utf-8", "ignore")
            )

        if evidence_type in (EVIDENCE_JSON, EVIDENCE_NDJSON):
            records = JsonParser().parse(content, **kwargs)
            if records:
                return records
        elif evidence_type == EVIDENCE_CSV:
            records = CsvParser().parse(content, **kwargs)
            if records:
                return records
        elif evidence_type == EVIDENCE_LOG:
            return LogParser().parse(content, **kwargs)

        for parser in (JsonParser(), CsvParser(), LogParser()):
            try:
                records = parser.parse(content, **kwargs)
            except Exception:  # noqa: BLE001 - defensive fallthrough
                records = []
            if records:
                return records
        return LogParser().parse(content, **kwargs)