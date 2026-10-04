"""The NORMALIZATION ENGINE.

Converts heterogeneous parser records (from TShark, Zeek, YARA, Velociraptor,
SIEM, Autopsy, generic parsers, …) into the common TRACE-X data model:

    records  ->  NormalizedEvent[]  +  NormalizedIndicator[]

Every normalised object retains full provenance: source tool, raw reference,
timestamp, confidence and the originating evidence.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.parsers.base import (
    EventType,
    NormalizedEvent,
    NormalizedIndicator,
    NormalizationResult,
)
from app.utils.indicators import canonical_indicator, extract_indicators

# Keys within a record's metadata that should be scanned for indicators.
_SCAN_METADATA_KEYS = (
    "dns_query",
    "answers",
    "http_host",
    "http_uri",
    "http_user_agent",
    "tls_server_name",
    "certificate_subject",
    "certificate_issuer",
    "src_ip",
    "dst_ip",
    "filename",
    "matched_file",
    "md5",
    "sha1",
    "sha256",
    "raw_line",
    "host",
    "user",
    "username",
    "process",
    "url",
)


class NormalizationEngine:
    """Stateless engine turning raw records into the common data model."""

    def normalize(
        self,
        records: Iterable[Dict[str, Any]],
        *,
        source: str,
        evidence_id: Optional[str] = None,
        is_demo: bool = False,
        default_confidence: float = 0.5,
    ) -> NormalizationResult:
        result = NormalizationResult()
        seen: Dict[Tuple[str, str], NormalizedIndicator] = {}

        for record in records:
            if not isinstance(record, dict):
                continue

            metadata = record.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {"value": metadata}
            if evidence_id:
                metadata.setdefault("evidence_id", evidence_id)

            timestamp = record.get("timestamp")
            event_type = str(record.get("event_type") or EventType.GENERIC_EVENT)
            description = str(record.get("description") or "").strip()
            confidence = float(record.get("confidence") or default_confidence)
            raw_reference = str(record.get("raw_reference") or "")

            # --- Collect indicators for this record -------------------------
            record_indicators: List[NormalizedIndicator] = []

            for indicator in record.get("indicators") or []:
                if isinstance(indicator, dict) and indicator.get("type"):
                    normalized = self._indicator(
                        indicator["type"],
                        indicator.get("value", ""),
                        indicator.get("normalized") or indicator.get("normalized_value"),
                        indicator.get("confidence", confidence),
                        source,
                        timestamp,
                    )
                    record_indicators.append(normalized)

            scan_text_parts = [description, raw_reference]
            for key in _SCAN_METADATA_KEYS:
                value = metadata.get(key)
                if value:
                    scan_text_parts.append(str(value))
            scan_text = "\n".join(part for part in scan_text_parts if part)

            for extracted in extract_indicators(scan_text):
                record_indicators.append(
                    self._indicator(
                        extracted["type"],
                        extracted["value"],
                        extracted["normalized"],
                        confidence,
                        source,
                        timestamp,
                    )
                )

            event = NormalizedEvent(
                event_type=event_type,
                description=description or event_type,
                source=source,
                timestamp=timestamp,
                raw_reference=raw_reference,
                confidence=confidence,
                metadata=metadata,
                indicators=record_indicators,
            )
            result.events.append(event)

            # --- Global de-duplication across the whole evidence item -------
            for indicator in record_indicators:
                key = (indicator.type, indicator.normalized_value)
                if key in seen:
                    existing = seen[key]
                    if indicator.first_seen and (
                        existing.first_seen is None or indicator.first_seen < existing.first_seen
                    ):
                        existing.first_seen = indicator.first_seen
                    if indicator.last_seen and (
                        existing.last_seen is None or indicator.last_seen > existing.last_seen
                    ):
                        existing.last_seen = indicator.last_seen
                    existing.confidence = max(existing.confidence, indicator.confidence)
                else:
                    seen[key] = indicator

        result.indicators = list(seen.values())
        return result

    @staticmethod
    def _indicator(
        indicator_type: str,
        value: str,
        normalized: Optional[str],
        confidence: float,
        source: str,
        timestamp,
    ) -> NormalizedIndicator:
        indicator_type = str(indicator_type).upper()
        canonical = normalized or canonical_indicator(indicator_type, value)
        return NormalizedIndicator(
            type=indicator_type,
            value=str(value),
            normalized_value=str(canonical),
            confidence=float(confidence),
            source=source,
            first_seen=timestamp,
            last_seen=timestamp,
        )