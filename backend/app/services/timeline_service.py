"""Unified forensic timeline construction."""

from __future__ import annotations

import datetime as dt
from typing import List, Optional

from sqlalchemy.orm import Session

from app.schemas.timeline import (
    TimelineBucket,
    TimelineEntry,
    TimelineGap,
    TimelineHistogram,
    TimelineResponse,
)
from app.services.base import BaseService
from app.services.event_service import EventService

# A gap larger than this many seconds between consecutive events is surfaced as
# a possible coverage gap (never as a conclusion).
DEFAULT_GAP_SECONDS = 3600.0


class TimelineService(BaseService):
    """Merge events from all evidence into a single chronological timeline."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.events = EventService(db)

    def build(
        self,
        *,
        case_id: str,
        start: Optional[dt.datetime] = None,
        end: Optional[dt.datetime] = None,
        event_types: Optional[List[str]] = None,
        sources: Optional[List[str]] = None,
        include_demo: bool = True,
        limit: int = 2000,
        gap_threshold_seconds: float = DEFAULT_GAP_SECONDS,
    ) -> TimelineResponse:
        safe_limit = self.clamp_limit(limit, maximum=20000)
        records = self.events.all_events(case_id=case_id, include_demo=include_demo)

        type_filter = {t for t in (event_types or []) if t}
        source_filter = {s for s in (sources or []) if s}

        filtered = []
        for event in records:
            if type_filter and event.event_type not in type_filter:
                continue
            if source_filter and event.source not in source_filter:
                continue
            if start and (event.timestamp is None or event.timestamp < start):
                continue
            if end and (event.timestamp is None or event.timestamp > end):
                continue
            filtered.append(event)

        total = len(filtered)
        truncated = total > safe_limit
        selected = filtered[:safe_limit]

        event_ids = [event.id for event in selected]
        indicator_map = self.events.indicators_for_events(event_ids)
        filename_map = self.events.evidence_filenames(
            [event.evidence_id for event in selected if event.evidence_id]
        )

        entries = [
            TimelineEntry(
                event_id=event.id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                source=event.source,
                description=event.description,
                confidence=event.confidence,
                evidence_id=event.evidence_id,
                evidence_filename=filename_map.get(event.evidence_id or ""),
                raw_reference=event.raw_reference,
                indicators=indicator_map.get(event.id, []),
                event_metadata=event.event_metadata or {},
                is_demo=event.is_demo,
            )
            for event in selected
        ]

        timestamped = [entry for entry in entries if entry.timestamp is not None]
        gaps = self._find_gaps(timestamped, gap_threshold_seconds)

        note = ""
        if truncated:
            note = (
                f"Timeline truncated to {safe_limit} of {total} events. "
                "Narrow the time range to see the remainder."
            )
        elif not entries:
            note = "No events matched the requested filters."

        return TimelineResponse(
            entries=entries,
            total=total,
            returned=len(entries),
            start=timestamped[0].timestamp if timestamped else None,
            end=timestamped[-1].timestamp if timestamped else None,
            truncated=truncated,
            gaps=gaps,
            note=note,
        )

    @staticmethod
    def _find_gaps(
        entries: List[TimelineEntry], threshold_seconds: float
    ) -> List[TimelineGap]:
        if len(entries) < 2 or threshold_seconds <= 0:
            return []
        gaps: List[TimelineGap] = []
        for previous, current in zip(entries, entries[1:]):
            delta = (current.timestamp - previous.timestamp).total_seconds()
            if delta > threshold_seconds:
                gaps.append(
                    TimelineGap(
                        after_event_id=previous.event_id,
                        before_event_id=current.event_id,
                        after_timestamp=previous.timestamp,
                        before_timestamp=current.timestamp,
                        gap_seconds=delta,
                    )
                )
        return gaps

    def histogram(
        self,
        *,
        case_id: str,
        interval: str = "hour",
        start: Optional[dt.datetime] = None,
        end: Optional[dt.datetime] = None,
        include_demo: bool = True,
    ) -> TimelineHistogram:
        """Bucketed event counts for timeline visualisation."""
        if interval not in ("minute", "hour", "day"):
            interval = "hour"
        records = self.events.all_events(case_id=case_id, include_demo=include_demo)

        def floor(value: dt.datetime) -> dt.datetime:
            if interval == "minute":
                return value.replace(second=0, microsecond=0)
            if interval == "day":
                return value.replace(hour=0, minute=0, second=0, microsecond=0)
            return value.replace(minute=0, second=0, microsecond=0)

        counts: dict = {}
        for event in records:
            if event.timestamp is None:
                continue
            if start and event.timestamp < start:
                continue
            if end and event.timestamp > end:
                continue
            key = floor(event.timestamp)
            counts[key] = counts.get(key, 0) + 1

        buckets = [
            TimelineBucket(bucket_start=key, count=counts[key])
            for key in sorted(counts)
        ]
        return TimelineHistogram(
            buckets=buckets, interval=interval, total=sum(counts.values())
        )