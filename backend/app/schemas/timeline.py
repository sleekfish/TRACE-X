"""Unified forensic timeline schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, OptionalUTCDateTime


class TimelineEntry(APIModel):
    """A single point on the merged, cross-evidence timeline."""

    event_id: str
    timestamp: OptionalUTCDateTime = None
    event_type: str
    source: str
    description: str
    confidence: float = 0.5
    evidence_id: Optional[str] = None
    evidence_filename: Optional[str] = None
    raw_reference: str = ""
    indicators: List[str] = Field(default_factory=list)
    event_metadata: Dict[str, Any] = Field(default_factory=dict)
    is_demo: bool = False


class TimelineGap(APIModel):
    """An unusually large gap between consecutive events (possible gap in
    coverage - presented for investigator review, never as a conclusion)."""

    after_event_id: str
    before_event_id: str
    after_timestamp: OptionalUTCDateTime = None
    before_timestamp: OptionalUTCDateTime = None
    gap_seconds: float = 0.0


class TimelineResponse(APIModel):
    entries: List[TimelineEntry] = Field(default_factory=list)
    total: int = 0
    returned: int = 0
    start: OptionalUTCDateTime = None
    end: OptionalUTCDateTime = None
    truncated: bool = False
    gaps: List[TimelineGap] = Field(default_factory=list)
    note: str = ""


class TimelineBucket(APIModel):
    bucket_start: OptionalUTCDateTime = None
    count: int = 0


class TimelineHistogram(APIModel):
    buckets: List[TimelineBucket] = Field(default_factory=list)
    interval: str = "hour"
    total: int = 0