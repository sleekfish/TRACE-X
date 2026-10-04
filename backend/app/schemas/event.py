"""Timeline event schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class EventOut(ORMModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    timestamp: Optional[UTCDateTime] = None
    event_type: str
    source: str
    description: str
    raw_reference: str
    confidence: float
    event_metadata: Dict[str, Any] = Field(default_factory=dict)
    is_demo: bool
    created_at: UTCDateTime


class EventCreate(APIModel):
    """Manual event entry (analyst-authored, source = 'analyst')."""

    timestamp: Optional[UTCDateTime] = None
    event_type: str = "GENERIC_EVENT"
    description: str = Field(min_length=1, max_length=4000)
    raw_reference: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    event_metadata: Dict[str, Any] = Field(default_factory=dict)


class EventPage(Page[EventOut]):
    pass


class EventSourceCount(APIModel):
    source: str
    count: int


class EventTypeCount(APIModel):
    event_type: str
    count: int


class EventStatistics(APIModel):
    total: int = 0
    by_source: List[EventSourceCount] = Field(default_factory=list)
    by_type: List[EventTypeCount] = Field(default_factory=list)
    first_event_at: Optional[UTCDateTime] = None
    last_event_at: Optional[UTCDateTime] = None