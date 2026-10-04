"""Indicator schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class IndicatorOut(ORMModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    type: str
    value: str
    normalized_value: str
    confidence: float
    first_seen: Optional[UTCDateTime] = None
    last_seen: Optional[UTCDateTime] = None
    source: str
    is_demo: bool
    created_at: UTCDateTime


class IndicatorCreate(APIModel):
    type: str = Field(min_length=1, max_length=32)
    value: str = Field(min_length=1)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "analyst"


class IndicatorTypeCount(APIModel):
    type: str
    count: int


class IndicatorStatistics(APIModel):
    total: int = 0
    unique_normalized: int = 0
    by_type: List[IndicatorTypeCount] = Field(default_factory=list)


class IndicatorPage(Page[IndicatorOut]):
    pass


class IndicatorDetail(IndicatorOut):
    related_cases: List[str] = Field(default_factory=list)
    related_evidence: List[str] = Field(default_factory=list)
    occurrence_count: int = 0
    context: Dict[str, Any] = Field(default_factory=dict)