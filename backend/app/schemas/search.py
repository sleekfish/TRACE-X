"""Global search schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from app.schemas.common import APIModel, OptionalUTCDateTime


class SearchRequest(APIModel):
    query: str = Field(min_length=1, max_length=512)
    case_id: Optional[str] = None
    entity_types: List[str] = Field(
        default_factory=list,
        description="Any of: case, evidence, event, indicator, finding, analysis_job.",
    )
    limit: int = Field(default=50, ge=1, le=500)


class SearchHit(APIModel):
    entity_type: str
    entity_id: str
    case_id: Optional[str] = None
    title: str = ""
    snippet: str = ""
    score: float = 0.0
    timestamp: OptionalUTCDateTime = None
    metadata: dict = Field(default_factory=dict)


class SearchTypeCount(APIModel):
    entity_type: str
    count: int = 0


class SearchResponse(APIModel):
    query: str
    hits: List[SearchHit] = Field(default_factory=list)
    total: int = 0
    by_type: List[SearchTypeCount] = Field(default_factory=list)
    note: str = ""