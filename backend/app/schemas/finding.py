"""Finding schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.models.enums import FindingStatus, Severity
from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class FindingCreate(APIModel):
    title: str = Field(min_length=1, max_length=512)
    description: str = ""
    severity: str = Severity.MEDIUM
    status: str = FindingStatus.REQUIRES_REVIEW
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    indicator_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    analyst_notes: str = ""


class FindingUpdate(APIModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    analyst_notes: Optional[str] = None
    evidence_ids: Optional[List[str]] = None
    indicator_ids: Optional[List[str]] = None
    event_ids: Optional[List[str]] = None


class FindingOut(ORMModel):
    id: str
    case_id: str
    title: str
    description: str
    severity: str
    status: str
    confidence: float
    evidence_ids: List[str] = Field(default_factory=list)
    indicator_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    historical_cases: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    analyst_notes: str
    is_demo: bool
    created_at: UTCDateTime
    updated_at: UTCDateTime


class FindingPage(Page[FindingOut]):
    pass