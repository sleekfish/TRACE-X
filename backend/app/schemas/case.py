"""Case schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from app.models.enums import CaseStatus, Severity
from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class CaseCreate(APIModel):
    case_number: Optional[str] = Field(
        default=None,
        max_length=32,
        description="Optional; auto-generated when omitted.",
    )
    title: str = Field(min_length=1, max_length=512)
    description: str = ""
    status: str = CaseStatus.OPEN
    severity: str = Severity.MEDIUM
    investigator_id: Optional[str] = None


class CaseUpdate(APIModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    investigator_id: Optional[str] = None


class CaseSummary(ORMModel):
    """Lightweight case representation for list views."""

    id: str
    case_number: str
    title: str
    status: str
    severity: str
    is_demo: bool
    created_at: UTCDateTime
    updated_at: UTCDateTime


class CaseOut(CaseSummary):
    description: str
    investigator_id: Optional[str] = None


class CaseStats(APIModel):
    """Aggregate counts for a single case."""

    evidence_count: int = 0
    event_count: int = 0
    indicator_count: int = 0
    finding_count: int = 0
    relationship_count: int = 0
    analysis_job_count: int = 0
    first_event_at: Optional[UTCDateTime] = None
    last_event_at: Optional[UTCDateTime] = None


class CaseDetail(CaseOut):
    stats: CaseStats = Field(default_factory=CaseStats)


class CasePage(Page[CaseSummary]):
    pass


class CaseList(APIModel):
    items: List[CaseSummary] = Field(default_factory=list)
    total: int = 0