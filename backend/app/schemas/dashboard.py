"""Dashboard / overview schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from app.schemas.activity import ActivityOut
from app.schemas.analysis import ToolInfo
from app.schemas.case import CaseSummary
from app.schemas.common import APIModel, OptionalUTCDateTime


class SeverityCount(APIModel):
    severity: str
    count: int = 0


class DashboardTotals(APIModel):
    cases: int = 0
    open_cases: int = 0
    evidence: int = 0
    events: int = 0
    indicators: int = 0
    findings: int = 0
    relationships: int = 0
    analysis_jobs: int = 0
    failed_jobs: int = 0
    demo_records: int = 0


class DashboardSummary(APIModel):
    totals: DashboardTotals = Field(default_factory=DashboardTotals)
    findings_by_severity: List[SeverityCount] = Field(default_factory=list)
    recent_cases: List[CaseSummary] = Field(default_factory=list)
    recent_activity: List[ActivityOut] = Field(default_factory=list)
    integrations: List[ToolInfo] = Field(default_factory=list)
    real_analysis_available: bool = False
    last_event_at: OptionalUTCDateTime = None
    note: str = ""