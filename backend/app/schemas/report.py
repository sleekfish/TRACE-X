"""Report schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from app.schemas.common import APIModel, UTCDateTime


class ReportRequest(APIModel):
    case_id: str
    title: Optional[str] = None
    format: str = Field(default="markdown", description="markdown | json")
    include_timeline: bool = True
    include_indicators: bool = True
    include_findings: bool = True
    include_evidence: bool = True
    include_integrations: bool = True
    include_ai_summary: bool = Field(
        default=False,
        description="Adds a Kimi-generated narrative summary when configured.",
    )
    persist: bool = Field(
        default=False,
        description="Write the report to report storage and return its path.",
    )


class ReportOut(APIModel):
    case_id: str
    case_number: str = ""
    title: str = ""
    format: str = "markdown"
    generated_at: UTCDateTime
    content: str = ""
    filename: Optional[str] = None
    storage_path: Optional[str] = None
    size_bytes: int = 0
    sections: List[str] = Field(default_factory=list)
    ai_summary_included: bool = False
    ai_summary_available: bool = False
    notes: List[str] = Field(default_factory=list)


class ReportFileInfo(APIModel):
    filename: str
    case_id: str
    format: str
    size_bytes: int
    created_at: UTCDateTime