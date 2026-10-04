"""Analysis orchestration schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.models.enums import AnalysisSource
from app.schemas.common import APIModel, ORMModel, Page, OptionalUTCDateTime, UTCDateTime


class AnalysisRequest(APIModel):
    """Request a forensic analysis run.

    ``tools`` may be omitted, in which case every adapter that supports the
    evidence type is considered.  Adapters whose tool is not installed are
    reported as ``UNAVAILABLE`` - they never produce synthetic output.
    """

    evidence_ids: List[str] = Field(default_factory=list)
    tools: Optional[List[str]] = Field(
        default=None,
        description="Explicit adapter names. Omit to auto-select per evidence type.",
    )
    case_id: Optional[str] = Field(
        default=None,
        description="Optional; inferred from the evidence when omitted.",
    )
    force: bool = Field(
        default=False,
        description="Re-run analysis even if a completed job already exists.",
    )
    source: str = Field(
        default=AnalysisSource.REAL,
        description="Provenance tag for the resulting records.",
    )


class AnalysisJobOut(ORMModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    tool: str
    status: str
    source: str
    command: List[str] = Field(default_factory=list)
    started_at: OptionalUTCDateTime = None
    completed_at: OptionalUTCDateTime = None
    exit_code: Optional[int] = None
    error_message: str
    tool_version: str
    adapter_version: str
    evidence_sha256: str
    events_created: int
    indicators_created: int
    job_metadata: Dict[str, Any] = Field(default_factory=dict)
    is_demo: bool
    created_at: UTCDateTime


class AnalysisJobDetail(AnalysisJobOut):
    stdout: str = ""
    stderr: str = ""


class AnalysisJobPage(Page[AnalysisJobOut]):
    pass


class AnalysisSkip(APIModel):
    """An evidence/tool pair that was intentionally not executed."""

    evidence_id: str
    tool: str
    status: str
    reason: str


class AnalysisRunResponse(APIModel):
    jobs: List[AnalysisJobOut] = Field(default_factory=list)
    skipped: List[AnalysisSkip] = Field(default_factory=list)
    events_created: int = 0
    indicators_created: int = 0
    relationships_created: int = 0
    message: str = ""
    warnings: List[str] = Field(default_factory=list)


class ToolInfo(APIModel):
    """Adapter capability description."""

    name: str
    installed: bool
    configured: bool
    status: str
    version: Optional[str] = None
    path: Optional[str] = None
    supported_evidence_types: List[str] = Field(default_factory=list)
    detail: str = ""
    is_external: bool = False