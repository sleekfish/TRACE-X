"""Evidence schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class EvidenceUpdate(APIModel):
    notes: Optional[str] = None
    acquisition_source: Optional[str] = Field(default=None, max_length=255)
    evidence_type: Optional[str] = Field(default=None, max_length=32)


class EvidenceOut(ORMModel):
    id: str
    case_id: str
    filename: str
    original_filename: str
    evidence_type: str
    detection_method: str
    mime_type: str
    file_size: int
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    acquisition_source: str
    uploaded_by: Optional[str] = None
    analysis_status: str
    notes: str
    is_demo: bool
    created_at: UTCDateTime
    updated_at: UTCDateTime


class EvidenceDetail(EvidenceOut):
    tool_provenance: Dict[str, Any] = Field(default_factory=dict)
    storage_path: str = ""
    supported_tools: List[str] = Field(default_factory=list)


class EvidenceIntegrity(APIModel):
    """Result of a re-hash / integrity verification."""

    evidence_id: str
    filename: str
    stored_sha256: str
    computed_sha256: str
    stored_sha1: Optional[str] = None
    computed_sha1: Optional[str] = None
    stored_md5: Optional[str] = None
    computed_md5: Optional[str] = None
    verified: bool
    verified_at: UTCDateTime


class EvidencePage(Page[EvidenceOut]):
    pass