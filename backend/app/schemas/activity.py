"""Audit activity schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class ActivityOut(ORMModel):
    id: str
    user_id: Optional[str] = None
    case_id: Optional[str] = None
    action: str
    entity_type: str
    entity_id: str
    description: str
    activity_metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: UTCDateTime


class ActivityPage(Page[ActivityOut]):
    pass