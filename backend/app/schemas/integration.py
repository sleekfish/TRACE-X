"""Integration status schemas."""

from __future__ import annotations

from typing import List

from pydantic import Field

from app.schemas.analysis import ToolInfo
from app.schemas.common import APIModel


class IntegrationStatusOut(APIModel):
    """Honest snapshot of every external integration.

    ``real_analysis_available`` is true only when at least one *external
    forensic binary* can actually be executed on this host.
    """

    integrations: List[ToolInfo] = Field(default_factory=list)
    real_analysis_available: bool = False
    available_tools: List[str] = Field(default_factory=list)
    unavailable_tools: List[str] = Field(default_factory=list)
    note: str = ""


class IntegrationCheckResult(APIModel):
    name: str
    status: str
    detail: str = ""
    version: str | None = None