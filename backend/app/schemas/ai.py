"""AI explanation layer schemas.

Kimi is used ONLY to explain, summarise and contextualise data that TRACE-X has
already produced.  It never invents findings and every response is explicitly
flagged as AI-generated text requiring human verification.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, UTCDateTime

AI_DISCLAIMER = (
    "AI-generated explanation. This text is a narrative aid only and is not "
    "forensic evidence. Verify every statement against the underlying "
    "evidence before relying on it."
)


class ExplainRequest(APIModel):
    case_id: str
    entity_type: str = Field(
        default="case",
        description="case | finding | indicator | evidence | timeline",
    )
    entity_id: Optional[str] = None
    question: Optional[str] = Field(
        default=None,
        description="Optional specific question. Defaults to a case overview.",
    )


class ExplainResponse(APIModel):
    explanation: str = ""
    available: bool = False
    provider: str = "kimi"
    model: str = ""
    generated_at: UTCDateTime
    is_ai_generated: bool = True
    disclaimer: str = AI_DISCLAIMER
    context_used: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)