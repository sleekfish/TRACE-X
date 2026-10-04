"""AI explanation layer endpoints (Kimi)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.ai import ExplainRequest, ExplainResponse
from app.services.ai_service import AIService

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/status", summary="Whether the AI explanation layer is available")
def ai_status(db: Session = Depends(get_session)) -> dict:
    service = AIService(db)
    return {"available": service.available()}


@router.post("/explain", response_model=ExplainResponse, summary="Explain an entity")
def explain(
    payload: ExplainRequest,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> ExplainResponse:
    return AIService(db).explain(payload, actor_id=actor_id)