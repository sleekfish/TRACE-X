"""Audit activity trail endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.activity import ActivityOut, ActivityPage
from app.services.activity_service import ActivityService

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("", response_model=ActivityPage, summary="List audit activity")
def list_activity(
    user_id: Optional[str] = None,
    case_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> ActivityPage:
    rows, total = ActivityService(db).list_activities(
        user_id=user_id,
        case_id=case_id,
        action=action,
        limit=limit,
        offset=offset,
    )
    return ActivityPage(
        items=[ActivityOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )