"""Dashboard overview endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.dashboard import DashboardSummary
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardSummary, summary="Dashboard summary")
def dashboard_summary(
    recent_limit: int = Query(default=5, ge=1, le=50),
    db: Session = Depends(get_session),
) -> DashboardSummary:
    return DashboardService(db).summary(recent_limit=recent_limit)