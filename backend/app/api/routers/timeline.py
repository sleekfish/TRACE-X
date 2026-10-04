"""Unified forensic timeline endpoints."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.timeline import TimelineHistogram, TimelineResponse
from app.services.timeline_service import TimelineService
from app.utils.timestamps import parse_timestamp

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("/{case_id}", response_model=TimelineResponse, summary="Merged timeline")
def build_timeline(
    case_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    event_type: Optional[List[str]] = Query(default=None),
    source: Optional[List[str]] = Query(default=None),
    include_demo: bool = True,
    limit: int = Query(default=2000, ge=1, le=20000),
    db: Session = Depends(get_session),
) -> TimelineResponse:
    return TimelineService(db).build(
        case_id=case_id,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
        event_types=event_type,
        sources=source,
        include_demo=include_demo,
        limit=limit,
    )


@router.get(
    "/{case_id}/histogram",
    response_model=TimelineHistogram,
    summary="Bucketed event counts",
)
def timeline_histogram(
    case_id: str,
    interval: str = Query(default="hour", pattern="^(minute|hour|day)$"),
    start: Optional[str] = None,
    end: Optional[str] = None,
    include_demo: bool = True,
    db: Session = Depends(get_session),
) -> TimelineHistogram:
    return TimelineService(db).histogram(
        case_id=case_id,
        interval=interval,
        start=parse_timestamp(start) if start else None,
        end=parse_timestamp(end) if end else None,
        include_demo=include_demo,
    )