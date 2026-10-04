"""Timeline event endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.common import Message
from app.schemas.event import EventCreate, EventOut, EventPage, EventStatistics
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventPage, summary="List events")
def list_events(
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    include_demo: bool = True,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> EventPage:
    rows, total = EventService(db).list_events(
        case_id=case_id,
        evidence_id=evidence_id,
        event_type=event_type,
        source=source,
        start=start,
        end=end,
        include_demo=include_demo,
        limit=limit,
        offset=offset,
    )
    return EventPage(
        items=[EventOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/statistics",
    response_model=EventStatistics,
    summary="Event counts by source/type",
)
def event_statistics(
    case_id: Optional[str] = None, db: Session = Depends(get_session)
) -> EventStatistics:
    return EventStatistics.model_validate(
        EventService(db).statistics(case_id=case_id)
    )


@router.post(
    "/cases/{case_id}",
    response_model=EventOut,
    status_code=201,
    summary="Create an analyst event",
)
def create_event(
    case_id: str,
    payload: EventCreate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> EventOut:
    event = EventService(db).create_event(case_id, payload, actor_id=actor_id)
    return EventOut.model_validate(event)


@router.get("/{event_id}", response_model=EventOut, summary="Get an event")
def get_event(event_id: str, db: Session = Depends(get_session)) -> EventOut:
    return EventOut.model_validate(EventService(db).get_event(event_id))


@router.delete("/{event_id}", response_model=Message, summary="Delete an event")
def delete_event(event_id: str, db: Session = Depends(get_session)) -> Message:
    EventService(db).delete_event(event_id)
    return Message(message=f"Event '{event_id}' deleted.")