"""Indicator endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.common import Message
from app.schemas.indicator import (
    IndicatorCreate,
    IndicatorDetail,
    IndicatorOut,
    IndicatorPage,
    IndicatorStatistics,
)
from app.services.indicator_service import IndicatorService

router = APIRouter(prefix="/indicators", tags=["indicators"])


@router.get("", response_model=IndicatorPage, summary="List indicators")
def list_indicators(
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    indicator_type: Optional[str] = Query(default=None, alias="type"),
    search: Optional[str] = None,
    include_demo: bool = True,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> IndicatorPage:
    rows, total = IndicatorService(db).list_indicators(
        case_id=case_id,
        evidence_id=evidence_id,
        indicator_type=indicator_type,
        search=search,
        include_demo=include_demo,
        limit=limit,
        offset=offset,
    )
    return IndicatorPage(
        items=[IndicatorOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/statistics",
    response_model=IndicatorStatistics,
    summary="Indicator counts by type",
)
def indicator_statistics(
    case_id: Optional[str] = None, db: Session = Depends(get_session)
) -> IndicatorStatistics:
    return IndicatorStatistics.model_validate(
        IndicatorService(db).statistics(case_id=case_id)
    )


@router.post(
    "/cases/{case_id}",
    response_model=IndicatorOut,
    status_code=201,
    summary="Create an indicator for a case",
)
def create_indicator(
    case_id: str,
    payload: IndicatorCreate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> IndicatorOut:
    indicator = IndicatorService(db).create_indicator(case_id, payload, actor_id=actor_id)
    return IndicatorOut.model_validate(indicator)


@router.get("/{indicator_id}", response_model=IndicatorDetail, summary="Indicator detail")
def get_indicator(indicator_id: str, db: Session = Depends(get_session)) -> IndicatorDetail:
    return IndicatorDetail.model_validate(IndicatorService(db).detail(indicator_id))


@router.delete("/{indicator_id}", response_model=Message, summary="Delete an indicator")
def delete_indicator(indicator_id: str, db: Session = Depends(get_session)) -> Message:
    IndicatorService(db).delete_indicator(indicator_id)
    return Message(message=f"Indicator '{indicator_id}' deleted.")