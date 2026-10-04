"""Case management endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.case import (
    CaseCreate,
    CaseDetail,
    CasePage,
    CaseStats,
    CaseSummary,
    CaseUpdate,
)
from app.schemas.common import Message
from app.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=CasePage, summary="List cases")
def list_cases(
    status: Optional[str] = Query(default=None, description="Filter by case status."),
    severity: Optional[str] = Query(default=None, description="Filter by severity."),
    investigator_id: Optional[str] = None,
    search: Optional[str] = Query(default=None, description="Free-text search."),
    include_demo: bool = True,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> CasePage:
    service = CaseService(db)
    rows, total = service.list_cases(
        status=status,
        severity=severity,
        investigator_id=investigator_id,
        search=search,
        include_demo=include_demo,
        limit=limit,
        offset=offset,
    )
    return CasePage(
        items=[CaseSummary.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=CaseDetail, status_code=201, summary="Create a case")
def create_case(
    payload: CaseCreate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> CaseDetail:
    service = CaseService(db)
    case = service.create_case(payload, actor_id=actor_id)
    detail = CaseDetail.model_validate(case)
    detail.stats = service.stats(case.id)
    return detail


@router.get("/{case_id}", response_model=CaseDetail, summary="Get a case with stats")
def get_case(case_id: str, db: Session = Depends(get_session)) -> CaseDetail:
    service = CaseService(db)
    case = service.get_case(case_id)
    detail = CaseDetail.model_validate(case)
    detail.stats = service.stats(case.id)
    return detail


@router.get(
    "/{case_id}/stats",
    response_model=CaseStats,
    summary="Aggregate counts for a case",
)
def case_stats(case_id: str, db: Session = Depends(get_session)) -> CaseStats:
    return CaseService(db).stats(case_id)


@router.get(
    "/{case_id}/overview",
    summary="Compact per-case numbers for the workspace header",
)
def case_overview(case_id: str, db: Session = Depends(get_session)) -> dict:
    from app.services.dashboard_service import DashboardService

    return DashboardService(db).case_overview(case_id)


@router.patch("/{case_id}", response_model=CaseDetail, summary="Update a case")
def update_case(
    case_id: str,
    payload: CaseUpdate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> CaseDetail:
    service = CaseService(db)
    case = service.update_case(case_id, payload, actor_id=actor_id)
    detail = CaseDetail.model_validate(case)
    detail.stats = service.stats(case.id)
    return detail


@router.delete("/{case_id}", response_model=Message, summary="Delete a case")
def delete_case(
    case_id: str,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> Message:
    CaseService(db).delete_case(case_id, actor_id=actor_id)
    return Message(message=f"Case '{case_id}' deleted.")