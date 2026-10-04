"""Finding endpoints (analyst-authored conclusions)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.common import Message
from app.schemas.finding import FindingCreate, FindingOut, FindingPage, FindingUpdate
from app.services.finding_service import FindingService

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=FindingPage, summary="List findings")
def list_findings(
    case_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    include_demo: bool = True,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> FindingPage:
    rows, total = FindingService(db).list_findings(
        case_id=case_id,
        severity=severity,
        status=status,
        include_demo=include_demo,
        limit=limit,
        offset=offset,
    )
    return FindingPage(
        items=[FindingOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/cases/{case_id}",
    response_model=FindingOut,
    status_code=201,
    summary="Create a finding for a case",
)
def create_finding(
    case_id: str,
    payload: FindingCreate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> FindingOut:
    finding = FindingService(db).create_finding(case_id, payload, actor_id=actor_id)
    return FindingOut.model_validate(finding)


@router.get("/{finding_id}", response_model=FindingOut, summary="Get a finding")
def get_finding(finding_id: str, db: Session = Depends(get_session)) -> FindingOut:
    return FindingOut.model_validate(FindingService(db).get_finding(finding_id))


@router.patch("/{finding_id}", response_model=FindingOut, summary="Update a finding")
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> FindingOut:
    finding = FindingService(db).update_finding(finding_id, payload, actor_id=actor_id)
    return FindingOut.model_validate(finding)


@router.delete("/{finding_id}", response_model=Message, summary="Delete a finding")
def delete_finding(
    finding_id: str,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> Message:
    FindingService(db).delete_finding(finding_id, actor_id=actor_id)
    return Message(message=f"Finding '{finding_id}' deleted.")