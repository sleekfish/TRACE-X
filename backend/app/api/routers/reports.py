"""Case report endpoints."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.report import ReportFileInfo, ReportOut, ReportRequest
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportOut, summary="Generate a case report")
def generate_report(
    payload: ReportRequest,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> ReportOut:
    return ReportService(db).generate(payload, actor_id=actor_id)


@router.get("", response_model=List[ReportFileInfo], summary="List persisted reports")
def list_reports(
    case_id: Optional[str] = None, db: Session = Depends(get_session)
) -> List[ReportFileInfo]:
    return ReportService(db).list_reports(case_id=case_id)


@router.get(
    "/{filename:path}",
    response_model=ReportOut,
    summary="Read a persisted report by filename",
)
def read_report(
    filename: str,
    case_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_session),
) -> ReportOut:
    return ReportService(db).read_report(filename, case_id=case_id)