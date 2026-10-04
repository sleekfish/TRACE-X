"""Analysis orchestration endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.analysis import (
    AnalysisJobDetail,
    AnalysisJobOut,
    AnalysisJobPage,
    AnalysisRequest,
    AnalysisRunResponse,
)
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("", response_model=AnalysisRunResponse, summary="Run analysis")
def run_analysis(
    payload: AnalysisRequest,
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> AnalysisRunResponse:
    result: Dict[str, Any] = AnalysisService(db).run(payload, actor_id=actor_id)
    return AnalysisRunResponse.model_validate(result)


@router.get("/jobs", response_model=AnalysisJobPage, summary="List analysis jobs")
def list_jobs(
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    tool: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> AnalysisJobPage:
    rows, total = AnalysisService(db).list_jobs(
        case_id=case_id,
        evidence_id=evidence_id,
        tool=tool,
        status=status,
        limit=limit,
        offset=offset,
    )
    return AnalysisJobPage(
        items=[AnalysisJobOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/jobs/{job_id}", response_model=AnalysisJobDetail, summary="Get a job")
def get_job(job_id: str, db: Session = Depends(get_session)) -> AnalysisJobDetail:
    return AnalysisJobDetail.model_validate(AnalysisService(db).get_job(job_id))