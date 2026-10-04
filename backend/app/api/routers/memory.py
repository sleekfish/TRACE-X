"""Persistent forensic memory endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.memory import (
    MemoryOverview,
    MemorySearchRequest,
    MemorySearchResponse,
)
from app.services.memory_service import MemoryService

router = APIRouter(prefix="/memory", tags=["memory"])


@router.post("/search", response_model=MemorySearchResponse, summary="Search memory")
def search_memory(
    payload: MemorySearchRequest, db: Session = Depends(get_session)
) -> MemorySearchResponse:
    return MemoryService(db).search(payload)


@router.get("/overview", response_model=MemoryOverview, summary="Memory statistics")
def memory_overview(db: Session = Depends(get_session)) -> MemoryOverview:
    return MemoryService(db).overview()