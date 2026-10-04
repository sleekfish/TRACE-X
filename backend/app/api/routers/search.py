"""Global search endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.search import SearchRequest, SearchResponse
from app.services.search_service import SearchService

router = APIRouter(prefix="/search", tags=["search"])


@router.post("", response_model=SearchResponse, summary="Search across entities")
def global_search(
    payload: SearchRequest, db: Session = Depends(get_session)
) -> SearchResponse:
    return SearchService(db).search(payload)


@router.get("", response_model=SearchResponse, summary="Search (query string)")
def global_search_get(
    q: str,
    case_id: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_session),
) -> SearchResponse:
    return SearchService(db).search(
        SearchRequest(query=q, case_id=case_id, limit=limit)
    )