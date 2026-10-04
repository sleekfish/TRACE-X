"""Evidence graph endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.relationship import (
    GraphQuery,
    GraphResponse,
    RelationshipOut,
    RelationshipPage,
)
from app.services.graph_service import GraphService
from app.services.relationship_service import RelationshipService

router = APIRouter(tags=["graph"])


@router.get("/graph", response_model=GraphResponse, summary="Build the evidence graph")
def build_graph(
    case_id: Optional[str] = None,
    include_evidence: bool = True,
    include_indicators: bool = True,
    include_events: bool = False,
    include_findings: bool = True,
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    max_nodes: int = Query(default=300, ge=1, le=2000),
    db: Session = Depends(get_session),
) -> GraphResponse:
    query = GraphQuery(
        case_id=case_id,
        include_evidence=include_evidence,
        include_indicators=include_indicators,
        include_events=include_events,
        include_findings=include_findings,
        min_confidence=min_confidence,
        max_nodes=max_nodes,
    )
    return GraphService(db).build(query)


@router.get(
    "/relationships",
    response_model=RelationshipPage,
    summary="List relationships",
)
def list_relationships(
    case_id: Optional[str] = None,
    relationship_type: Optional[str] = None,
    source_type: Optional[str] = None,
    target_type: Optional[str] = None,
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> RelationshipPage:
    rows, total = RelationshipService(db).list_relationships(
        case_id=case_id,
        relationship_type=relationship_type,
        source_type=source_type,
        target_type=target_type,
        min_confidence=min_confidence,
        limit=limit,
        offset=offset,
    )
    return RelationshipPage(
        items=[RelationshipOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )