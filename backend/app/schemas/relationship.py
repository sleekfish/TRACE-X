"""Relationship / graph schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field

from app.schemas.common import APIModel, ORMModel, Page, UTCDateTime


class RelationshipOut(ORMModel):
    id: str
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    relationship_type: str
    confidence: float
    evidence_reference: str
    relationship_metadata: Dict[str, Any] = Field(default_factory=dict)
    requires_review: bool
    is_demo: bool
    created_at: UTCDateTime


class RelationshipPage(Page[RelationshipOut]):
    pass


class GraphNode(APIModel):
    id: str
    label: str
    node_type: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(APIModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence: float = 0.5
    requires_review: bool = True
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphResponse(APIModel):
    """Evidence-graph payload.  ``truncated`` is set when node/edge caps apply."""

    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    truncated: bool = False
    note: str = ""


class GraphQuery(APIModel):
    case_id: Optional[str] = None
    include_evidence: bool = True
    include_indicators: bool = True
    include_events: bool = False
    include_findings: bool = True
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    max_nodes: int = Field(default=300, ge=1, le=2000)