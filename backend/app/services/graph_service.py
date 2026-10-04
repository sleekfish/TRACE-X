"""Evidence-graph construction.

Turns stored relationships into a node/edge payload for visualisation.  Nodes
are limited to entities the caller asked for, and the graph is capped at
``max_nodes`` (highest-degree nodes win) so the API never returns an unbounded
payload.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.models.case import Case
from app.models.event import Event
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.schemas.relationship import GraphEdge, GraphNode, GraphQuery, GraphResponse
from app.services.base import BaseService
from app.services.case_service import CaseService


class GraphService(BaseService):
    """Assemble the entity graph for a case (or the whole workspace)."""

    NODE_TYPES = ("case", "evidence", "indicator", "event", "finding")

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.cases = CaseService(db)

    def build(self, query: GraphQuery) -> GraphResponse:
        included = self._included_types(query)
        node_ids, labels, properties = self._collect_nodes(query, included)

        edges = self._collect_edges(node_ids, included, query.min_confidence)

        degree: Dict[str, int] = {}
        for edge in edges:
            degree[edge.source] = degree.get(edge.source, 0) + 1
            degree[edge.target] = degree.get(edge.target, 0) + 1

        truncated = len(node_ids) > query.max_nodes
        if truncated:
            retained = {
                node_id
                for node_id, _ in sorted(
                    degree.items(), key=lambda item: item[1], reverse=True
                )[: query.max_nodes]
            }
            edges = [
                edge for edge in edges if edge.source in retained and edge.target in retained
            ]
            node_ids = node_ids & retained

        nodes = [
            GraphNode(
                id=node_id,
                label=labels.get(node_id, node_id),
                node_type=properties.get(node_id, {}).get("node_type", "unknown"),
                properties=properties.get(node_id, {}),
            )
            for node_id in sorted(node_ids)
        ]

        note = ""
        if truncated:
            note = (
                f"Graph truncated to {query.max_nodes} most-connected nodes. "
                "Increase max_nodes or narrow the filters to see more."
            )
        elif not nodes:
            note = "No graph entities matched the requested filters."

        return GraphResponse(
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
            truncated=truncated,
            note=note,
        )

    # --- Node collection ----------------------------------------------------
    def _included_types(self, query: GraphQuery) -> Set[str]:
        included = {"case"}
        if query.include_evidence:
            included.add("evidence")
        if query.include_indicators:
            included.add("indicator")
        if query.include_events:
            included.add("event")
        if query.include_findings:
            included.add("finding")
        return included

    def _collect_nodes(
        self, query: GraphQuery, included: Set[str]
    ) -> Tuple[Set[str], Dict[str, str], Dict[str, Dict[str, Any]]]:
        node_ids: Set[str] = set()
        labels: Dict[str, str] = {}
        properties: Dict[str, Dict[str, Any]] = {}

        case_ids: List[str]
        if query.case_id:
            case = self.db.get(Case, query.case_id)
            if case is None:
                raise ValidationError(
                    f"Case '{query.case_id}' does not exist.", {"case_id": query.case_id}
                )
            case_ids = [case.id]
        else:
            case_ids = [row[0] for row in self.db.execute(select(Case.id)).all()]

        if case_ids and "case" in included:
            for case in self.db.execute(
                select(Case).where(Case.id.in_(case_ids))
            ).scalars().all():
                node_ids.add(case.id)
                labels[case.id] = f"{case.case_number}: {case.title}"
                properties[case.id] = {
                    "node_type": "case",
                    "case_number": case.case_number,
                    "status": case.status,
                    "severity": case.severity,
                    "is_demo": case.is_demo,
                }

        if not case_ids:
            return node_ids, labels, properties

        if "evidence" in included:
            for item in self.db.execute(
                select(Evidence).where(Evidence.case_id.in_(case_ids))
            ).scalars().all():
                node_ids.add(item.id)
                labels[item.id] = item.original_filename
                properties[item.id] = {
                    "node_type": "evidence",
                    "case_id": item.case_id,
                    "evidence_type": item.evidence_type,
                    "sha256": item.sha256,
                    "is_demo": item.is_demo,
                }

        if "indicator" in included:
            for item in self.db.execute(
                select(Indicator).where(Indicator.case_id.in_(case_ids))
            ).scalars().all():
                node_ids.add(item.id)
                labels[item.id] = f"{item.type}: {item.normalized_value}"
                properties[item.id] = {
                    "node_type": "indicator",
                    "case_id": item.case_id,
                    "indicator_type": item.type,
                    "normalized_value": item.normalized_value,
                    "confidence": item.confidence,
                    "is_demo": item.is_demo,
                }

        if "event" in included:
            for item in self.db.execute(
                select(Event).where(Event.case_id.in_(case_ids))
            ).scalars().all():
                node_ids.add(item.id)
                labels[item.id] = f"{item.event_type}: {item.description[:60]}"
                properties[item.id] = {
                    "node_type": "event",
                    "case_id": item.case_id,
                    "event_type": item.event_type,
                    "source": item.source,
                    "timestamp": item.timestamp.isoformat() if item.timestamp else None,
                    "is_demo": item.is_demo,
                }

        if "finding" in included:
            for item in self.db.execute(
                select(Finding).where(Finding.case_id.in_(case_ids))
            ).scalars().all():
                node_ids.add(item.id)
                labels[item.id] = item.title
                properties[item.id] = {
                    "node_type": "finding",
                    "case_id": item.case_id,
                    "severity": item.severity,
                    "status": item.status,
                    "is_demo": item.is_demo,
                }

        return node_ids, labels, properties

    # --- Edge collection ----------------------------------------------------
    def _collect_edges(
        self, node_ids: Set[str], included: Set[str], min_confidence: float
    ) -> List[GraphEdge]:
        if not node_ids:
            return []

        stmt = (
            select(Relationship)
            .where(
                Relationship.source_id.in_(node_ids),
                Relationship.target_id.in_(node_ids),
                Relationship.confidence >= min_confidence,
            )
            .order_by(Relationship.confidence.desc())
        )
        edges: List[GraphEdge] = []
        seen: Set[Tuple[str, str, str]] = set()
        for relationship in self.db.execute(stmt).scalars().all():
            if relationship.source_type not in included:
                continue
            if relationship.target_type not in included:
                continue
            key = (
                relationship.source_id,
                relationship.target_id,
                relationship.relationship_type,
            )
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                GraphEdge(
                    id=relationship.id,
                    source=relationship.source_id,
                    target=relationship.target_id,
                    relationship_type=relationship.relationship_type,
                    confidence=relationship.confidence,
                    requires_review=relationship.requires_review,
                    properties={
                        "evidence_reference": relationship.evidence_reference,
                        "is_demo": relationship.is_demo,
                        **(relationship.relationship_metadata or {}),
                    },
                )
            )
        return edges