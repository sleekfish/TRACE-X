"""Relationship read services (the evidence graph's edge store)."""

from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.relationship import Relationship
from app.services.base import BaseService


class RelationshipService(BaseService):
    """Query relationships directly."""

    def get_relationship(self, relationship_id: str) -> Relationship:
        return self.get_or_404(Relationship, relationship_id, "Relationship")

    def list_relationships(
        self,
        *,
        entity_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        source_type: Optional[str] = None,
        target_type: Optional[str] = None,
        min_confidence: Optional[float] = None,
        requires_review: Optional[bool] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Relationship], int]:
        stmt = select(Relationship).order_by(Relationship.created_at.desc())
        if entity_id:
            stmt = stmt.where(
                (Relationship.source_id == entity_id) | (Relationship.target_id == entity_id)
            )
        if relationship_type:
            stmt = stmt.where(Relationship.relationship_type == relationship_type)
        if source_type:
            stmt = stmt.where(Relationship.source_type == source_type)
        if target_type:
            stmt = stmt.where(Relationship.target_type == target_type)
        if min_confidence is not None:
            stmt = stmt.where(Relationship.confidence >= min_confidence)
        if requires_review is not None:
            stmt = stmt.where(Relationship.requires_review.is_(requires_review))
        if not include_demo:
            stmt = stmt.where(Relationship.is_demo.is_(False))
        return self.paginate(stmt, limit=limit, offset=offset)

    def delete_relationship(self, relationship_id: str) -> None:
        relationship = self.get_relationship(relationship_id)
        self.db.delete(relationship)
        self.commit()