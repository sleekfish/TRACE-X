"""Indicator services."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.models.case import Case
from app.models.enums import RelationshipType
from app.models.event import Event
from app.models.evidence import Evidence
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.schemas.indicator import IndicatorCreate
from app.services.base import BaseService
from app.utils.indicators import SUPPORTED_TYPES, canonical_indicator


class IndicatorService(BaseService):
    """Read and manage indicators."""

    def get_indicator(self, indicator_id: str) -> Indicator:
        return self.get_or_404(Indicator, indicator_id, "Indicator")

    def list_indicators(
        self,
        *,
        case_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        indicator_type: Optional[str] = None,
        search: Optional[str] = None,
        min_confidence: Optional[float] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Indicator], int]:
        stmt = select(Indicator).order_by(Indicator.created_at.desc())
        if case_id:
            stmt = stmt.where(Indicator.case_id == case_id)
        if evidence_id:
            stmt = stmt.where(Indicator.evidence_id == evidence_id)
        if indicator_type:
            stmt = stmt.where(Indicator.type == indicator_type.upper())
        if min_confidence is not None:
            stmt = stmt.where(Indicator.confidence >= min_confidence)
        if not include_demo:
            stmt = stmt.where(Indicator.is_demo.is_(False))
        if search:
            pattern = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                func.lower(Indicator.value).like(pattern)
                | func.lower(Indicator.normalized_value).like(pattern)
            )
        return self.paginate(stmt, limit=limit, offset=offset)

    def statistics(self, *, case_id: Optional[str] = None) -> Dict[str, Any]:
        filters = []
        if case_id:
            filters.append(Indicator.case_id == case_id)

        total = int(
            self.db.execute(
                select(func.count()).select_from(Indicator).where(*filters)
            ).scalar()
            or 0
        )
        unique_values = int(
            self.db.execute(
                select(func.count(func.distinct(Indicator.normalized_value))).where(*filters)
            ).scalar()
            or 0
        )
        by_type_stmt = (
            select(Indicator.type, func.count())
            .where(*filters)
            .group_by(Indicator.type)
            .order_by(func.count().desc())
        )
        return {
            "total": total,
            "unique_normalized": unique_values,
            "by_type": [
                {"type": row[0], "count": row[1]}
                for row in self.db.execute(by_type_stmt).all()
            ],
        }

    def detail(self, indicator_id: str) -> Dict[str, Any]:
        """Build the detail view for a single indicator, including provenance."""
        indicator = self.get_indicator(indicator_id)

        occurrence_count = int(
            self.db.execute(
                select(func.count())
                .select_from(Relationship)
                .where(
                    Relationship.target_type == "indicator",
                    Relationship.target_id == indicator.id,
                    Relationship.relationship_type == RelationshipType.EVENT_INDICATOR,
                )
            ).scalar()
            or 0
        )

        related_cases = [
            row[0]
            for row in self.db.execute(
                select(Indicator.case_id)
                .where(Indicator.normalized_value == indicator.normalized_value)
                .distinct()
            ).all()
        ]
        related_evidence = [
            row[0]
            for row in self.db.execute(
                select(Indicator.evidence_id)
                .where(
                    Indicator.normalized_value == indicator.normalized_value,
                    Indicator.evidence_id.is_not(None),
                )
                .distinct()
            ).all()
        ]

        # A few representative events for context (never a conclusion).
        events = self.db.execute(
            select(Event.id, Event.timestamp, Event.description)
            .join(Relationship, Relationship.source_id == Event.id)
            .where(
                Relationship.target_type == "indicator",
                Relationship.target_id == indicator.id,
                Relationship.relationship_type == RelationshipType.EVENT_INDICATOR,
            )
            .order_by(Event.timestamp.asc().nulls_last())
            .limit(10)
        ).all()

        return {
            "related_cases": related_cases,
            "related_evidence": [eid for eid in related_evidence if eid],
            "occurrence_count": occurrence_count,
            "context": {
                "sample_events": [
                    {"event_id": row[0], "timestamp": row[1], "description": row[2]}
                    for row in events
                ],
                "seen_in_case_count": len(related_cases),
            },
        }

    def create_indicator(
        self,
        case_id: str,
        payload: IndicatorCreate,
        *,
        actor_id: Optional[str] = None,
    ) -> Indicator:
        if not self.db.get(Case, case_id):
            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})
        indicator_type = payload.type.strip().upper()
        if indicator_type not in SUPPORTED_TYPES:
            raise ValidationError(
                f"Unsupported indicator type '{payload.type}'.",
                {"allowed": SUPPORTED_TYPES},
            )
        normalized = canonical_indicator(indicator_type, payload.value)

        existing = self.db.execute(
            select(Indicator).where(
                Indicator.case_id == case_id,
                Indicator.type == indicator_type,
                Indicator.normalized_value == normalized,
            )
        ).scalars().first()
        if existing is not None:
            return existing

        indicator = Indicator(
            case_id=case_id,
            evidence_id=None,
            type=indicator_type,
            value=payload.value.strip(),
            normalized_value=normalized,
            confidence=payload.confidence,
            source=payload.source or "analyst",
            is_demo=False,
        )
        self.db.add(indicator)
        self.flush()
        self._link_case(indicator)
        self.commit()
        return indicator

    def _link_case(self, indicator: Indicator) -> None:
        exists = self.db.execute(
            select(Relationship.id).where(
                Relationship.source_type == "case",
                Relationship.source_id == indicator.case_id,
                Relationship.target_type == "indicator",
                Relationship.target_id == indicator.id,
                Relationship.relationship_type == RelationshipType.CASE_INDICATOR,
            )
        ).scalars().first()
        if exists:
            return
        self.db.add(
            Relationship(
                source_type="case",
                source_id=indicator.case_id,
                target_type="indicator",
                target_id=indicator.id,
                relationship_type=RelationshipType.CASE_INDICATOR,
                confidence=indicator.confidence,
                evidence_reference=indicator.normalized_value,
                requires_review=False,
            )
        )
        self.db.flush()

    def delete_indicator(self, indicator_id: str) -> None:
        indicator = self.get_indicator(indicator_id)
        self.db.execute(
            Relationship.__table__.delete().where(
                Relationship.target_type == "indicator",
                Relationship.target_id == indicator.id,
            )
        )
        self.db.delete(indicator)
        self.commit()