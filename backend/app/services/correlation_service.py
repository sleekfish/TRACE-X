"""Cross-case correlation.

Finds indicators that a case shares with previously ingested cases and records
the link as a relationship.  Correlations are *leads for review* - they are
always created with ``requires_review = True`` and carry the confidence of the
weakest contributing indicator, never an invented certainty.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.models.case import Case
from app.models.enums import RelationshipType
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService

# Indicator type -> relationship type for indicator-to-indicator links.
_TYPE_TO_RELATIONSHIP = {
    "IP": RelationshipType.SAME_IP,
    "DOMAIN": RelationshipType.SAME_DOMAIN,
    "URL": RelationshipType.SAME_URL,
    "HASH": RelationshipType.SAME_HASH,
    "HOSTNAME": RelationshipType.SAME_HOSTNAME,
    "EMAIL": RelationshipType.SAME_EMAIL,
    "CERTIFICATE": RelationshipType.SAME_CERTIFICATE,
}


class CorrelationService(BaseService):
    """Builds and reads cross-case relationships derived from shared indicators."""

    # --- Correlation --------------------------------------------------------
    def correlate_case(
        self, case_id: str, *, actor_id: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.db.get(Case, case_id):
            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})

        local = list(
            self.db.execute(
                select(Indicator).where(Indicator.case_id == case_id)
            ).scalars().all()
        )
        if not local:
            return {
                "case_id": case_id,
                "shared_indicators": 0,
                "relationships_created": 0,
                "correlated_cases": [],
                "message": "This case has no indicators to correlate yet.",
            }

        existing = self._relationship_keys()
        relationships_created = 0
        correlated_cases: Dict[str, Dict[str, Any]] = {}

        for indicator in local:
            others = list(
                self.db.execute(
                    select(Indicator).where(
                        Indicator.normalized_value == indicator.normalized_value,
                        Indicator.case_id != case_id,
                    )
                ).scalars().all()
            )
            if not others:
                continue

            relationship_type = _TYPE_TO_RELATIONSHIP.get(
                indicator.type, RelationshipType.SHARED_INDICATOR
            )
            for other in others:
                confidence = min(indicator.confidence, other.confidence)
                is_demo = indicator.is_demo or other.is_demo
                relationships_created += self._create_indicator_link(
                    existing,
                    indicator,
                    other,
                    relationship_type,
                    confidence=confidence,
                    is_demo=is_demo,
                )
                relationships_created += self._create_case_link(
                    existing,
                    case_id,
                    other.case_id,
                    confidence=confidence,
                    shared_value=indicator.normalized_value,
                    is_demo=is_demo,
                )

                entry = correlated_cases.setdefault(
                    other.case_id,
                    {"case_id": other.case_id, "shared_values": [], "max_confidence": 0.0},
                )
                if indicator.normalized_value not in entry["shared_values"]:
                    entry["shared_values"].append(indicator.normalized_value)
                entry["max_confidence"] = max(entry["max_confidence"], confidence)

        for case_summary in correlated_cases.values():
            case = self.db.get(Case, case_summary["case_id"])
            if case is not None:
                case_summary["case_number"] = case.case_number
                case_summary["case_title"] = case.title

        self.commit()
        log_activity(
            self.db,
            action="correlation.completed",
            user_id=actor_id,
            case_id=case_id,
            entity_type="case",
            entity_id=case_id,
            description=(
                f"Correlation found {len(correlated_cases)} linked case(s) and "
                f"created {relationships_created} relationship(s)."
            ),
            metadata={"relationships_created": relationships_created},
        )
        self.commit()

        return {
            "case_id": case_id,
            "shared_indicators": sum(
                len(entry["shared_values"]) for entry in correlated_cases.values()
            ),
            "relationships_created": relationships_created,
            "correlated_cases": sorted(
                correlated_cases.values(),
                key=lambda item: item["max_confidence"],
                reverse=True,
            ),
            "message": (
                f"{relationships_created} relationship(s) recorded across "
                f"{len(correlated_cases)} historical case(s)."
            ),
        }

    def correlate_all(self, *, actor_id: Optional[str] = None) -> Dict[str, Any]:
        """Correlate every case.  Intended for the seed/backfill script."""
        case_ids = [
            row[0] for row in self.db.execute(select(Case.id)).all()
        ]
        total = 0
        for case_id in case_ids:
            total += self.correlate_case(case_id, actor_id=actor_id)["relationships_created"]
        return {"cases": len(case_ids), "relationships_created": total}

    # --- Reads --------------------------------------------------------------
    def shared_indicators(self, case_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
        """Indicator values in this case that also appear in other cases."""
        stmt = (
            select(
                Indicator.normalized_value,
                Indicator.type,
                func.count(func.distinct(Indicator.case_id)).label("case_count"),
            )
            .where(
                Indicator.normalized_value.in_(
                    select(Indicator.normalized_value).where(Indicator.case_id == case_id)
                ),
                Indicator.case_id != case_id,
            )
            .group_by(Indicator.normalized_value, Indicator.type)
            .order_by(func.count(func.distinct(Indicator.case_id)).desc())
            .limit(limit)
        )
        return [
            {"normalized_value": row[0], "type": row[1], "other_case_count": row[2]}
            for row in self.db.execute(stmt).all()
        ]

    def related_cases(self, case_id: str) -> List[Dict[str, Any]]:
        """Cases connected to ``case_id`` by a HISTORICAL_CORRELATION link."""
        stmt = select(Relationship).where(
            Relationship.relationship_type == RelationshipType.HISTORICAL_CORRELATION,
            Relationship.source_type == "case",
            Relationship.target_type == "case",
            (Relationship.source_id == case_id) | (Relationship.target_id == case_id),
        )
        results: List[Dict[str, Any]] = []
        for relationship in self.db.execute(stmt).scalars().all():
            other_id = (
                relationship.target_id
                if relationship.source_id == case_id
                else relationship.source_id
            )
            case = self.db.get(Case, other_id)
            if case is None:
                continue
            results.append(
                {
                    "relationship_id": relationship.id,
                    "case_id": case.id,
                    "case_number": case.case_number,
                    "case_title": case.title,
                    "case_status": case.status,
                    "confidence": relationship.confidence,
                    "shared_values": (relationship.relationship_metadata or {}).get(
                        "shared_values", []
                    ),
                    "requires_review": relationship.requires_review,
                }
            )
        return sorted(results, key=lambda item: item["confidence"], reverse=True)

    # --- Internal helpers ---------------------------------------------------
    def _relationship_keys(self) -> Set[Tuple[str, str, str, str, str]]:
        stmt = select(
            Relationship.source_type,
            Relationship.source_id,
            Relationship.target_type,
            Relationship.target_id,
            Relationship.relationship_type,
        )
        return {tuple(row) for row in self.db.execute(stmt).all()}

    def _create_indicator_link(
        self,
        existing: Set[Tuple[str, str, str, str, str]],
        left: Indicator,
        right: Indicator,
        relationship_type: str,
        *,
        confidence: float,
        is_demo: bool,
    ) -> int:
        # Canonical ordering keeps the pair unique regardless of direction.
        first, second = sorted((left, right), key=lambda item: item.id)
        key = ("indicator", first.id, "indicator", second.id, relationship_type)
        if key in existing:
            return 0
        self.db.add(
            Relationship(
                source_type="indicator",
                source_id=first.id,
                target_type="indicator",
                target_id=second.id,
                relationship_type=relationship_type,
                confidence=confidence,
                evidence_reference=first.normalized_value,
                relationship_metadata={
                    "normalized_value": first.normalized_value,
                    "cases": sorted({left.case_id, right.case_id}),
                },
                requires_review=True,
                is_demo=is_demo,
            )
        )
        existing.add(key)
        self.db.flush()
        return 1

    def _create_case_link(
        self,
        existing: Set[Tuple[str, str, str, str, str]],
        case_id: str,
        other_case_id: str,
        *,
        confidence: float,
        shared_value: str,
        is_demo: bool,
    ) -> int:
        if case_id == other_case_id:
            return 0
        first, second = sorted((case_id, other_case_id))
        key = ("case", first, "case", second, RelationshipType.HISTORICAL_CORRELATION)
        if key in existing:
            # Enrich the existing relationship with the additional shared value.
            relationship = self.db.execute(
                select(Relationship).where(
                    Relationship.source_id == first,
                    Relationship.target_id == second,
                    Relationship.relationship_type == RelationshipType.HISTORICAL_CORRELATION,
                )
            ).scalars().first()
            if relationship is not None:
                metadata = dict(relationship.relationship_metadata or {})
                values = metadata.get("shared_values", [])
                if shared_value not in values:
                    values.append(shared_value)
                metadata["shared_values"] = values
                metadata["shared_count"] = len(values)
                relationship.relationship_metadata = metadata
                relationship.confidence = max(relationship.confidence, confidence)
                self.db.flush()
            return 0

        self.db.add(
            Relationship(
                source_type="case",
                source_id=first,
                target_type="case",
                target_id=second,
                relationship_type=RelationshipType.HISTORICAL_CORRELATION,
                confidence=confidence,
                evidence_reference=shared_value,
                relationship_metadata={
                    "shared_values": [shared_value],
                    "shared_count": 1,
                },
                requires_review=True,
                is_demo=is_demo,
            )
        )
        existing.add(key)
        self.db.flush()
        return 1