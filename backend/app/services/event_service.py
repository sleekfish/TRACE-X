"""Timeline event services."""

from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.enums import AnalysisSource
from app.models.event import Event
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.models.enums import RelationshipType
from app.schemas.event import EventCreate
from app.services.base import BaseService
from app.utils.timestamps import parse_timestamp


class EventService(BaseService):
    """Read and manage normalised timeline events."""

    def get_event(self, event_id: str) -> Event:
        return self.get_or_404(Event, event_id, "Event")

    def list_events(
        self,
        *,
        case_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[Event], int]:
        stmt = select(Event).order_by(Event.timestamp.asc().nulls_last(), Event.created_at.asc())
        if case_id:
            stmt = stmt.where(Event.case_id == case_id)
        if evidence_id:
            stmt = stmt.where(Event.evidence_id == evidence_id)
        if event_type:
            stmt = stmt.where(Event.event_type == event_type)
        if source:
            stmt = stmt.where(Event.source == source)
        if not include_demo:
            stmt = stmt.where(Event.is_demo.is_(False))
        if start:
            stmt = stmt.where(Event.timestamp >= parse_timestamp(start))
        if end:
            stmt = stmt.where(Event.timestamp <= parse_timestamp(end))
        return self.paginate(stmt, limit=limit, offset=offset)

    def all_events(
        self,
        *,
        case_id: str,
        include_demo: bool = True,
    ) -> List[Event]:
        """Return every event for a case in chronological order."""
        stmt = (
            select(Event)
            .where(Event.case_id == case_id)
            .order_by(Event.timestamp.asc().nulls_last(), Event.created_at.asc())
        )
        if not include_demo:
            stmt = stmt.where(Event.is_demo.is_(False))
        return list(self.db.execute(stmt).scalars().all())

    def indicators_for_events(self, event_ids: List[str]) -> Dict[str, List[str]]:
        """Map event id -> indicator normalized values (via relationships)."""
        if not event_ids:
            return {}
        stmt = (
            select(Relationship.source_id, Indicator.normalized_value)
            .join(Indicator, Relationship.target_id == Indicator.id)
            .where(
                Relationship.source_type == "event",
                Relationship.target_type == "indicator",
                Relationship.relationship_type == RelationshipType.EVENT_INDICATOR,
                Relationship.source_id.in_(event_ids),
            )
        )
        mapping: Dict[str, List[str]] = {}
        for event_id, value in self.db.execute(stmt).all():
            mapping.setdefault(event_id, [])
            if value not in mapping[event_id]:
                mapping[event_id].append(value)
        return mapping

    def evidence_filenames(self, evidence_ids: List[str]) -> Dict[str, str]:
        if not evidence_ids:
            return {}
        from app.models.evidence import Evidence

        stmt = select(Evidence.id, Evidence.original_filename).where(
            Evidence.id.in_(evidence_ids)
        )
        return {row[0]: row[1] for row in self.db.execute(stmt).all()}

    def create_event(self, case_id: str, payload: EventCreate, *, actor_id: Optional[str] = None) -> Event:
        """Analyst-authored event.  Explicitly tagged as analyst-sourced."""
        if not self.db.get(Case, case_id):
            from app.core.exceptions import ValidationError

            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})
        event = Event(
            case_id=case_id,
            evidence_id=None,
            timestamp=parse_timestamp(payload.timestamp),
            event_type=payload.event_type,
            source=AnalysisSource.REAL if payload.raw_reference else "analyst",
            description=payload.description,
            raw_reference=payload.raw_reference,
            confidence=payload.confidence,
            event_metadata={**(payload.event_metadata or {}), "authored_by": actor_id},
            is_demo=False,
        )
        # Analyst-authored manual entries are clearly labelled as such.
        event.source = "analyst"
        self.db.add(event)
        self.commit()
        return event

    def delete_event(self, event_id: str) -> None:
        event = self.get_event(event_id)
        self.db.delete(event)
        self.commit()

    def statistics(self, *, case_id: Optional[str] = None) -> Dict[str, object]:
        base_filters = []
        if case_id:
            base_filters.append(Event.case_id == case_id)

        total = int(
            self.db.execute(
                select(func.count()).select_from(Event).where(*base_filters)
            ).scalar()
            or 0
        )
        by_source = (
            select(Event.source, func.count())
            .where(*base_filters)
            .group_by(Event.source)
        )
        by_type = (
            select(Event.event_type, func.count())
            .where(*base_filters)
            .group_by(Event.event_type)
        )
        first_event, last_event = self.db.execute(
            select(func.min(Event.timestamp), func.max(Event.timestamp)).where(*base_filters)
        ).one()
        return {
            "total": total,
            "by_source": [{"source": row[0], "count": row[1]} for row in self.db.execute(by_source).all()],
            "by_type": [
                {"event_type": row[0], "count": row[1]} for row in self.db.execute(by_type).all()
            ],
            "first_event_at": first_event,
            "last_event_at": last_event,
        }