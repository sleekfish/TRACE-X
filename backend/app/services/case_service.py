"""Case management services."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.models.case import Case
from app.models.enums import CaseStatus, Severity
from app.models.evidence import Evidence
from app.models.event import Event
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.models.analysis_job import AnalysisJob
from app.schemas.case import CaseCreate, CaseStats, CaseUpdate
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService
from app.utils.timestamps import utcnow


class CaseService(BaseService):
    """Create, read, update and summarise cases."""

    # --- Helpers ------------------------------------------------------------
    def _next_case_number(self) -> str:
        year = utcnow().year
        prefix = f"TX-{year}-"
        stmt = select(func.count()).select_from(Case).where(Case.case_number.like(f"{prefix}%"))
        count = int(self.db.execute(stmt).scalar() or 0)
        candidate_index = count + 1
        # Guard against collisions if cases were deleted.
        while True:
            candidate = f"{prefix}{candidate_index:04d}"
            exists = self.db.execute(
                select(Case.id).where(Case.case_number == candidate)
            ).scalars().first()
            if not exists:
                return candidate
            candidate_index += 1

    def get_case(self, case_id: str) -> Case:
        return self.get_or_404(Case, case_id, "Case")

    def get_by_number(self, case_number: str) -> Case:
        stmt = select(Case).where(Case.case_number == case_number)
        case = self.db.execute(stmt).scalars().first()
        if case is None:
            raise NotFoundError(f"Case '{case_number}' was not found.")
        return case

    # --- Queries ------------------------------------------------------------
    def list_cases(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        investigator_id: Optional[str] = None,
        search: Optional[str] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[Case], int]:
        stmt = select(Case).order_by(Case.created_at.desc())
        if status:
            stmt = stmt.where(Case.status == status)
        if severity:
            stmt = stmt.where(Case.severity == severity)
        if investigator_id:
            stmt = stmt.where(Case.investigator_id == investigator_id)
        if not include_demo:
            stmt = stmt.where(Case.is_demo.is_(False))
        if search:
            pattern = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                func.lower(Case.title).like(pattern)
                | func.lower(Case.case_number).like(pattern)
                | func.lower(Case.description).like(pattern)
            )
        return self.paginate(stmt, limit=limit, offset=offset)

    # --- Mutations ----------------------------------------------------------
    def create_case(
        self,
        payload: CaseCreate,
        *,
        actor_id: Optional[str] = None,
        is_demo: bool = False,
    ) -> Case:
        self.require_one_of(payload.status, CaseStatus.ALL, "status")
        self.require_one_of(payload.severity, Severity.ALL, "severity")

        case_number = (payload.case_number or "").strip() or self._next_case_number()
        existing = self.db.execute(
            select(Case.id).where(Case.case_number == case_number)
        ).scalars().first()
        if existing:
            raise ConflictError(
                f"Case number '{case_number}' already exists.",
                {"case_number": case_number},
            )

        case = Case(
            case_number=case_number,
            title=payload.title.strip(),
            description=payload.description or "",
            status=payload.status,
            severity=payload.severity,
            investigator_id=payload.investigator_id or actor_id,
            is_demo=is_demo,
        )
        self.db.add(case)
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.CASE_CREATED,
            user_id=actor_id,
            case_id=case.id,
            entity_type="case",
            entity_id=case.id,
            description=f"Case {case.case_number} created: {case.title}",
        )
        self.commit()
        return case

    def update_case(
        self, case_id: str, payload: CaseUpdate, *, actor_id: Optional[str] = None
    ) -> Case:
        case = self.get_case(case_id)
        if payload.status is not None:
            self.require_one_of(payload.status, CaseStatus.ALL, "status")
            case.status = payload.status
        if payload.severity is not None:
            self.require_one_of(payload.severity, Severity.ALL, "severity")
            case.severity = payload.severity
        if payload.title is not None:
            case.title = payload.title.strip()
        if payload.description is not None:
            case.description = payload.description
        if payload.investigator_id is not None:
            case.investigator_id = payload.investigator_id or None

        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.CASE_UPDATED,
            user_id=actor_id,
            case_id=case.id,
            entity_type="case",
            entity_id=case.id,
            description=f"Case {case.case_number} updated.",
        )
        self.commit()
        return case

    def delete_case(self, case_id: str, *, actor_id: Optional[str] = None) -> None:
        case = self.get_case(case_id)
        number = case.case_number
        self.db.delete(case)
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.CASE_DELETED,
            user_id=actor_id,
            entity_type="case",
            entity_id=case_id,
            description=f"Case {number} deleted.",
        )
        self.commit()

    # --- Aggregates ---------------------------------------------------------
    def entity_ids(self, case_id: str) -> Dict[str, List[str]]:
        """Collect every graph entity id belonging to a case."""

        def ids(model: Any) -> List[str]:
            return [
                row
                for row in self.db.execute(
                    select(model.id).where(model.case_id == case_id)
                ).scalars().all()
            ]

        return {
            "evidence": ids(Evidence),
            "indicator": ids(Indicator),
            "event": ids(Event),
            "finding": ids(Finding),
        }

    def stats(self, case_id: str) -> CaseStats:
        self.get_case(case_id)

        def count(model: Any) -> int:
            return int(
                self.db.execute(
                    select(func.count()).select_from(model).where(model.case_id == case_id)
                ).scalar()
                or 0
            )

        first_event, last_event = self.db.execute(
            select(func.min(Event.timestamp), func.max(Event.timestamp)).where(
                Event.case_id == case_id
            )
        ).one()

        # Relationships are global; count only those touching this case's entities.
        entity_ids = self.entity_ids(case_id)
        all_ids = [value for group in entity_ids.values() for value in group]
        relationship_count = 0
        if all_ids:
            relationship_count = int(
                self.db.execute(
                    select(func.count())
                    .select_from(Relationship)
                    .where(
                        Relationship.source_id.in_(all_ids)
                        | Relationship.target_id.in_(all_ids)
                    )
                ).scalar()
                or 0
            )

        return CaseStats(
            evidence_count=count(Evidence),
            event_count=count(Event),
            indicator_count=count(Indicator),
            finding_count=count(Finding),
            relationship_count=relationship_count,
            analysis_job_count=count(AnalysisJob),
            first_event_at=first_event,
            last_event_at=last_event,
        )

    def assert_exists(self, case_id: str) -> Case:
        """Validate a case reference supplied by a client."""
        case = self.db.get(Case, case_id)
        if case is None:
            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})
        return case