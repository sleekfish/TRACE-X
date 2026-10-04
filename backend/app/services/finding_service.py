"""Finding services.

Findings are analyst conclusions.  TRACE-X never auto-creates a finding from
tool output; it only records what an investigator asserts, together with the
evidence/indicator/event ids that support it and any historical cases that
share those indicators.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.models.case import Case
from app.models.enums import FindingStatus, RelationshipType, Severity
from app.models.event import Event
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.schemas.finding import FindingCreate, FindingUpdate
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService


class FindingService(BaseService):
    """Create, update and read analyst findings."""

    def get_finding(self, finding_id: str) -> Finding:
        return self.get_or_404(Finding, finding_id, "Finding")

    def list_findings(
        self,
        *,
        case_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Finding], int]:
        stmt = select(Finding).order_by(Finding.created_at.desc())
        if case_id:
            stmt = stmt.where(Finding.case_id == case_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if not include_demo:
            stmt = stmt.where(Finding.is_demo.is_(False))
        return self.paginate(stmt, limit=limit, offset=offset)

    def create_finding(
        self,
        case_id: str,
        payload: FindingCreate,
        *,
        actor_id: Optional[str] = None,
    ) -> Finding:
        if not self.db.get(Case, case_id):
            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})
        self.require_one_of(payload.severity, Severity.ALL, "severity")
        self.require_one_of(payload.status, FindingStatus.ALL, "status")

        evidence_ids = self._validate_ids(Evidence, case_id, payload.evidence_ids, "evidence")
        indicator_ids = self._validate_ids(Indicator, case_id, payload.indicator_ids, "indicator")
        event_ids = self._validate_ids(Event, case_id, payload.event_ids, "event")

        historical_cases = self._historical_cases(indicator_ids)

        finding = Finding(
            case_id=case_id,
            title=payload.title.strip(),
            description=payload.description or "",
            severity=payload.severity,
            status=payload.status,
            confidence=payload.confidence,
            evidence_ids=evidence_ids,
            indicator_ids=indicator_ids,
            event_ids=event_ids,
            historical_cases=historical_cases,
            provenance={
                "authored_by": actor_id,
                "supporting_evidence": len(evidence_ids),
                "supporting_indicators": len(indicator_ids),
                "supporting_events": len(event_ids),
                "historical_case_count": len(historical_cases),
            },
            analyst_notes=payload.analyst_notes or "",
            is_demo=False,
        )
        self.db.add(finding)
        self.db.flush()
        self._link_evidence(finding, evidence_ids)
        log_activity(
            self.db,
            action=ActivityAction.FINDING_CREATED,
            user_id=actor_id,
            case_id=case_id,
            entity_type="finding",
            entity_id=finding.id,
            description=f"Finding '{finding.title}' created ({finding.severity}).",
        )
        self.commit()
        return finding

    def update_finding(
        self,
        finding_id: str,
        payload: FindingUpdate,
        *,
        actor_id: Optional[str] = None,
    ) -> Finding:
        finding = self.get_finding(finding_id)
        if payload.severity is not None:
            self.require_one_of(payload.severity, Severity.ALL, "severity")
            finding.severity = payload.severity
        if payload.status is not None:
            self.require_one_of(payload.status, FindingStatus.ALL, "status")
            finding.status = payload.status
        if payload.title is not None:
            finding.title = payload.title.strip()
        if payload.description is not None:
            finding.description = payload.description
        if payload.confidence is not None:
            finding.confidence = payload.confidence
        if payload.analyst_notes is not None:
            finding.analyst_notes = payload.analyst_notes
        if payload.evidence_ids is not None:
            finding.evidence_ids = self._validate_ids(
                Evidence, finding.case_id, payload.evidence_ids, "evidence"
            )
        if payload.indicator_ids is not None:
            finding.indicator_ids = self._validate_ids(
                Indicator, finding.case_id, payload.indicator_ids, "indicator"
            )
            finding.historical_cases = self._historical_cases(finding.indicator_ids)
        if payload.event_ids is not None:
            finding.event_ids = self._validate_ids(
                Event, finding.case_id, payload.event_ids, "event"
            )

        provenance = dict(finding.provenance or {})
        provenance.update(
            {
                "last_edited_by": actor_id,
                "supporting_evidence": len(finding.evidence_ids or []),
                "supporting_indicators": len(finding.indicator_ids or []),
                "supporting_events": len(finding.event_ids or []),
                "historical_case_count": len(finding.historical_cases or []),
            }
        )
        finding.provenance = provenance
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.FINDING_UPDATED,
            user_id=actor_id,
            case_id=finding.case_id,
            entity_type="finding",
            entity_id=finding.id,
            description=f"Finding '{finding.title}' updated ({finding.status}).",
        )
        self.commit()
        return finding

    def delete_finding(self, finding_id: str, *, actor_id: Optional[str] = None) -> None:
        finding = self.get_finding(finding_id)
        self.db.execute(
            Relationship.__table__.delete().where(
                Relationship.source_type == "finding",
                Relationship.source_id == finding.id,
            )
        )
        self.db.delete(finding)
        self.commit()

    def severity_counts(self, *, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        stmt = select(Finding.severity, func.count()).group_by(Finding.severity)
        if case_id:
            stmt = stmt.where(Finding.case_id == case_id)
        return [{"severity": row[0], "count": row[1]} for row in self.db.execute(stmt).all()]

    # --- Helpers ------------------------------------------------------------
    def _validate_ids(self, model: Any, case_id: str, ids: List[str], label: str) -> List[str]:
        unique = list(dict.fromkeys(ids or []))
        if not unique:
            return []
        found = {
            row[0]
            for row in self.db.execute(
                select(model.id).where(model.id.in_(unique), model.case_id == case_id)
            ).all()
        }
        missing = [entity_id for entity_id in unique if entity_id not in found]
        if missing:
            raise ValidationError(
                f"Unknown {label} id(s) for this case.", {f"{label}_ids": missing}
            )
        return unique

    def _historical_cases(self, indicator_ids: List[str]) -> List[str]:
        """Cases that share any of the finding's indicators (from memory)."""
        if not indicator_ids:
            return []
        values = [
            row[0]
            for row in self.db.execute(
                select(Indicator.normalized_value).where(Indicator.id.in_(indicator_ids))
            ).all()
        ]
        if not values:
            return []
        own_case_ids = {
            row[0]
            for row in self.db.execute(
                select(Indicator.case_id).where(Indicator.id.in_(indicator_ids))
            ).all()
        }
        stmt = (
            select(Indicator.case_id)
            .where(
                Indicator.normalized_value.in_(values),
                Indicator.case_id.notin_(own_case_ids or {""}),
            )
            .distinct()
        )
        return [row[0] for row in self.db.execute(stmt).all()]

    def _link_evidence(self, finding: Finding, evidence_ids: List[str]) -> None:
        for evidence_id in evidence_ids:
            exists = self.db.execute(
                select(Relationship.id).where(
                    Relationship.source_type == "finding",
                    Relationship.source_id == finding.id,
                    Relationship.target_type == "evidence",
                    Relationship.target_id == evidence_id,
                    Relationship.relationship_type == RelationshipType.FINDING_EVIDENCE,
                )
            ).scalars().first()
            if exists:
                continue
            self.db.add(
                Relationship(
                    source_type="finding",
                    source_id=finding.id,
                    target_type="evidence",
                    target_id=evidence_id,
                    relationship_type=RelationshipType.FINDING_EVIDENCE,
                    confidence=finding.confidence,
                    evidence_reference=finding.title,
                    requires_review=False,
                )
            )
        self.db.flush()