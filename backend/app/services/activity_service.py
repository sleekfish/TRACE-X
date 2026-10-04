"""Audit / activity logging."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.activity import Activity
from app.services.base import BaseService


class ActivityAction:
    """Canonical activity action names."""

    LOGIN = "login"
    REGISTER = "register"
    CASE_CREATED = "case.created"
    CASE_UPDATED = "case.updated"
    CASE_DELETED = "case.deleted"
    EVIDENCE_UPLOADED = "evidence.uploaded"
    EVIDENCE_UPDATED = "evidence.updated"
    EVIDENCE_DELETED = "evidence.deleted"
    EVIDENCE_VERIFIED = "evidence.verified"
    ANALYSIS_REQUESTED = "analysis.requested"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    REPORT_GENERATED = "report.generated"
    MEMORY_SEARCHED = "memory.searched"


def log_activity(
    db: Session,
    *,
    action: str,
    user_id: Optional[str] = None,
    case_id: Optional[str] = None,
    entity_type: str = "",
    entity_id: str = "",
    description: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Activity:
    """Record an audit entry.  Never raises for a missing session."""
    activity = Activity(
        user_id=user_id,
        case_id=case_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        description=description,
        activity_metadata=metadata or {},
    )
    db.add(activity)
    db.flush()
    return activity


class ActivityService(BaseService):
    """Read access to the audit trail."""

    def list_activities(
        self,
        *,
        user_id: Optional[str] = None,
        case_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[Activity], int]:
        stmt = select(Activity).order_by(Activity.timestamp.desc())
        if user_id:
            stmt = stmt.where(Activity.user_id == user_id)
        if case_id:
            stmt = stmt.where(Activity.case_id == case_id)
        if action:
            stmt = stmt.where(Activity.action == action)
        return self.paginate(stmt, limit=limit, offset=offset)

    def recent(self, limit: int = 10) -> List[Activity]:
        stmt = select(Activity).order_by(Activity.timestamp.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars().all())