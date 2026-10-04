"""Dashboard aggregation service.

Every number returned here is a direct ``COUNT`` over stored rows - no
estimates, no synthetic padding.  The integration panel reflects the real,
probed status of each adapter.
"""

from __future__ import annotations

from typing import Any, List

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.adapters.base import IntegrationInfo
from app.adapters.registry import registry
from app.models.activity import Activity
from app.models.analysis_job import AnalysisJob
from app.models.case import Case
from app.models.enums import AnalysisStatus, CaseStatus
from app.models.evidence import Evidence
from app.models.event import Event
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.schemas.activity import ActivityOut
from app.schemas.analysis import ToolInfo
from app.schemas.case import CaseSummary
from app.schemas.dashboard import DashboardSummary, DashboardTotals, SeverityCount
from app.services.base import BaseService

OPEN_STATUSES = (CaseStatus.OPEN, CaseStatus.ACTIVE, CaseStatus.UNDER_REVIEW)


class DashboardService(BaseService):
    """Build the analyst dashboard overview."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # --- Helpers ------------------------------------------------------------
    def _count(self, model: Any, *filters: Any) -> int:
        stmt = select(func.count()).select_from(model)
        if filters:
            stmt = stmt.where(*filters)
        return int(self.db.execute(stmt).scalar() or 0)

    def _demo_count(self, model: Any) -> int:
        return self._count(model, model.is_demo.is_(True))

    # --- Summary ------------------------------------------------------------
    def summary(self, *, recent_limit: int = 5) -> DashboardSummary:
        totals = DashboardTotals(
            cases=self._count(Case),
            open_cases=self._count(Case, Case.status.in_(OPEN_STATUSES)),
            evidence=self._count(Evidence),
            events=self._count(Event),
            indicators=self._count(Indicator),
            findings=self._count(Finding),
            relationships=self._count(Relationship),
            analysis_jobs=self._count(AnalysisJob),
            failed_jobs=self._count(AnalysisJob, AnalysisJob.status == AnalysisStatus.FAILED),
            demo_records=(
                self._demo_count(Case)
                + self._demo_count(Evidence)
                + self._demo_count(Event)
                + self._demo_count(Indicator)
                + self._demo_count(Finding)
            ),
        )

        severity_stmt = (
            select(Finding.severity, func.count())
            .group_by(Finding.severity)
            .order_by(func.count().desc())
        )
        findings_by_severity = [
            SeverityCount(severity=row[0] or "unknown", count=int(row[1]))
            for row in self.db.execute(severity_stmt).all()
        ]

        recent_cases = [
            CaseSummary.model_validate(case)
            for case in self.db.execute(
                select(Case).order_by(Case.created_at.desc()).limit(recent_limit)
            ).scalars().all()
        ]

        recent_activity = [
            ActivityOut.model_validate(activity)
            for activity in self.db.execute(
                select(Activity).order_by(Activity.timestamp.desc()).limit(10)
            ).scalars().all()
        ]

        last_event_at = self.db.execute(select(func.max(Event.timestamp))).scalar()

        real_adapters = registry.real_analysis_capable()
        note = ""
        if not real_adapters:
            note = (
                "No external forensic binary (tshark, zeek, yara) is currently "
                "installed on this host, so no REAL tool execution is possible. "
                "Structured exports can still be ingested truthfully."
            )

        return DashboardSummary(
            totals=totals,
            findings_by_severity=findings_by_severity,
            recent_cases=recent_cases,
            recent_activity=recent_activity,
            integrations=self.integrations(),
            real_analysis_available=bool(real_adapters),
            last_event_at=last_event_at,
            note=note,
        )

    # --- Integrations -------------------------------------------------------
    def integrations(self) -> List[ToolInfo]:
        return [self._to_tool_info(info) for info in registry.integration_infos()]

    def integration(self, name: str) -> ToolInfo:
        for info in registry.integration_infos():
            if info.name == name:
                return self._to_tool_info(info)
        from app.core.exceptions import NotFoundError

        raise NotFoundError(f"Integration '{name}' was not found.")

    @staticmethod
    def _to_tool_info(info: IntegrationInfo) -> ToolInfo:
        return ToolInfo(
            name=info.name,
            installed=info.installed,
            configured=info.configured,
            status=info.status,
            version=info.version,
            path=info.path,
            supported_evidence_types=list(info.supported_evidence_types),
            detail=info.detail,
            is_external=info.is_external,
        )

    # --- Case-scoped overview ----------------------------------------------
    def case_overview(self, case_id: str) -> dict:
        """Compact per-case numbers for the case workspace header."""
        case = self.get_or_404(Case, case_id, "Case")
        indicator_types = [
            {"type": row[0], "count": int(row[1])}
            for row in self.db.execute(
                select(Indicator.type, func.count())
                .where(Indicator.case_id == case_id)
                .group_by(Indicator.type)
                .order_by(func.count().desc())
            ).all()
        ]
        failed_jobs = self._count(
            AnalysisJob,
            AnalysisJob.case_id == case_id,
            AnalysisJob.status == AnalysisStatus.FAILED,
        )
        unavailable_jobs = self._count(
            AnalysisJob,
            AnalysisJob.case_id == case_id,
            AnalysisJob.status == AnalysisStatus.UNAVAILABLE,
        )
        last_event_at = self.db.execute(
            select(func.max(Event.timestamp)).where(Event.case_id == case_id)
        ).scalar()
        return {
            "case_id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "is_demo": case.is_demo,
            "evidence_count": self._count(Evidence, Evidence.case_id == case_id),
            "event_count": self._count(Event, Event.case_id == case_id),
            "indicator_count": self._count(Indicator, Indicator.case_id == case_id),
            "finding_count": self._count(Finding, Finding.case_id == case_id),
            "analysis_job_count": self._count(AnalysisJob, AnalysisJob.case_id == case_id),
            "failed_jobs": failed_jobs,
            "unavailable_jobs": unavailable_jobs,
            "indicator_types": indicator_types,
            "last_event_at": last_event_at,
            "open_findings": self._count(
                Finding,
                Finding.case_id == case_id,
                or_(
                    Finding.status == "open",
                    Finding.status == "requires_review",
                ),
            ),
        }