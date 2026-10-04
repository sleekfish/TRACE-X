"""Global cross-entity search.

Searches only fields that are actually stored - it never fabricates a match.
The search is case-scoped when ``case_id`` is supplied, otherwise it spans all
cases the caller may see.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.case import Case
from app.models.event import Event
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.schemas.search import SearchHit, SearchRequest, SearchResponse, SearchTypeCount
from app.services.base import BaseService

ALL_ENTITY_TYPES = ("case", "evidence", "event", "indicator", "finding", "analysis_job")


class SearchService(BaseService):
    """Simple, honest substring search across stored entities."""

    def search(self, request: SearchRequest) -> SearchResponse:
        query = request.query.strip()
        pattern = f"%{query.lower()}%"
        requested = [
            entity for entity in (request.entity_types or ALL_ENTITY_TYPES)
            if entity in ALL_ENTITY_TYPES
        ]
        limit = self.clamp_limit(request.limit, maximum=500)

        hits: List[SearchHit] = []
        for entity_type in requested:
            hits.extend(
                self._search_entity(entity_type, pattern, case_id=request.case_id, limit=limit)
            )

        hits.sort(key=lambda hit: hit.score, reverse=True)
        truncated_total = len(hits)
        hits = hits[:limit]

        counts: Dict[str, int] = {}
        for hit in hits:
            counts[hit.entity_type] = counts.get(hit.entity_type, 0) + 1

        note = ""
        if not hits:
            note = (
                "No stored record matched. Search only covers data that has been "
                "ingested into TRACE-X."
            )
        return SearchResponse(
            query=query,
            hits=hits,
            total=truncated_total,
            by_type=[
                SearchTypeCount(entity_type=key, count=counts[key])
                for key in sorted(counts, key=lambda k: counts[k], reverse=True)
            ],
            note=note,
        )

    # --- Per-entity search --------------------------------------------------
    def _search_entity(
        self, entity_type: str, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        if entity_type == "case":
            return self._search_cases(pattern, limit)
        if entity_type == "evidence":
            return self._search_evidence(pattern, case_id=case_id, limit=limit)
        if entity_type == "event":
            return self._search_events(pattern, case_id=case_id, limit=limit)
        if entity_type == "indicator":
            return self._search_indicators(pattern, case_id=case_id, limit=limit)
        if entity_type == "finding":
            return self._search_findings(pattern, case_id=case_id, limit=limit)
        if entity_type == "analysis_job":
            return self._search_jobs(pattern, case_id=case_id, limit=limit)
        return []

    def _search_cases(self, pattern: str, limit: int) -> List[SearchHit]:
        stmt = (
            select(Case)
            .where(
                or_(
                    func.lower(Case.title).like(pattern),
                    func.lower(Case.case_number).like(pattern),
                    func.lower(Case.description).like(pattern),
                )
            )
            .limit(limit)
        )
        return [
            SearchHit(
                entity_type="case",
                entity_id=case.id,
                case_id=case.id,
                title=f"{case.case_number}: {case.title}",
                snippet=(case.description or "")[:240],
                score=1.0,
                timestamp=case.created_at,
                metadata={"status": case.status, "severity": case.severity},
            )
            for case in self.db.execute(stmt).scalars().all()
        ]

    def _search_evidence(
        self, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        stmt = select(Evidence).where(
            or_(
                func.lower(Evidence.original_filename).like(pattern),
                func.lower(Evidence.sha256).like(pattern),
                func.lower(Evidence.notes).like(pattern),
            )
        )
        if case_id:
            stmt = stmt.where(Evidence.case_id == case_id)
        stmt = stmt.limit(limit)
        return [
            SearchHit(
                entity_type="evidence",
                entity_id=item.id,
                case_id=item.case_id,
                title=item.original_filename,
                snippet=f"{item.evidence_type} | sha256 {item.sha256[:16]}…",
                score=0.9,
                timestamp=item.created_at,
                metadata={"analysis_status": item.analysis_status},
            )
            for item in self.db.execute(stmt).scalars().all()
        ]

    def _search_events(
        self, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        stmt = select(Event).where(
            or_(
                func.lower(Event.description).like(pattern),
                func.lower(Event.raw_reference).like(pattern),
                func.lower(Event.event_type).like(pattern),
            )
        )
        if case_id:
            stmt = stmt.where(Event.case_id == case_id)
        stmt = stmt.order_by(Event.timestamp.asc().nulls_last()).limit(limit)
        return [
            SearchHit(
                entity_type="event",
                entity_id=event.id,
                case_id=event.case_id,
                title=event.event_type,
                snippet=event.description[:240],
                score=0.8,
                timestamp=event.timestamp,
                metadata={"source": event.source, "confidence": event.confidence},
            )
            for event in self.db.execute(stmt).scalars().all()
        ]

    def _search_indicators(
        self, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        stmt = select(Indicator).where(
            or_(
                func.lower(Indicator.value).like(pattern),
                func.lower(Indicator.normalized_value).like(pattern),
            )
        )
        if case_id:
            stmt = stmt.where(Indicator.case_id == case_id)
        stmt = stmt.limit(limit)
        return [
            SearchHit(
                entity_type="indicator",
                entity_id=indicator.id,
                case_id=indicator.case_id,
                title=f"{indicator.type}: {indicator.normalized_value}",
                snippet=f"confidence {indicator.confidence:.2f} | source {indicator.source}",
                score=0.95,
                timestamp=indicator.first_seen or indicator.created_at,
                metadata={"indicator_type": indicator.type},
            )
            for indicator in self.db.execute(stmt).scalars().all()
        ]

    def _search_findings(
        self, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        stmt = select(Finding).where(
            or_(
                func.lower(Finding.title).like(pattern),
                func.lower(Finding.description).like(pattern),
                func.lower(Finding.analyst_notes).like(pattern),
            )
        )
        if case_id:
            stmt = stmt.where(Finding.case_id == case_id)
        stmt = stmt.limit(limit)
        return [
            SearchHit(
                entity_type="finding",
                entity_id=finding.id,
                case_id=finding.case_id,
                title=finding.title,
                snippet=finding.description[:240],
                score=0.85,
                timestamp=finding.created_at,
                metadata={"severity": finding.severity, "status": finding.status},
            )
            for finding in self.db.execute(stmt).scalars().all()
        ]

    def _search_jobs(
        self, pattern: str, *, case_id: Optional[str], limit: int
    ) -> List[SearchHit]:
        stmt = select(AnalysisJob).where(
            or_(
                func.lower(AnalysisJob.tool).like(pattern),
                func.lower(AnalysisJob.error_message).like(pattern),
            )
        )
        if case_id:
            stmt = stmt.where(AnalysisJob.case_id == case_id)
        stmt = stmt.limit(limit)
        return [
            SearchHit(
                entity_type="analysis_job",
                entity_id=job.id,
                case_id=job.case_id,
                title=f"{job.tool} ({job.status})",
                snippet=job.error_message[:240],
                score=0.6,
                timestamp=job.created_at,
                metadata={"source": job.source},
            )
            for job in self.db.execute(stmt).scalars().all()
        ]