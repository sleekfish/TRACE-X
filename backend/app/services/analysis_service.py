"""Forensic analysis orchestration.

This service is the bridge between the real tool adapters and the database:

    evidence -> adapter -> raw output -> parser -> normalizer -> DB

Rules that this service never breaks:

* A tool that is not installed produces an ``UNAVAILABLE`` job - never events.
* Every event and indicator carries the tool, adapter version and evidence it
  came from.
* Records tagged with a non-REAL source are stored with ``is_demo = True`` so
  simulated data can never be mistaken for real forensic output.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.base import AnalysisResult, BaseToolAdapter
from app.adapters.registry import registry
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models.analysis_job import AnalysisJob
from app.models.enums import AnalysisSource, AnalysisStatus, RelationshipType
from app.models.evidence import Evidence
from app.models.event import Event
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.parsers.base import NormalizedEvent, NormalizedIndicator, NormalizationResult
from app.parsers.normalizer import NormalizationEngine
from app.schemas.analysis import AnalysisRequest
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService
from app.utils.timestamps import parse_timestamp, utcnow

logger = get_logger(__name__)


class AnalysisService(BaseService):
    """Runs adapters against evidence and persists normalised results."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.engine = NormalizationEngine()

    # --- Public API ---------------------------------------------------------
    def run(self, payload: AnalysisRequest, *, actor_id: Optional[str] = None) -> Dict[str, Any]:
        if not payload.evidence_ids:
            raise ValidationError("At least one evidence id is required.")

        source = self._validate_source(payload.source)
        is_demo = source != AnalysisSource.REAL

        evidence_items = self._load_evidence(payload.evidence_ids)
        case_id = payload.case_id or evidence_items[0].case_id
        for evidence in evidence_items:
            if evidence.case_id != case_id:
                raise ValidationError(
                    "All evidence items must belong to the same case.",
                    {"case_id": case_id, "evidence_case_id": evidence.case_id},
                )

        jobs: List[AnalysisJob] = []
        skipped: List[Dict[str, str]] = []
        warnings: List[str] = []
        totals = {"events": 0, "indicators": 0, "relationships": 0}

        for evidence in evidence_items:
            adapters, adapter_skips = self._resolve_adapters(evidence, payload.tools)
            skipped.extend(adapter_skips)

            if not adapters:
                warnings.append(
                    f"No adapter is applicable to evidence '{evidence.original_filename}' "
                    f"({evidence.evidence_type})."
                )
                continue

            for adapter in adapters:
                existing = self._existing_job(evidence.id, adapter.name)
                if existing is not None and not payload.force:
                    skipped.append(
                        {
                            "evidence_id": evidence.id,
                            "tool": adapter.name,
                            "status": existing.status,
                            "reason": "A completed job already exists; use force=true to re-run.",
                        }
                    )
                    continue

                job, counts = self._execute(adapter, evidence, source=source, is_demo=is_demo)
                jobs.append(job)
                totals["events"] += counts["events"]
                totals["indicators"] += counts["indicators"]
                totals["relationships"] += counts["relationships"]
                if job.error_message and job.status == AnalysisStatus.FAILED:
                    warnings.append(f"{adapter.name}: {job.error_message}")

            self._refresh_evidence_status(evidence)

        self._refresh_case_status(case_id)

        log_activity(
            self.db,
            action=ActivityAction.ANALYSIS_REQUESTED,
            user_id=actor_id,
            case_id=case_id,
            entity_type="analysis",
            entity_id=jobs[0].id if jobs else "",
            description=(
                f"Analysis requested for {len(evidence_items)} evidence item(s); "
                f"{len(jobs)} job(s) executed."
            ),
            metadata={
                "jobs": len(jobs),
                "skipped": len(skipped),
                "events": totals["events"],
                "indicators": totals["indicators"],
                "source": source,
            },
        )
        self.commit()

        return {
            "jobs": jobs,
            "skipped": skipped,
            "events_created": totals["events"],
            "indicators_created": totals["indicators"],
            "relationships_created": totals["relationships"],
            "warnings": warnings,
            "message": self._summary_message(jobs, skipped),
        }

    # --- Setup helpers ------------------------------------------------------
    @staticmethod
    def _validate_source(source: str) -> str:
        if source not in AnalysisSource.ALL:
            raise ValidationError(
                f"Invalid analysis source '{source}'.", {"allowed": AnalysisSource.ALL}
            )
        return source

    def _load_evidence(self, evidence_ids: List[str]) -> List[Evidence]:
        unique_ids = list(dict.fromkeys(evidence_ids))
        stmt = select(Evidence).where(Evidence.id.in_(unique_ids))
        found = {item.id: item for item in self.db.execute(stmt).scalars().all()}
        missing = [eid for eid in unique_ids if eid not in found]
        if missing:
            raise NotFoundError(
                "One or more evidence items were not found.", {"missing": missing}
            )
        return [found[eid] for eid in unique_ids]

    def _resolve_adapters(
        self, evidence: Evidence, requested: Optional[List[str]]
    ) -> Tuple[List[BaseToolAdapter], List[Dict[str, str]]]:
        skipped: List[Dict[str, str]] = []

        if requested:
            selected: List[BaseToolAdapter] = []
            for name in requested:
                adapter = registry.get(name)
                if adapter is None:
                    skipped.append(
                        {
                            "evidence_id": evidence.id,
                            "tool": name,
                            "status": AnalysisStatus.SKIPPED,
                            "reason": f"Unknown adapter '{name}'.",
                        }
                    )
                    continue
                if evidence.evidence_type not in adapter.supported_evidence_types():
                    skipped.append(
                        {
                            "evidence_id": evidence.id,
                            "tool": name,
                            "status": AnalysisStatus.SKIPPED,
                            "reason": (
                                f"Adapter does not support evidence type "
                                f"'{evidence.evidence_type}'."
                            ),
                        }
                    )
                    continue
                selected.append(adapter)
            return selected, skipped

        return registry.for_evidence_type(evidence.evidence_type), skipped

    def _existing_job(self, evidence_id: str, tool: str) -> Optional[AnalysisJob]:
        stmt = (
            select(AnalysisJob)
            .where(
                AnalysisJob.evidence_id == evidence_id,
                AnalysisJob.tool == tool,
                AnalysisJob.status.in_(
                    [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL]
                ),
            )
            .order_by(AnalysisJob.created_at.desc())
        )
        return self.db.execute(stmt).scalars().first()

    # --- Execution ----------------------------------------------------------
    def _execute(
        self,
        adapter: BaseToolAdapter,
        evidence: Evidence,
        *,
        source: str,
        is_demo: bool,
    ) -> Tuple[AnalysisJob, Dict[str, int]]:
        job = AnalysisJob(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            tool=adapter.name,
            status=AnalysisStatus.RUNNING,
            source=source,
            started_at=utcnow(),
            evidence_sha256=evidence.sha256,
            adapter_version=adapter.adapter_version,
            is_demo=is_demo,
        )
        self.db.add(job)
        self.db.flush()

        try:
            result: AnalysisResult = adapter.analyze(evidence)
        except Exception as exc:  # noqa: BLE001 - a failing tool must not break the API
            logger.exception("Adapter %s raised while analysing %s", adapter.name, evidence.id)
            result = AnalysisResult(tool=adapter.name, status=AnalysisStatus.FAILED)
            result.error_message = f"Adapter error: {exc}"

        job.status = result.status
        job.source = result.source or source
        job.command = list(result.command or [])
        job.stdout = (result.stdout or "")[:200000]
        job.stderr = (result.stderr or "")[:200000]
        job.exit_code = result.exit_code
        job.error_message = result.error_message or ""
        job.tool_version = result.tool_version or ""
        job.adapter_version = adapter.adapter_version
        job.completed_at = utcnow()

        counts = {"events": 0, "indicators": 0, "relationships": 0}
        if result.succeeded and result.records:
            counts = self._persist(result, adapter, evidence, source=job.source, is_demo=is_demo)
        elif result.succeeded and not result.records:
            job.job_metadata = {
                **(job.job_metadata or {}),
                "note": "Adapter completed but produced no records.",
            }

        job.events_created = counts["events"]
        job.indicators_created = counts["indicators"]
        job.job_metadata = {
            **(job.job_metadata or {}),
            **(result.metadata or {}),
            "parser": result.parser_name,
            "record_count": len(result.records),
            "relationships_created": counts["relationships"],
        }
        self.db.flush()
        return job, counts

    # --- Persistence --------------------------------------------------------
    def _persist(
        self,
        result: AnalysisResult,
        adapter: BaseToolAdapter,
        evidence: Evidence,
        *,
        source: str,
        is_demo: bool,
    ) -> Dict[str, int]:
        normalized: NormalizationResult = self.engine.normalize(
            result.records,
            source=adapter.name,
            evidence_id=evidence.id,
            is_demo=is_demo,
        )

        known_event_keys = self._existing_event_keys(evidence.id)
        indicator_cache = self._indicator_cache(evidence.case_id)
        relationship_cache = self._relationship_cache()

        events_created = 0
        indicators_created = 0
        relationships_created = 0

        # Case -> Evidence relationship (created once).
        relationships_created += self._link(
            relationship_cache,
            source_type="case",
            source_id=evidence.case_id,
            target_type="evidence",
            target_id=evidence.id,
            relationship_type=RelationshipType.CASE_EVIDENCE,
            confidence=1.0,
            evidence_reference=evidence.sha256,
            requires_review=False,
            is_demo=is_demo,
        )

        for normalized_event in normalized.events:
            event = self._create_event(
                normalized_event, evidence, source=adapter.name, is_demo=is_demo,
                known_keys=known_event_keys,
            )
            if event is None:
                continue
            events_created += 1
            relationships_created += self._link(
                relationship_cache,
                source_type="evidence",
                source_id=evidence.id,
                target_type="event",
                target_id=event.id,
                relationship_type=RelationshipType.EVIDENCE_EVENT,
                confidence=event.confidence,
                evidence_reference=event.raw_reference,
                requires_review=False,
                is_demo=is_demo,
            )

            for normalized_indicator in normalized_event.indicators:
                indicator, created = self._upsert_indicator(
                    normalized_indicator,
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    source=adapter.name,
                    is_demo=is_demo,
                    cache=indicator_cache,
                )
                if created:
                    indicators_created += 1
                relationships_created += self._link(
                    relationship_cache,
                    source_type="event",
                    source_id=event.id,
                    target_type="indicator",
                    target_id=indicator.id,
                    relationship_type=RelationshipType.EVENT_INDICATOR,
                    confidence=normalized_indicator.confidence,
                    evidence_reference=event.raw_reference,
                    requires_review=True,
                    is_demo=is_demo,
                )
                relationships_created += self._link(
                    relationship_cache,
                    source_type="case",
                    source_id=evidence.case_id,
                    target_type="indicator",
                    target_id=indicator.id,
                    relationship_type=RelationshipType.CASE_INDICATOR,
                    confidence=normalized_indicator.confidence,
                    evidence_reference=evidence.sha256,
                    requires_review=False,
                    is_demo=is_demo,
                )

        # Indicators extracted at evidence level but not tied to an event.
        for normalized_indicator in normalized.indicators:
            indicator, created = self._upsert_indicator(
                normalized_indicator,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                source=adapter.name,
                is_demo=is_demo,
                cache=indicator_cache,
            )
            if created:
                indicators_created += 1

        self.db.flush()
        return {
            "events": events_created,
            "indicators": indicators_created,
            "relationships": relationships_created,
        }

    def _existing_event_keys(self, evidence_id: str) -> set:
        stmt = select(Event.event_type, Event.timestamp, Event.description).where(
            Event.evidence_id == evidence_id
        )
        return {(row[0], row[1], row[2]) for row in self.db.execute(stmt).all()}

    @staticmethod
    def _naive(value: Optional[Any]) -> Optional[Any]:
        """Coerce any timestamp-like value to a naive UTC datetime."""
        if value is None:
            return None
        return parse_timestamp(value)

    def _create_event(
        self,
        normalized: NormalizedEvent,
        evidence: Evidence,
        *,
        source: str,
        is_demo: bool,
        known_keys: set,
    ) -> Optional[Event]:
        timestamp = self._naive(normalized.timestamp)
        key = (normalized.event_type, timestamp, normalized.description)
        if key in known_keys:
            return None

        metadata = dict(normalized.metadata or {})
        metadata.setdefault("evidence_id", evidence.id)
        metadata.setdefault("evidence_filename", evidence.original_filename)

        event = Event(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            timestamp=timestamp,
            event_type=normalized.event_type,
            source=source,
            description=normalized.description[:4000],
            raw_reference=normalized.raw_reference[:2000],
            confidence=normalized.confidence,
            event_metadata=metadata,
            is_demo=is_demo,
        )
        self.db.add(event)
        self.db.flush()
        known_keys.add(key)
        return event

    def _indicator_cache(self, case_id: str) -> Dict[Tuple[str, str], Indicator]:
        stmt = select(Indicator).where(Indicator.case_id == case_id)
        return {
            (indicator.type, indicator.normalized_value): indicator
            for indicator in self.db.execute(stmt).scalars().all()
        }

    def _upsert_indicator(
        self,
        normalized: NormalizedIndicator,
        *,
        case_id: str,
        evidence_id: str,
        source: str,
        is_demo: bool,
        cache: Dict[Tuple[str, str], Indicator],
    ) -> Tuple[Indicator, bool]:
        key = (normalized.type, normalized.normalized_value)
        first_seen = self._naive(normalized.first_seen)
        last_seen = self._naive(normalized.last_seen)
        existing = cache.get(key)
        if existing is not None:
            if first_seen and (
                existing.first_seen is None or first_seen < existing.first_seen
            ):
                existing.first_seen = first_seen
            if last_seen and (
                existing.last_seen is None or last_seen > existing.last_seen
            ):
                existing.last_seen = last_seen
            existing.confidence = max(existing.confidence, normalized.confidence)
            if existing.evidence_id is None:
                existing.evidence_id = evidence_id
            return existing, False

        indicator = Indicator(
            case_id=case_id,
            evidence_id=evidence_id,
            type=normalized.type,
            value=normalized.value[:2000],
            normalized_value=normalized.normalized_value[:2000],
            confidence=normalized.confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            source=source,
            is_demo=is_demo,
        )
        self.db.add(indicator)
        self.db.flush()
        cache[key] = indicator
        return indicator, True

    def _relationship_cache(self) -> set:
        stmt = select(
            Relationship.source_type,
            Relationship.source_id,
            Relationship.target_type,
            Relationship.target_id,
            Relationship.relationship_type,
        )
        return {tuple(row) for row in self.db.execute(stmt).all()}

    def _link(
        self,
        cache: set,
        *,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str,
        relationship_type: str,
        confidence: float,
        evidence_reference: str = "",
        requires_review: bool = True,
        is_demo: bool = False,
    ) -> int:
        key = (source_type, source_id, target_type, target_id, relationship_type)
        if key in cache:
            return 0
        relationship = Relationship(
            source_type=source_type,
            source_id=source_id,
            target_type=target_type,
            target_id=target_id,
            relationship_type=relationship_type,
            confidence=confidence,
            evidence_reference=evidence_reference or "",
            requires_review=requires_review,
            is_demo=is_demo,
        )
        self.db.add(relationship)
        self.db.flush()
        cache.add(key)
        return 1

    # --- Status roll-up -----------------------------------------------------
    def _refresh_evidence_status(self, evidence: Evidence) -> None:
        stmt = select(AnalysisJob.status).where(AnalysisJob.evidence_id == evidence.id)
        statuses = [row[0] for row in self.db.execute(stmt).all()]
        if not statuses:
            evidence.analysis_status = AnalysisStatus.PENDING
        elif AnalysisStatus.RUNNING in statuses:
            evidence.analysis_status = AnalysisStatus.RUNNING
        elif any(status in (AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL) for status in statuses):
            evidence.analysis_status = (
                AnalysisStatus.PARTIAL
                if AnalysisStatus.UNAVAILABLE in statuses or AnalysisStatus.FAILED in statuses
                else AnalysisStatus.COMPLETED
            )
        elif all(status == AnalysisStatus.UNAVAILABLE for status in statuses):
            evidence.analysis_status = AnalysisStatus.UNAVAILABLE
        else:
            evidence.analysis_status = AnalysisStatus.FAILED
        self.db.flush()

    def _refresh_case_status(self, case_id: str) -> None:
        from app.models.case import Case
        from app.models.enums import CaseStatus

        case = self.db.get(Case, case_id)
        if case is None:
            return
        has_events = self.db.execute(
            select(Event.id).where(Event.case_id == case_id).limit(1)
        ).scalars().first()
        if has_events and case.status == CaseStatus.OPEN:
            case.status = CaseStatus.ACTIVE
            self.db.flush()

    # --- Queries ------------------------------------------------------------
    def get_job(self, job_id: str) -> AnalysisJob:
        return self.get_or_404(AnalysisJob, job_id, "Analysis job")

    def list_jobs(
        self,
        *,
        case_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        tool: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AnalysisJob], int]:
        stmt = select(AnalysisJob).order_by(AnalysisJob.created_at.desc())
        if case_id:
            stmt = stmt.where(AnalysisJob.case_id == case_id)
        if evidence_id:
            stmt = stmt.where(AnalysisJob.evidence_id == evidence_id)
        if tool:
            stmt = stmt.where(AnalysisJob.tool == tool)
        if status:
            stmt = stmt.where(AnalysisJob.status == status)
        return self.paginate(stmt, limit=limit, offset=offset)

    # --- Messaging ----------------------------------------------------------
    @staticmethod
    def _summary_message(jobs: List[AnalysisJob], skipped: List[Dict[str, str]]) -> str:
        if not jobs and skipped:
            return "No analysis was executed; see 'skipped' for details."
        completed = sum(1 for job in jobs if job.status == AnalysisStatus.COMPLETED)
        partial = sum(1 for job in jobs if job.status == AnalysisStatus.PARTIAL)
        unavailable = sum(1 for job in jobs if job.status == AnalysisStatus.UNAVAILABLE)
        failed = sum(1 for job in jobs if job.status == AnalysisStatus.FAILED)
        return (
            f"{len(jobs)} job(s): {completed} completed, {partial} partial, "
            f"{unavailable} unavailable (tool not installed), {failed} failed."
        )