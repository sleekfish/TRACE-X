"""Persistent forensic memory.

Answers the central investigatory question: *have we seen this indicator
before, and where?*  Every answer is derived solely from stored indicators and
carries full provenance (case, evidence, source tool, timestamps).  Nothing is
inferred or fabricated.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.indicator import Indicator
from app.schemas.memory import (
    MemoryCaseSummary,
    MemoryMatch,
    MemoryOverview,
    MemorySearchRequest,
    MemorySearchResponse,
)
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService
from app.utils.indicators import canonical_indicator, extract_indicators


class MemoryService(BaseService):
    """Cross-case indicator memory."""

    MAX_SEARCH_VALUES = 500

    # --- Query preparation --------------------------------------------------
    def extract_query_values(self, request: MemorySearchRequest) -> Tuple[List[str], List[str]]:
        """Return ``(searched_values, extracted_values)``.

        ``query`` free text is scanned with the same indicator extractor used
        during ingestion, so memory searches are consistent with what was
        stored.  Explicit ``indicators`` are added verbatim.
        """
        searched: List[str] = []
        extracted: List[str] = []

        for raw in request.indicators:
            value = (raw or "").strip()
            if value:
                searched.append(value)

        if request.query:
            for item in extract_indicators(request.query):
                normalized = item["normalized"]
                extracted.append(normalized)
                searched.append(normalized)

        # Always include the raw query as a literal too (handles plain hashes,
        # strings that are not detectable indicators, partial hostnames, …).
        if request.query and request.query.strip():
            searched.append(request.query.strip())

        # De-duplicate, preserving order, and cap the search breadth.
        unique: List[str] = []
        lowered_seen: Set[str] = set()
        for value in searched:
            key = value.lower()
            if key in lowered_seen:
                continue
            lowered_seen.add(key)
            unique.append(value)
        return unique[: self.MAX_SEARCH_VALUES], list(dict.fromkeys(extracted))

    # --- Search -------------------------------------------------------------
    def search(
        self, request: MemorySearchRequest, *, actor_id: Optional[str] = None
    ) -> MemorySearchResponse:
        searched_values, extracted = self.extract_query_values(request)
        if not searched_values:
            return MemorySearchResponse(
                note="No searchable indicators were supplied or could be extracted.",
            )

        # Match on the canonical (normalized) form for every searched value.
        normalized_targets: Set[str] = set()
        for value in searched_values:
            normalized_targets.add(value.strip().lower())
            # Include a canonicalised form for common types.
            for indicator_type in ("DOMAIN", "URL", "HASH", "EMAIL"):
                normalized_targets.add(
                    canonical_indicator(indicator_type, value).lower()
                )
        targets = {value for value in normalized_targets if value}

        stmt = select(Indicator).where(
            func.lower(Indicator.normalized_value).in_(targets)
        )
        if request.indicator_types:
            stmt = stmt.where(
                Indicator.type.in_([t.strip().upper() for t in request.indicator_types])
            )
        if request.min_confidence > 0:
            stmt = stmt.where(Indicator.confidence >= request.min_confidence)
        if request.exclude_case_id and not request.include_same_case:
            stmt = stmt.where(Indicator.case_id != request.exclude_case_id)

        stmt = stmt.order_by(Indicator.confidence.desc(), Indicator.created_at.desc())
        stmt = stmt.limit(request.limit + 1)
        rows = list(self.db.execute(stmt).scalars().all())
        truncated = len(rows) > request.limit
        rows = rows[: request.limit]

        case_ids = {row.case_id for row in rows}
        evidence_ids = {row.evidence_id for row in rows if row.evidence_id}
        case_map = self._case_map(case_ids)
        evidence_map = self._evidence_map(evidence_ids)

        matches: List[MemoryMatch] = []
        case_aggregate: Dict[str, MemoryCaseSummary] = {}

        for row in rows:
            case = case_map.get(row.case_id)
            evidence = evidence_map.get(row.evidence_id or "")
            matches.append(
                MemoryMatch(
                    indicator_id=row.id,
                    indicator_type=row.type,
                    value=row.value,
                    normalized_value=row.normalized_value,
                    confidence=row.confidence,
                    case_id=row.case_id,
                    case_number=case.case_number if case else "",
                    case_title=case.title if case else "",
                    case_status=case.status if case else "",
                    evidence_id=row.evidence_id,
                    evidence_filename=evidence.original_filename if evidence else None,
                    source=row.source,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    is_demo=row.is_demo,
                    match_reason=f"Stored indicator '{row.normalized_value}' matched the search.",
                )
            )

            summary = case_aggregate.get(row.case_id)
            if summary is None:
                summary = MemoryCaseSummary(
                    case_id=row.case_id,
                    case_number=case.case_number if case else "",
                    case_title=case.title if case else "",
                    case_status=case.status if case else "",
                    is_demo=row.is_demo,
                )
                case_aggregate[row.case_id] = summary
            summary.shared_indicator_count += 1
            if row.type not in summary.shared_indicator_types:
                summary.shared_indicator_types.append(row.type)
            if row.normalized_value not in summary.shared_values:
                summary.shared_values.append(row.normalized_value)
            summary.max_confidence = max(summary.max_confidence, row.confidence)

        cases = sorted(
            case_aggregate.values(),
            key=lambda item: (item.shared_indicator_count, item.max_confidence),
            reverse=True,
        )

        note = ""
        if not matches:
            note = (
                "No stored indicator matched. This means the value has not been "
                "ingested into TRACE-X memory - not that it is safe."
            )
        elif truncated:
            note = f"Results truncated to {request.limit} matches."

        log_activity(
            self.db,
            action=ActivityAction.MEMORY_SEARCHED,
            user_id=actor_id,
            entity_type="memory",
            description=(
                f"Memory searched for {len(searched_values)} value(s); "
                f"{len(matches)} match(es) across {len(cases)} case(s)."
            ),
            metadata={"matched": len(matches), "cases": len(cases)},
        )
        self.commit()

        return MemorySearchResponse(
            searched_values=searched_values,
            extracted_indicators=extracted,
            matches=matches,
            cases=cases,
            total_matches=len(matches),
            total_cases=len(cases),
            truncated=truncated,
            note=note,
        )

    # --- Overview -----------------------------------------------------------
    def overview(self) -> MemoryOverview:
        total_indicators = int(
            self.db.execute(select(func.count()).select_from(Indicator)).scalar() or 0
        )
        unique_values = int(
            self.db.execute(
                select(func.count(func.distinct(Indicator.normalized_value)))
            ).scalar()
            or 0
        )

        # Values appearing in more than one case = the heart of the memory.
        shared_stmt = (
            select(
                Indicator.normalized_value,
                func.count(func.distinct(Indicator.case_id)).label("case_count"),
                func.count().label("occurrences"),
                func.max(Indicator.confidence).label("max_confidence"),
            )
            .group_by(Indicator.normalized_value)
            .having(func.count(func.distinct(Indicator.case_id)) > 1)
            .order_by(func.count(func.distinct(Indicator.case_id)).desc())
            .limit(20)
        )
        shared_rows = self.db.execute(shared_stmt).all()

        shared_count = int(
            self.db.execute(
                select(func.count()).select_from(
                    select(Indicator.normalized_value)
                    .group_by(Indicator.normalized_value)
                    .having(func.count(func.distinct(Indicator.case_id)) > 1)
                    .subquery()
                )
            ).scalar()
            or 0
        )

        total_cases_indexed = int(
            self.db.execute(
                select(func.count(func.distinct(Indicator.case_id)))
            ).scalar()
            or 0
        )

        top_values: List[MemoryCaseSummary] = []
        for value, case_count, occurrences, max_confidence in shared_rows:
            cases = self.db.execute(
                select(Case.id, Case.case_number, Case.title, Case.status)
                .join(Indicator, Indicator.case_id == Case.id)
                .where(Indicator.normalized_value == value)
                .distinct()
            ).all()
            top_values.append(
                MemoryCaseSummary(
                    case_id=cases[0][0] if cases else "",
                    case_number=", ".join(row[1] for row in cases[:5]),
                    case_title=value,
                    case_status=f"{case_count} case(s)",
                    shared_indicator_count=occurrences,
                    shared_indicator_types=[
                        row[0]
                        for row in self.db.execute(
                            select(Indicator.type)
                            .where(Indicator.normalized_value == value)
                            .distinct()
                        ).all()
                    ],
                    shared_values=[value],
                    max_confidence=float(max_confidence or 0.0),
                )
            )

        note = ""
        if total_indicators == 0:
            note = "Memory is empty. Upload and analyse evidence to populate it."

        return MemoryOverview(
            total_indicators=total_indicators,
            unique_normalized_values=unique_values,
            indicators_shared_across_cases=shared_count,
            total_cases_indexed=total_cases_indexed,
            top_values=top_values,
            note=note,
        )

    # --- Helpers ------------------------------------------------------------
    def _case_map(self, case_ids: Set[str]) -> Dict[str, Case]:
        if not case_ids:
            return {}
        stmt = select(Case).where(Case.id.in_(case_ids))
        return {case.id: case for case in self.db.execute(stmt).scalars().all()}

    def _evidence_map(self, evidence_ids: Set[str]) -> Dict[str, Evidence]:
        if not evidence_ids:
            return {}
        stmt = select(Evidence).where(Evidence.id.in_(evidence_ids))
        return {item.id: item for item in self.db.execute(stmt).scalars().all()}