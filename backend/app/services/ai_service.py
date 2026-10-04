"""Kimi explanation layer.

STRICT CONTRACT - the AI layer may only *explain* data TRACE-X has already
produced.  It:

* receives a deterministic, bounded context built from the database;
* is instructed never to speculate beyond that context;
* never writes findings, events, indicators or relationships;
* reports ``available = False`` (with a clear reason) when Kimi is not
  configured, instead of failing the request.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.schemas.ai import AI_DISCLAIMER, ExplainRequest, ExplainResponse
from app.services.base import BaseService
from app.services.event_service import EventService
from app.utils.timestamps import utcnow

logger = get_logger(__name__)

SYSTEM_PROMPT = (
    "You are the explanation assistant for TRACE-X MEMORY, a digital forensics "
    "platform. You will receive a JSON context containing data that TRACE-X has "
    "already extracted from evidence.\n"
    "Rules you must follow absolutely:\n"
    "1. Only describe, summarise and contextualise the data in the provided "
    "context. Never invent hosts, users, timestamps, tool output or findings.\n"
    "2. If the context does not answer the question, say so explicitly.\n"
    "3. Distinguish clearly between observed facts (present in the context) and "
    "your own interpretation, which you must label as interpretation.\n"
    "4. Never claim a conclusion such as 'the system was compromised'. Describe "
    "what the data shows and what an investigator might review next.\n"
    "5. Be concise, neutral and technical. Use plain text."
)


class AIService(BaseService):
    """Builds context and asks Kimi to explain it."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.events = EventService(db)

    # --- Availability -------------------------------------------------------
    @property
    def available(self) -> bool:
        return bool(settings.kimi_api_key)

    def _unavailable_reason(self) -> str:
        if not settings.kimi_api_key:
            return (
                "Kimi is not configured. Set KIMI_API_KEY to enable AI "
                "explanations. All forensic data remains fully available "
                "without it."
            )
        return "Kimi is unavailable."

    # --- Context builders ---------------------------------------------------
    def build_case_context(self, case_id: str, *, sample_events: int = 25) -> Dict[str, Any]:
        case = self.db.get(Case, case_id)
        if case is None:
            return {"error": f"Case '{case_id}' was not found."}

        evidence = self.db.execute(
            select(Evidence).where(Evidence.case_id == case_id)
        ).scalars().all()
        indicators = self.db.execute(
            select(Indicator).where(Indicator.case_id == case_id).limit(100)
        ).scalars().all()
        findings = self.db.execute(
            select(Finding).where(Finding.case_id == case_id)
        ).scalars().all()
        events = self.events.all_events(case_id=case_id)

        by_type: Dict[str, int] = {}
        for indicator in indicators:
            by_type[indicator.type] = by_type.get(indicator.type, 0) + 1

        return {
            "case": {
                "case_number": case.case_number,
                "title": case.title,
                "description": case.description,
                "status": case.status,
                "severity": case.severity,
                "is_demo": case.is_demo,
            },
            "counts": {
                "evidence": len(evidence),
                "events": len(events),
                "indicators": len(indicators),
                "findings": len(findings),
                "timestamped_events": sum(1 for event in events if event.timestamp),
            },
            "indicator_types": by_type,
            "evidence": [
                {
                    "filename": item.original_filename,
                    "evidence_type": item.evidence_type,
                    "analysis_status": item.analysis_status,
                    "sha256": item.sha256,
                    "file_size": item.file_size,
                }
                for item in evidence[:25]
            ],
            "indicators": [
                {
                    "type": indicator.type,
                    "value": indicator.normalized_value,
                    "confidence": indicator.confidence,
                    "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
                    "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
                }
                for indicator in indicators
            ],
            "findings": [
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "confidence": finding.confidence,
                    "description": finding.description,
                }
                for finding in findings
            ],
            "timeline_sample": [
                {
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "event_type": event.event_type,
                    "source": event.source,
                    "description": event.description[:300],
                }
                for event in events[:sample_events]
            ],
        }

    def build_finding_context(self, case_id: str, finding_id: str) -> Dict[str, Any]:
        finding = self.db.get(Finding, finding_id)
        if finding is None or finding.case_id != case_id:
            return {"error": f"Finding '{finding_id}' was not found in this case."}
        return {
            "finding": {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "status": finding.status,
                "confidence": finding.confidence,
                "analyst_notes": finding.analyst_notes,
                "provenance": finding.provenance,
            },
            "supporting_evidence_count": len(finding.evidence_ids or []),
            "supporting_indicator_count": len(finding.indicator_ids or []),
            "supporting_event_count": len(finding.event_ids or []),
            "historical_cases": finding.historical_cases or [],
        }

    def build_indicator_context(self, case_id: str, indicator_id: str) -> Dict[str, Any]:
        indicator = self.db.get(Indicator, indicator_id)
        if indicator is None or indicator.case_id != case_id:
            return {"error": f"Indicator '{indicator_id}' was not found in this case."}
        return {
            "indicator": {
                "type": indicator.type,
                "value": indicator.normalized_value,
                "confidence": indicator.confidence,
                "source": indicator.source,
                "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
                "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
            }
        }

    def build_evidence_context(self, case_id: str, evidence_id: str) -> Dict[str, Any]:
        item = self.db.get(Evidence, evidence_id)
        if item is None or item.case_id != case_id:
            return {"error": f"Evidence '{evidence_id}' was not found in this case."}
        return {
            "evidence": {
                "filename": item.original_filename,
                "evidence_type": item.evidence_type,
                "detection_method": item.detection_method,
                "analysis_status": item.analysis_status,
                "sha256": item.sha256,
                "file_size": item.file_size,
                "acquisition_source": item.acquisition_source,
            },
            "tool_provenance": item.tool_provenance,
        }

    # --- Explanation --------------------------------------------------------
    def explain(self, request: ExplainRequest, *, actor_id: Optional[str] = None) -> ExplainResponse:
        context = self._context_for(request)
        warnings: List[str] = []

        if "error" in context:
            return ExplainResponse(
                explanation="",
                available=self.available,
                model=settings.kimi_model,
                generated_at=utcnow(),
                context_used=context,
                warnings=[context["error"]],
            )

        if not self.available:
            return ExplainResponse(
                explanation="",
                available=False,
                provider="kimi",
                model=settings.kimi_model,
                generated_at=utcnow(),
                context_used=context,
                warnings=[self._unavailable_reason()],
            )

        question = request.question or self._default_question(request.entity_type)
        explanation, error = self._call_kimi(context, question)
        if error:
            warnings.append(error)

        return ExplainResponse(
            explanation=explanation,
            available=True,
            provider="kimi",
            model=settings.kimi_model,
            generated_at=utcnow(),
            is_ai_generated=True,
            disclaimer=AI_DISCLAIMER,
            context_used=context,
            warnings=warnings,
        )

    def _context_for(self, request: ExplainRequest) -> Dict[str, Any]:
        entity_type = (request.entity_type or "case").lower()
        if entity_type == "case" or not request.entity_id:
            return self.build_case_context(request.case_id)
        if entity_type == "finding":
            return self.build_finding_context(request.case_id, request.entity_id)
        if entity_type == "indicator":
            return self.build_indicator_context(request.case_id, request.entity_id)
        if entity_type == "evidence":
            return self.build_evidence_context(request.case_id, request.entity_id)
        if entity_type == "timeline":
            return self.build_case_context(request.case_id, sample_events=50)
        return {"error": f"Unsupported entity type '{request.entity_type}'."}

    @staticmethod
    def _default_question(entity_type: str) -> str:
        if entity_type == "finding":
            return (
                "Explain what this finding records, which evidence supports it, "
                "and what an investigator should verify next."
            )
        if entity_type == "indicator":
            return "Explain what this indicator is and the context it appears in."
        if entity_type == "evidence":
            return "Summarise what this evidence item is and how it was processed."
        if entity_type == "timeline":
            return "Summarise the sequence of events and note any unexplained gaps."
        return (
            "Summarise this case objectively: what evidence was analysed, what was "
            "observed, and what remains unclear."
        )

    def _call_kimi(self, context: Dict[str, Any], question: str) -> tuple[str, Optional[str]]:
        import json

        url = f"{settings.kimi_base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": settings.kimi_model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Question: {question}\n\n"
                        f"TRACE-X context (JSON):\n{json.dumps(context, indent=2, default=str)}"
                    ),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {settings.kimi_api_key}",
            "Content-Type": "application/json",
        }
        try:
            with httpx.Client(timeout=60.0) as client:
                response = client.post(url, json=payload, headers=headers)
            if response.status_code >= 400:
                logger.warning("Kimi returned HTTP %s", response.status_code)
                return "", (
                    f"Kimi request failed with HTTP {response.status_code}. "
                    "The forensic data below is unaffected."
                )
            body = response.json()
        except httpx.HTTPError as exc:
            logger.warning("Kimi request error: %s", exc)
            return "", "Kimi could not be reached. The forensic data is unaffected."
        except ValueError as exc:
            logger.warning("Kimi returned invalid JSON: %s", exc)
            return "", "Kimi returned an unreadable response. The forensic data is unaffected."

        choices = body.get("choices") or []
        if not choices:
            return "", "Kimi returned no completion."
        message = choices[0].get("message") or {}
        return str(message.get("content") or "").strip(), None

    # --- Report integration -------------------------------------------------
    def summary_for_report(self, case_id: str) -> tuple[Optional[str], bool, List[str]]:
        """Return ``(summary, available, warnings)`` for report embedding."""
        response = self.explain(
            ExplainRequest(case_id=case_id, entity_type="case")
        )
        if not response.available or not response.explanation:
            return None, response.available, response.warnings
        return response.explanation, True, response.warnings