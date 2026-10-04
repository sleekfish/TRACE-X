"""Case report generation.

Reports contain ONLY data that exists in the database.  Every section is
explicitly derived from stored records, and the provenance block states which
tools actually ran.  AI narrative (when enabled) is clearly fenced and
disclaimed.  Nothing is written to disk unless ``persist`` is requested.
"""

from __future__ import annotations

import json
import datetime as dt
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adapters.registry import registry
from app.core.config import settings
from app.core.exceptions import ValidationError
from app.models.analysis_job import AnalysisJob
from app.models.case import Case
from app.models.enums import AnalysisStatus
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.schemas.ai import AI_DISCLAIMER
from app.schemas.memory import MemorySearchRequest
from app.schemas.report import ReportFileInfo, ReportOut, ReportRequest
from app.services.activity_service import ActivityAction, log_activity
from app.services.ai_service import AIService
from app.services.base import BaseService
from app.services.event_service import EventService
from app.services.memory_service import MemoryService
from app.utils.timestamps import to_iso_z, utcnow
from app.utils.validation import ensure_within, sanitize_filename

MAX_EVENTS_IN_REPORT = 500
MAX_INDICATORS_IN_REPORT = 500
SUPPORTED_FORMATS = ("markdown", "json")


def _mtime_to_utc(timestamp: float) -> dt.datetime:
    """Convert a filesystem mtime into a naive UTC datetime."""
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).replace(tzinfo=None)


class ReportService(BaseService):
    """Generate structured, evidence-grounded case reports."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.events = EventService(db)
        self.memory = MemoryService(db)
        self.ai = AIService(db)
        self.report_root = Path(settings.report_storage_path)

    # --- Public API ---------------------------------------------------------
    def generate(self, request: ReportRequest, *, actor_id: Optional[str] = None) -> ReportOut:
        if request.format not in SUPPORTED_FORMATS:
            raise ValidationError(
                f"Unsupported report format '{request.format}'.",
                {"allowed": list(SUPPORTED_FORMATS)},
            )

        case = self.db.get(Case, request.case_id)
        if case is None:
            raise ValidationError(
                f"Case '{request.case_id}' does not exist.", {"case_id": request.case_id}
            )

        data = self._collect(case, request)
        notes: List[str] = list(data["notes"])

        ai_summary: Optional[str] = None
        ai_available = False
        if request.include_ai_summary:
            ai_summary, ai_available, ai_warnings = self.ai.summary_for_report(case.id)
            notes.extend(ai_warnings)
            if not ai_available:
                notes.append(
                    "AI summary was requested but Kimi is not configured; the "
                    "report was generated without it."
                )

        if request.format == "markdown":
            content = self._render_markdown(
                case, data, request, ai_summary=ai_summary
            )
        else:
            content = json.dumps(
                self._render_json(case, data, request, ai_summary=ai_summary),
                indent=2,
                default=str,
            )

        title = request.title or f"TRACE-X Report - {case.case_number}: {case.title}"
        filename: Optional[str] = None
        storage_path: Optional[str] = None
        if request.persist:
            filename, storage_path = self._persist(case, title, request.format, content)
            notes.append(f"Report written to {storage_path}")

        sections = self._sections(request)
        log_activity(
            self.db,
            action=ActivityAction.REPORT_GENERATED,
            user_id=actor_id,
            case_id=case.id,
            entity_type="report",
            entity_id=filename or "",
            description=f"Report generated for case {case.case_number} ({request.format}).",
            metadata={"sections": sections, "persisted": request.persist},
        )
        self.commit()

        return ReportOut(
            case_id=case.id,
            case_number=case.case_number,
            title=title,
            format=request.format,
            generated_at=utcnow(),
            content=content,
            filename=filename,
            storage_path=storage_path,
            size_bytes=len(content.encode("utf-8")),
            sections=sections,
            ai_summary_included=bool(ai_summary),
            ai_summary_available=ai_available,
            notes=notes,
        )

    def list_reports(self, *, case_id: Optional[str] = None) -> List[ReportFileInfo]:
        if not self.report_root.exists():
            return []
        reports: List[ReportFileInfo] = []
        pattern = f"{case_id}_*" if case_id else "*"
        for path in sorted(self.report_root.glob(f"{pattern}"), reverse=True):
            if not path.is_file():
                continue
            stat = path.stat()
            stem = path.name
            report_format = "json" if path.suffix == ".json" else "markdown"
            parts = stem.split("_", 1)
            reports.append(
                ReportFileInfo(
                    filename=path.name,
                    case_id=parts[0] if parts else "",
                    format=report_format,
                    size_bytes=stat.st_size,
                    created_at=_mtime_to_utc(stat.st_mtime),
                )
            )
        return reports

    def read_report(self, filename: str, *, case_id: Optional[str] = None) -> ReportOut:
        path = ensure_within(self.report_root, filename)
        if case_id and not path.name.startswith(f"{case_id}_"):
            raise ValidationError(
                "Report does not belong to the requested case.", {"filename": filename}
            )
        if not path.is_file():
            raise ValidationError("Report file was not found.", {"filename": filename})

        content = path.read_text(encoding="utf-8", errors="replace")
        report_format = "json" if path.suffix == ".json" else "markdown"
        stat = path.stat()
        return ReportOut(
            case_id=path.name.split("_", 1)[0],
            case_number="",
            title=path.name,
            format=report_format,
            generated_at=_mtime_to_utc(stat.st_mtime),
            content=content,
            filename=path.name,
            storage_path=str(path),
            size_bytes=stat.st_size,
            notes=["Loaded from report storage."],
        )

    # --- Data collection ----------------------------------------------------
    def _collect(self, case: Case, request: ReportRequest) -> Dict[str, Any]:
        notes: List[str] = []
        data: Dict[str, Any] = {"notes": notes}

        data["evidence"] = []
        data["events"] = []
        data["indicators"] = []
        data["findings"] = []
        data["jobs"] = []
        data["integrations"] = []
        data["memory_links"] = []

        if request.include_evidence:
            evidence = self.db.execute(
                select(Evidence)
                .where(Evidence.case_id == case.id)
                .order_by(Evidence.created_at.asc())
            ).scalars().all()
            data["evidence"] = [
                {
                    "filename": item.original_filename,
                    "evidence_type": item.evidence_type,
                    "detection_method": item.detection_method,
                    "file_size": item.file_size,
                    "sha256": item.sha256,
                    "analysis_status": item.analysis_status,
                    "acquisition_source": item.acquisition_source,
                    "is_demo": item.is_demo,
                }
                for item in evidence
            ]

        if request.include_timeline:
            events = self.events.all_events(case_id=case.id)
            total_events = len(events)
            if total_events > MAX_EVENTS_IN_REPORT:
                notes.append(
                    f"Timeline truncated to the first {MAX_EVENTS_IN_REPORT} of "
                    f"{total_events} events."
                )
            filename_map = self.events.evidence_filenames(
                [event.evidence_id for event in events if event.evidence_id]
            )
            data["events"] = [
                {
                    "timestamp": to_iso_z(event.timestamp),
                    "event_type": event.event_type,
                    "source": event.source,
                    "description": event.description,
                    "confidence": event.confidence,
                    "evidence_id": event.evidence_id,
                    "evidence_filename": filename_map.get(event.evidence_id or ""),
                    "is_demo": event.is_demo,
                }
                for event in events[:MAX_EVENTS_IN_REPORT]
            ]
            data["event_total"] = total_events

        if request.include_indicators:
            indicators = self.db.execute(
                select(Indicator)
                .where(Indicator.case_id == case.id)
                .order_by(Indicator.type.asc(), Indicator.normalized_value.asc())
            ).scalars().all()
            if len(indicators) > MAX_INDICATORS_IN_REPORT:
                notes.append(
                    f"Indicators truncated to {MAX_INDICATORS_IN_REPORT} of "
                    f"{len(indicators)}."
                )
            data["indicators"] = [
                {
                    "type": indicator.type,
                    "value": indicator.normalized_value,
                    "confidence": indicator.confidence,
                    "source": indicator.source,
                    "first_seen": to_iso_z(indicator.first_seen),
                    "last_seen": to_iso_z(indicator.last_seen),
                    "is_demo": indicator.is_demo,
                }
                for indicator in indicators[:MAX_INDICATORS_IN_REPORT]
            ]
            data["indicator_total"] = len(indicators)

            memory = self.memory.search(
                MemorySearchRequest(
                    indicators=[indicator.normalized_value for indicator in indicators[:200]],
                    exclude_case_id=case.id,
                    limit=200,
                )
            )
            data["memory_links"] = [
                {
                    "case_number": summary.case_number,
                    "case_title": summary.case_title,
                    "shared_indicator_count": summary.shared_indicator_count,
                    "shared_values": summary.shared_values,
                    "max_confidence": summary.max_confidence,
                }
                for summary in memory.cases
            ]
            if not memory.matches:
                notes.append(
                    "No indicators from this case have previously been seen in "
                    "other TRACE-X cases."
                )

        if request.include_findings:
            findings = self.db.execute(
                select(Finding)
                .where(Finding.case_id == case.id)
                .order_by(Finding.created_at.asc())
            ).scalars().all()
            data["findings"] = [
                {
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "status": finding.status,
                    "confidence": finding.confidence,
                    "evidence_ids": finding.evidence_ids,
                    "indicator_ids": finding.indicator_ids,
                    "historical_cases": finding.historical_cases,
                    "analyst_notes": finding.analyst_notes,
                    "provenance": finding.provenance,
                }
                for finding in findings
            ]

        jobs = self.db.execute(
            select(AnalysisJob)
            .where(AnalysisJob.case_id == case.id)
            .order_by(AnalysisJob.created_at.asc())
        ).scalars().all()
        data["jobs"] = [
            {
                "tool": job.tool,
                "status": job.status,
                "source": job.source,
                "tool_version": job.tool_version,
                "adapter_version": job.adapter_version,
                "command": job.command,
                "exit_code": job.exit_code,
                "events_created": job.events_created,
                "indicators_created": job.indicators_created,
                "error_message": job.error_message,
                "started_at": to_iso_z(job.started_at),
                "completed_at": to_iso_z(job.completed_at),
                "is_demo": job.is_demo,
            }
            for job in jobs
        ]

        if request.include_integrations:
            data["integrations"] = [
                {
                    "name": info.name,
                    "status": info.status,
                    "installed": info.installed,
                    "configured": info.configured,
                    "version": info.version,
                    "supported_evidence_types": info.supported_evidence_types,
                    "detail": info.detail,
                    "is_external": info.is_external,
                }
                for info in registry.integration_infos()
            ]

        # Provenance summary.
        unavailable = [job for job in jobs if job.status == AnalysisStatus.UNAVAILABLE]
        if unavailable:
            notes.append(
                "Some configured tools were not installed on the analysis host "
                f"({', '.join(sorted({job.tool for job in unavailable}))}); those "
                "evidences were NOT analysed with them."
            )
        if any(item["is_demo"] for item in data["evidence"]):
            notes.append(
                "This case contains DEMO evidence. Records flagged is_demo=true are "
                "synthetic and must not be treated as forensic findings."
            )
        return data

    # --- Rendering ----------------------------------------------------------
    @staticmethod
    def _sections(request: ReportRequest) -> List[str]:
        sections = ["case"]
        if request.include_evidence:
            sections.append("evidence")
        if request.include_timeline:
            sections.append("timeline")
        if request.include_indicators:
            sections.append("indicators")
        if request.include_findings:
            sections.append("findings")
        sections.append("analysis")
        if request.include_integrations:
            sections.append("integrations")
        if request.include_ai_summary:
            sections.append("ai_summary")
        return sections

    def _render_markdown(
        self,
        case: Case,
        data: Dict[str, Any],
        request: ReportRequest,
        *,
        ai_summary: Optional[str],
    ) -> str:
        lines: List[str] = []
        lines.append(f"# TRACE-X MEMORY Report - {case.case_number}")
        lines.append("")
        lines.append(f"**Title:** {case.title}")
        lines.append(f"**Status:** {case.status}  ")
        lines.append(f"**Severity:** {case.severity}  ")
        lines.append(f"**Generated (UTC):** {to_iso_z(utcnow())}  ")
        if case.is_demo:
            lines.append("")
            lines.append("> **DEMO CASE** - all records are synthetic.")
        lines.append("")
        if case.description:
            lines.append(case.description)
            lines.append("")

        if request.include_evidence:
            lines.append("## Evidence")
            lines.append("")
            if not data["evidence"]:
                lines.append("_No evidence has been uploaded to this case._")
            else:
                lines.append("| Filename | Type | Size (bytes) | SHA-256 | Analysis | Demo |")
                lines.append("| --- | --- | --- | --- | --- | --- |")
                for item in data["evidence"]:
                    lines.append(
                        f"| {item['filename']} | {item['evidence_type']} | "
                        f"{item['file_size']} | `{item['sha256']}` | "
                        f"{item['analysis_status']} | {item['is_demo']} |"
                    )
            lines.append("")

        if request.include_timeline:
            lines.append("## Timeline")
            lines.append("")
            if not data["events"]:
                lines.append("_No events have been extracted for this case._")
            else:
                lines.append(
                    f"Total events: {data.get('event_total', len(data['events']))} "
                    f"(showing {len(data['events'])})"
                )
                lines.append("")
                lines.append("| Timestamp (UTC) | Type | Source | Description | Confidence |")
                lines.append("| --- | --- | --- | --- | --- |")
                for event in data["events"]:
                    description = (event["description"] or "").replace("|", "\\|").replace("\n", " ")
                    lines.append(
                        f"| {event['timestamp'] or 'unknown'} | {event['event_type']} | "
                        f"{event['source']} | {description[:200]} | {event['confidence']:.2f} |"
                    )
            lines.append("")

        if request.include_indicators:
            lines.append("## Indicators")
            lines.append("")
            if not data["indicators"]:
                lines.append("_No indicators have been extracted for this case._")
            else:
                lines.append(
                    f"Total indicators: {data.get('indicator_total', len(data['indicators']))}"
                )
                lines.append("")
                lines.append("| Type | Value | Confidence | Source | First seen |")
                lines.append("| --- | --- | --- | --- | --- |")
                for indicator in data["indicators"]:
                    lines.append(
                        f"| {indicator['type']} | `{indicator['value']}` | "
                        f"{indicator['confidence']:.2f} | {indicator['source']} | "
                        f"{indicator['first_seen'] or 'unknown'} |"
                    )
            lines.append("")

            lines.append("### Cross-case memory")
            lines.append("")
            if not data["memory_links"]:
                lines.append(
                    "_No indicator from this case was previously recorded in other "
                    "cases._"
                )
            else:
                for link in data["memory_links"]:
                    lines.append(
                        f"- **{link['case_number'] or link['case_title']}** - "
                        f"{link['shared_indicator_count']} shared indicator(s): "
                        f"{', '.join(link['shared_values'][:10])}"
                    )
            lines.append("")

        if request.include_findings:
            lines.append("## Findings")
            lines.append("")
            if not data["findings"]:
                lines.append("_No findings have been recorded for this case._")
            else:
                for finding in data["findings"]:
                    lines.append(
                        f"### {finding['title']} ({finding['severity']}, {finding['status']})"
                    )
                    lines.append("")
                    if finding["description"]:
                        lines.append(finding["description"])
                        lines.append("")
                    lines.append(
                        f"- Confidence: {finding['confidence']:.2f}\n"
                        f"- Supporting evidence: {len(finding['evidence_ids'] or [])}\n"
                        f"- Supporting indicators: {len(finding['indicator_ids'] or [])}\n"
                        f"- Historical cases sharing indicators: "
                        f"{len(finding['historical_cases'] or [])}"
                    )
                    if finding["analyst_notes"]:
                        lines.append(f"- Analyst notes: {finding['analyst_notes']}")
                    lines.append("")

        lines.append("## Analysis provenance")
        lines.append("")
        if not data["jobs"]:
            lines.append("_No analysis jobs have been run for this case._")
        else:
            lines.append("| Tool | Status | Source | Tool version | Events | Indicators |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for job in data["jobs"]:
                lines.append(
                    f"| {job['tool']} | {job['status']} | {job['source']} | "
                    f"{job['tool_version'] or 'unknown'} | {job['events_created']} | "
                    f"{job['indicators_created']} |"
                )
        lines.append("")

        if request.include_integrations:
            lines.append("## Integration status at report time")
            lines.append("")
            lines.append("| Tool | Status | Installed | Version | Detail |")
            lines.append("| --- | --- | --- | --- | --- |")
            for info in data["integrations"]:
                lines.append(
                    f"| {info['name']} | {info['status']} | {info['installed']} | "
                    f"{info['version'] or '-'} | {info['detail']} |"
                )
            lines.append("")

        if request.include_ai_summary:
            lines.append("## AI-generated narrative")
            lines.append("")
            lines.append(f"> {AI_DISCLAIMER}")
            lines.append("")
            if ai_summary:
                lines.append(ai_summary)
            else:
                lines.append("_AI summary was not available (Kimi is not configured)._")
            lines.append("")

        if data["notes"]:
            lines.append("## Notes and limitations")
            lines.append("")
            for note in data["notes"]:
                lines.append(f"- {note}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def _render_json(
        self,
        case: Case,
        data: Dict[str, Any],
        request: ReportRequest,
        *,
        ai_summary: Optional[str],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "report": {
                "case_number": case.case_number,
                "title": case.title,
                "description": case.description,
                "status": case.status,
                "severity": case.severity,
                "is_demo": case.is_demo,
                "generated_at": to_iso_z(utcnow()),
                "format": "json",
                "sections": self._sections(request),
            },
            "notes": data["notes"],
        }
        if request.include_evidence:
            payload["evidence"] = data["evidence"]
        if request.include_timeline:
            payload["events"] = data["events"]
            payload["event_total"] = data.get("event_total", 0)
        if request.include_indicators:
            payload["indicators"] = data["indicators"]
            payload["indicator_total"] = data.get("indicator_total", 0)
            payload["cross_case_memory"] = data["memory_links"]
        if request.include_findings:
            payload["findings"] = data["findings"]
        payload["analysis_jobs"] = data["jobs"]
        if request.include_integrations:
            payload["integrations"] = data["integrations"]
        if request.include_ai_summary:
            payload["ai_summary"] = {
                "content": ai_summary or "",
                "available": bool(ai_summary),
                "disclaimer": AI_DISCLAIMER,
            }
        return payload

    # --- Persistence --------------------------------------------------------
    def _persist(
        self, case: Case, title: str, report_format: str, content: str
    ) -> tuple[str, str]:
        self.report_root.mkdir(parents=True, exist_ok=True)
        extension = "json" if report_format == "json" else "md"
        timestamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        slug = sanitize_filename(title)[:40].strip("_.-") or "report"
        filename = f"{case.id}_{timestamp}_{slug}.{extension}"
        path = ensure_within(self.report_root, filename)
        path.write_text(content, encoding="utf-8")
        return filename, str(path)