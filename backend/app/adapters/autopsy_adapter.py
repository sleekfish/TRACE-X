"""Autopsy-compatible artifact ingestion.

TRACE-X does NOT attempt to reimplement Autopsy.  Instead it consumes
structured exports produced by Autopsy (CSV, JSON, NDJSON, timeline exports)
and normalises them into the common TRACE-X data model, preserving
``source = "autopsy"`` provenance.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.adapters.generic_adapter import read_text_file
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.generic_parser import GenericParser
from app.utils.file_detection import (
    EVIDENCE_CSV,
    EVIDENCE_JSON,
    EVIDENCE_NDJSON,
    EVIDENCE_TEXT,
)

logger = get_logger(__name__)


class AutopsyAdapter(BaseToolAdapter):
    name = "autopsy"

    def is_available(self) -> bool:
        # Ingestion of Autopsy exports needs no external binary.
        return True

    def supported_evidence_types(self) -> List[str]:
        return [EVIDENCE_CSV, EVIDENCE_JSON, EVIDENCE_NDJSON, EVIDENCE_TEXT]

    def integration_info(self) -> IntegrationInfo:
        return IntegrationInfo(
            name=self.name,
            installed=True,
            configured=True,
            status=IntegrationStatus.AVAILABLE,
            version=self.adapter_version,
            supported_evidence_types=self.supported_evidence_types(),
            detail=(
                "Ingests structured Autopsy exports (CSV/JSON/NDJSON timeline & "
                "artifact exports). TRACE-X does not run Autopsy itself."
            ),
        )

    def analyze(self, evidence) -> AnalysisResult:
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")
        result.parser_name = "autopsy-export"

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        try:
            content = read_text_file(evidence_path)
        except OSError as exc:
            result.status = AnalysisStatus.FAILED
            result.error_message = f"Unable to read Autopsy export: {exc}"
            return result

        result.exit_code = 0
        result.tool_version = self.adapter_version
        result.stdout = content[:20000]
        result.records = self.parse_output(
            content,
            filename=getattr(evidence, "original_filename", "autopsy_export.csv"),
            evidence_type=getattr(evidence, "evidence_type", None),
        )
        result.status = AnalysisStatus.COMPLETED
        result.metadata["record_count"] = len(result.records)
        result.metadata["provenance"] = "autopsy"
        return result

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return GenericParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")