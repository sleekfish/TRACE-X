"""Generic, always-available parser adapter.

This adapter performs REAL parsing of the evidence file using TRACE-X's own
parsers (JSON / NDJSON / CSV / LOG / TXT).  It does not require any external
tool, so it is always available - but it is explicitly NOT a forensic tool
execution and is reported as such (``tool = "tracex-generic-parser"``).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.generic_parser import GenericParser
from app.utils.file_detection import (
    EVIDENCE_CSV,
    EVIDENCE_JSON,
    EVIDENCE_LOG,
    EVIDENCE_NDJSON,
    EVIDENCE_TEXT,
)

logger = get_logger(__name__)


def read_text_file(path: Path, max_bytes: int | None = None) -> str:
    """Read a text file with encoding fallbacks, bounded by ``max_bytes``."""
    limit = max_bytes or settings.max_tool_output_bytes
    raw = path.read_bytes()[:limit]
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class GenericAdapter(BaseToolAdapter):
    name = "tracex-generic-parser"

    def is_available(self) -> bool:
        return True

    def supported_evidence_types(self) -> List[str]:
        return [EVIDENCE_JSON, EVIDENCE_NDJSON, EVIDENCE_CSV, EVIDENCE_LOG, EVIDENCE_TEXT]

    def integration_info(self) -> IntegrationInfo:
        return IntegrationInfo(
            name=self.name,
            installed=True,
            configured=True,
            status=IntegrationStatus.AVAILABLE,
            version=self.adapter_version,
            supported_evidence_types=self.supported_evidence_types(),
            detail=(
                "Built-in TRACE-X parser for structured and text evidence. "
                "Real parsing - not an external forensic tool."
            ),
        )

    def analyze(self, evidence) -> AnalysisResult:
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")
        result.parser_name = "generic"

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        try:
            content = read_text_file(evidence_path)
        except OSError as exc:
            result.status = AnalysisStatus.FAILED
            result.error_message = f"Unable to read evidence file: {exc}"
            return result

        result.command = []
        result.tool_version = self.adapter_version
        result.stdout = content[:20000]
        result.exit_code = 0
        result.records = self.parse_output(
            content,
            filename=getattr(evidence, "original_filename", "evidence.txt"),
            evidence_type=getattr(evidence, "evidence_type", None),
        )
        result.status = AnalysisStatus.COMPLETED
        result.metadata["record_count"] = len(result.records)
        return result

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return GenericParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")