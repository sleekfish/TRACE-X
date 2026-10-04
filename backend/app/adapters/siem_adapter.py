"""Generic SIEM / EDR telemetry ingestion adapter.

Supports structured telemetry in JSON, NDJSON and CSV form (SIEM events, EDR
events, authentication logs, network events, endpoint events).

* File-based ingestion (evidence exports) works without configuration.
* Live API pull requires ``SIEM_URL`` (+ optional ``SIEM_API_KEY``); when it is
  not configured the adapter reports ``CONFIGURATION_REQUIRED`` and never
  fabricates live telemetry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.adapters.generic_adapter import read_text_file
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.generic_parser import GenericParser
from app.utils.file_detection import EVIDENCE_CSV, EVIDENCE_JSON, EVIDENCE_NDJSON

logger = get_logger(__name__)


class SiemAdapter(BaseToolAdapter):
    name = "siem"
    is_external_service = True

    def _configured(self) -> bool:
        return bool((settings.siem_url or "").strip())

    def is_available(self) -> bool:
        # Structured telemetry exports can always be ingested; the *live* API
        # requires configuration (reported separately).
        return True

    def supported_evidence_types(self) -> List[str]:
        return [EVIDENCE_JSON, EVIDENCE_NDJSON, EVIDENCE_CSV]

    def integration_info(self) -> IntegrationInfo:
        configured = self._configured()
        return IntegrationInfo(
            name=self.name,
            installed=True,
            configured=configured,
            status=IntegrationStatus.AVAILABLE if configured else IntegrationStatus.CONFIGURATION_REQUIRED,
            version=self.adapter_version,
            supported_evidence_types=self.supported_evidence_types(),
            detail=(
                "Live SIEM/EDR API configured; file-based telemetry ingestion also available."
                if configured
                else "Live SIEM/EDR API not configured (CONFIGURATION_REQUIRED). "
                "File-based telemetry ingestion (JSON/NDJSON/CSV) is available."
            ),
            is_external=True,
        )

    def analyze(self, evidence) -> AnalysisResult:
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")
        result.parser_name = "siem-telemetry"

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        try:
            content = read_text_file(evidence_path)
        except OSError as exc:
            result.status = AnalysisStatus.FAILED
            result.error_message = f"Unable to read telemetry export: {exc}"
            return result

        result.exit_code = 0
        result.tool_version = self.adapter_version
        result.stdout = content[:20000]
        result.records = self.parse_output(
            content,
            filename=getattr(evidence, "original_filename", "telemetry.json"),
            evidence_type=getattr(evidence, "evidence_type", None),
        )
        result.status = AnalysisStatus.COMPLETED
        result.metadata["record_count"] = len(result.records)
        return result

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return GenericParser().parse(raw_output, **kwargs)

    def pull_live_events(self, query: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Attempt a live pull from the configured SIEM API.

        Returns a dict describing the real outcome; never fabricates data.
        """
        if not self._configured():
            return {
                "status": IntegrationStatus.CONFIGURATION_REQUIRED,
                "records": [],
                "error": "SIEM_URL is not configured.",
            }
        url = (settings.siem_url or "").rstrip("/")
        headers = {"Accept": "application/json"}
        if settings.siem_api_key:
            headers["Authorization"] = f"Bearer {settings.siem_api_key}"
        params: Dict[str, Any] = {"limit": limit}
        if query:
            params["q"] = query
        try:
            response = httpx.get(url, headers=headers, params=params, timeout=30.0)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Live SIEM pull failed: %s", exc)
            return {"status": IntegrationStatus.ERROR, "records": [], "error": str(exc)}
        items = payload if isinstance(payload, list) else payload.get("events", [])
        return {"status": IntegrationStatus.AVAILABLE, "records": items, "error": ""}

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")