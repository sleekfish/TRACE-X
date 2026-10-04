"""Velociraptor integration layer.

Velociraptor is an optional, externally-hosted DFIR platform.  This adapter
connects ONLY when ``VELOCIRAPTOR_URL`` and ``VELOCIRAPTOR_API_KEY`` are
configured; otherwise it reports ``CONFIGURATION_REQUIRED`` and never pretends
that Velociraptor data exists.

Only an approved, fixed set of artifacts can be requested - there is no
arbitrary artifact execution surface.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.json_parser import JsonParser

logger = get_logger(__name__)

# Only these vetted artifacts may be requested.
APPROVED_ARTIFACTS = [
    "Windows.System.Pslist",
    "Windows.Network.Netstat",
    "Windows.Sys.Users",
    "Windows.NTFS.MFT",
    "Generic.Client.Info",
]


class VelociraptorAdapter(BaseToolAdapter):
    name = "velociraptor"
    is_external_service = True

    def _configured(self) -> bool:
        return bool((settings.velociraptor_url or "").strip()) and bool(
            (settings.velociraptor_api_key or "").strip()
        )

    def is_available(self) -> bool:
        return self._configured()

    def supported_evidence_types(self) -> List[str]:
        return []

    def integration_info(self) -> IntegrationInfo:
        if not self._configured():
            return IntegrationInfo(
                name=self.name,
                installed=False,
                configured=False,
                status=IntegrationStatus.CONFIGURATION_REQUIRED,
                supported_evidence_types=self.supported_evidence_types(),
                detail="Set VELOCIRAPTOR_URL and VELOCIRAPTOR_API_KEY to enable this integration.",
                is_external=True,
            )
        return IntegrationInfo(
            name=self.name,
            installed=True,
            configured=True,
            status=IntegrationStatus.AVAILABLE,
            version=self.adapter_version,
            path=settings.velociraptor_url,
            supported_evidence_types=self.supported_evidence_types(),
            detail="Velociraptor API is configured.",
            is_external=True,
        )

    def analyze(self, evidence) -> AnalysisResult:
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        if not self._configured():
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = (
                "Velociraptor is not configured (CONFIGURATION_REQUIRED). "
                "Set VELOCIRAPTOR_URL and VELOCIRAPTOR_API_KEY."
            )
            return result

        artifact = getattr(evidence, "acquisition_source", "") or "Windows.System.Pslist"
        if artifact not in APPROVED_ARTIFACTS:
            result.status = AnalysisStatus.FAILED
            result.error_message = (
                f"Artifact '{artifact}' is not in the approved list: {APPROVED_ARTIFACTS}"
            )
            return result

        collected = self.collect_artifact(artifact)
        result.stdout = str(collected.get("raw", ""))[:20000]
        result.stderr = str(collected.get("error", ""))
        result.metadata["artifact"] = artifact
        result.parser_name = "velociraptor"

        if collected.get("status") != IntegrationStatus.AVAILABLE:
            result.status = (
                AnalysisStatus.UNAVAILABLE
                if collected.get("status") == IntegrationStatus.CONFIGURATION_REQUIRED
                else AnalysisStatus.FAILED
            )
            result.error_message = str(collected.get("error", "Velociraptor request failed."))
            return result

        result.records = self.parse_output(str(collected.get("raw", "")))
        result.status = AnalysisStatus.COMPLETED
        result.exit_code = 0
        result.tool_version = self.adapter_version
        return result

    def collect_artifact(self, artifact: str) -> Dict[str, Any]:
        """Request an approved artifact from the configured Velociraptor server."""
        url = (settings.velociraptor_url or "").rstrip("/") + "/api/v1/CollectArtifact"
        headers = {
            "Authorization": f"Bearer {settings.velociraptor_api_key}",
            "Content-Type": "application/json",
        }
        body = {"artifacts": [artifact]}
        try:
            response = httpx.post(url, headers=headers, json=body, timeout=60.0)
            response.raise_for_status()
            return {"status": IntegrationStatus.AVAILABLE, "raw": response.text, "error": ""}
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Velociraptor collection failed: %s", exc)
            return {"status": IntegrationStatus.ERROR, "raw": "", "error": str(exc)}

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return JsonParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")