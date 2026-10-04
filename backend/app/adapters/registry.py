"""Adapter registry.

Maps evidence types to the adapters that can *truthfully* process them and
exposes the aggregate integration status used by ``/integrations/status``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from app.adapters.autopsy_adapter import AutopsyAdapter
from app.adapters.base import BaseToolAdapter, IntegrationInfo
from app.adapters.generic_adapter import GenericAdapter
from app.adapters.siem_adapter import SiemAdapter
from app.adapters.tshark_adapter import TsharkAdapter
from app.adapters.velociraptor_adapter import VelociraptorAdapter
from app.adapters.yara_adapter import YaraAdapter
from app.adapters.zeek_adapter import ZeekAdapter
from app.models.enums import AnalysisSource
from app.utils.file_detection import (
    EVIDENCE_ARCHIVE,
    EVIDENCE_CSV,
    EVIDENCE_EXECUTABLE,
    EVIDENCE_JSON,
    EVIDENCE_LOG,
    EVIDENCE_NDJSON,
    EVIDENCE_PCAP,
    EVIDENCE_PDF,
    EVIDENCE_TEXT,
    EVIDENCE_UNKNOWN,
)

# Best-effort default ordering when no explicit adapter selection is provided.
_DEFAULT_ADAPTERS: Dict[str, List[str]] = {
    EVIDENCE_PCAP: ["tshark", "zeek"],
    EVIDENCE_EXECUTABLE: ["yara"],
    EVIDENCE_ARCHIVE: ["yara"],
    EVIDENCE_PDF: ["yara"],
    EVIDENCE_JSON: ["siem", "autopsy", "tracex-generic-parser"],
    EVIDENCE_NDJSON: ["siem", "autopsy", "tracex-generic-parser"],
    EVIDENCE_CSV: ["autopsy", "siem", "tracex-generic-parser"],
    EVIDENCE_LOG: ["tracex-generic-parser"],
    EVIDENCE_TEXT: ["yara", "tracex-generic-parser"],
    EVIDENCE_UNKNOWN: ["tracex-generic-parser"],
}


class AdapterRegistry:
    """Holds one instance of every adapter and resolves them by evidence type."""

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseToolAdapter] = {
            adapter.name: adapter
            for adapter in (
                TsharkAdapter(),
                ZeekAdapter(),
                YaraAdapter(),
                VelociraptorAdapter(),
                SiemAdapter(),
                AutopsyAdapter(),
                GenericAdapter(),
            )
        }

    # --- Lookup -------------------------------------------------------------
    def all(self) -> List[BaseToolAdapter]:
        return list(self._adapters.values())

    def get(self, name: str) -> Optional[BaseToolAdapter]:
        return self._adapters.get(name)

    def names(self) -> List[str]:
        return list(self._adapters.keys())

    def for_evidence_type(self, evidence_type: str) -> List[BaseToolAdapter]:
        """Return adapters relevant to ``evidence_type`` (preferred order first)."""
        preferred = _DEFAULT_ADAPTERS.get(evidence_type, [])
        selected = [
            self._adapters[name]
            for name in preferred
            if name in self._adapters
        ]
        return selected

    def available_for_evidence_type(self, evidence_type: str) -> List[BaseToolAdapter]:
        return [adapter for adapter in self.for_evidence_type(evidence_type) if adapter.is_available()]

    # --- Status -------------------------------------------------------------
    def integration_infos(self) -> List[IntegrationInfo]:
        """Honest, never-raising integration status for every adapter."""
        infos: List[IntegrationInfo] = []
        for adapter in self._adapters.values():
            try:
                infos.append(adapter.integration_info())
            except Exception as exc:  # noqa: BLE001 - status must never crash the API
                infos.append(
                    IntegrationInfo(
                        name=adapter.name,
                        installed=False,
                        configured=False,
                        status="ERROR",
                        supported_evidence_types=[],
                        detail=f"Failed to determine status: {exc}",
                        is_external=adapter.is_external_service,
                    )
                )
        return infos

    def real_analysis_capable(self) -> List[str]:
        """Adapters that can currently execute a REAL external forensic binary.

        The built-in parser, structured-export ingestion and external services
        are intentionally excluded: they are real, but they are not local
        forensic-binary execution.
        """
        binary_adapters = {"tshark", "zeek", "yara"}
        return [
            adapter.name
            for adapter in self._adapters.values()
            if adapter.name in binary_adapters and adapter.is_available()
        ]

    def demo_source(self) -> str:
        return AnalysisSource.REAL


registry = AdapterRegistry()