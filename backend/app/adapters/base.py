"""Base interface shared by every forensic tool adapter."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models.enums import AnalysisSource, AnalysisStatus

ADAPTER_VERSION = "1.0.0"


@dataclass
class AnalysisResult:
    """Result of running a forensic adapter against a single evidence item."""

    tool: str
    status: str
    source: str = AnalysisSource.REAL
    tool_version: Optional[str] = None
    command: List[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    error_message: str = ""
    parser_name: str = ""
    records: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_real(self) -> bool:
        return self.source == AnalysisSource.REAL

    @property
    def succeeded(self) -> bool:
        return self.status in (AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL)


@dataclass
class IntegrationInfo:
    """Reported status of an integration for the frontend."""

    name: str
    installed: bool
    status: str
    version: Optional[str] = None
    path: Optional[str] = None
    configured: bool = True
    supported_evidence_types: List[str] = field(default_factory=list)
    detail: str = ""
    is_external: bool = False


class BaseToolAdapter(abc.ABC):
    """Common interface every forensic tool adapter must implement."""

    name: str = "base"
    adapter_version: str = ADAPTER_VERSION
    is_external_service: bool = False

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True only when the tool can ACTUALLY be executed."""
        raise NotImplementedError

    @abc.abstractmethod
    def integration_info(self) -> IntegrationInfo:
        """Return the honest integration status (never raises)."""
        raise NotImplementedError

    @abc.abstractmethod
    def supported_evidence_types(self) -> List[str]:
        raise NotImplementedError

    @abc.abstractmethod
    def analyze(self, evidence) -> AnalysisResult:
        """Run the tool (or return an unavailable result) for this evidence."""
        raise NotImplementedError

    def parse_output(self, raw_output: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Parse raw tool output into records. Optional for adapters."""
        return []

    def normalize(self, parsed_output: List[Dict[str, Any]], **kwargs: Any):
        """Normalise parsed records. Optional; the service layer does this."""
        raise NotImplementedError