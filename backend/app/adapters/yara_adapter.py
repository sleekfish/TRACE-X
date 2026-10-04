"""REAL YARA integration.

YARA is executed against evidence files using a **configured** rule
directory.  Users can never supply arbitrary rules through the API; only rules
present in ``YARA_RULES_PATH`` are applied.

A YARA match is NOT a maliciousness verdict - it is surfaced as a finding
candidate that requires investigator review.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.yara_parser import YaraParser
from app.utils import subprocess_runner
from app.utils.file_detection import (
    EVIDENCE_ARCHIVE,
    EVIDENCE_EXECUTABLE,
    EVIDENCE_PDF,
    EVIDENCE_TEXT,
    EVIDENCE_UNKNOWN,
)

logger = get_logger(__name__)


class YaraAdapter(BaseToolAdapter):
    name = "yara"

    def __init__(self) -> None:
        self._path: Optional[str] = subprocess_runner.find_executable(
            ["yara", "yara64", "yara64.exe"], settings.yara_path
        )
        self._version: Optional[str] = None
        self._version_checked = False

    def _resolve(self) -> None:
        if self._path is None:
            self._path = subprocess_runner.find_executable(
                ["yara", "yara64", "yara64.exe"], settings.yara_path
            )

    def _rules_path(self) -> Optional[str]:
        raw = (settings.yara_rules_path or "").strip()
        if not raw:
            return None
        path = Path(raw)
        return str(path) if path.exists() else None

    def _get_version(self) -> Optional[str]:
        if not self._version_checked:
            self._version_checked = True
            if self._path:
                self._version = subprocess_runner.get_tool_version(self._path, ["--version"])
        return self._version

    def is_available(self) -> bool:
        self._resolve()
        return bool(self._path and self._rules_path())

    def supported_evidence_types(self) -> List[str]:
        return [EVIDENCE_EXECUTABLE, EVIDENCE_ARCHIVE, EVIDENCE_PDF, EVIDENCE_TEXT, EVIDENCE_UNKNOWN]

    def integration_info(self) -> IntegrationInfo:
        self._resolve()
        rules = self._rules_path()
        if not self._path:
            return IntegrationInfo(
                name=self.name,
                installed=False,
                status=IntegrationStatus.NOT_INSTALLED,
                supported_evidence_types=self.supported_evidence_types(),
                detail="YARA is not installed or not on PATH. Set YARA_PATH to use it.",
            )
        if not rules:
            return IntegrationInfo(
                name=self.name,
                installed=True,
                configured=False,
                status=IntegrationStatus.CONFIGURATION_REQUIRED,
                version=self._get_version(),
                path=self._path,
                supported_evidence_types=self.supported_evidence_types(),
                detail="YARA is installed but YARA_RULES_PATH is not configured.",
            )
        return IntegrationInfo(
            name=self.name,
            installed=True,
            configured=True,
            status=IntegrationStatus.AVAILABLE,
            version=self._get_version(),
            path=self._path,
            supported_evidence_types=self.supported_evidence_types(),
            detail=f"YARA is available with rules at {rules}.",
        )

    def analyze(self, evidence) -> AnalysisResult:
        self._resolve()
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")

        if not self._path:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = "YARA is not installed (NOT_INSTALLED)."
            return result

        rules = self._rules_path()
        if not rules:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = (
                "YARA is installed but YARA_RULES_PATH is not configured "
                "(CONFIGURATION_REQUIRED)."
            )
            return result

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        args = [self._path, "-r", "-m", rules, str(evidence_path)]
        result.command = args
        result.tool_version = self._get_version()

        try:
            tool_result = subprocess_runner.run_tool(args)
        except subprocess_runner.ToolNotFoundError as exc:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = f"YARA executable not found: {exc}"
            return result

        result.stdout = tool_result.stdout
        result.stderr = tool_result.stderr
        result.exit_code = tool_result.exit_code
        result.metadata["duration_seconds"] = tool_result.duration_seconds

        if tool_result.timed_out:
            result.status = AnalysisStatus.FAILED
            result.error_message = "YARA execution timed out."
            return result

        # YARA exit code 0 = no match, 1 = match(es), >1 = error.
        if tool_result.exit_code not in (0, 1):
            result.status = AnalysisStatus.FAILED
            result.error_message = (
                tool_result.stderr.strip()
                or f"YARA exited with code {tool_result.exit_code}."
            )
            return result

        result.parser_name = "yara"
        result.records = self.parse_output(tool_result.stdout)
        result.status = AnalysisStatus.COMPLETED
        result.metadata["matches"] = len(result.records)
        return result

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return YaraParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")