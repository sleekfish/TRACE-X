"""REAL Zeek integration.

If Zeek is installed it is run against PCAP evidence inside an isolated
temporary working directory.  The resulting logs (conn/dns/http/ssl/files) are
parsed and normalised.  If Zeek is not installed the adapter reports
``NOT_INSTALLED`` - no output is ever fabricated.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Dict, List, Optional

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.zeek_parser import ZeekParser
from app.utils import subprocess_runner
from app.utils.file_detection import EVIDENCE_PCAP

logger = get_logger(__name__)

_ZEEK_LOG_NAMES = ["conn.log", "dns.log", "http.log", "ssl.log", "files.log"]


class ZeekAdapter(BaseToolAdapter):
    name = "zeek"

    def __init__(self) -> None:
        self._path: Optional[str] = subprocess_runner.find_executable(
            ["zeek"], settings.zeek_path
        )
        self._version: Optional[str] = None
        self._version_checked = False

    def _resolve(self) -> None:
        if self._path is None:
            self._path = subprocess_runner.find_executable(["zeek"], settings.zeek_path)

    def _get_version(self) -> Optional[str]:
        if not self._version_checked:
            self._version_checked = True
            if self._path:
                self._version = subprocess_runner.get_tool_version(self._path, ["--version"])
        return self._version

    def is_available(self) -> bool:
        self._resolve()
        return bool(self._path)

    def supported_evidence_types(self) -> List[str]:
        return [EVIDENCE_PCAP]

    def integration_info(self) -> IntegrationInfo:
        self._resolve()
        if not self._path:
            return IntegrationInfo(
                name=self.name,
                installed=False,
                status=IntegrationStatus.NOT_INSTALLED,
                supported_evidence_types=self.supported_evidence_types(),
                detail="Zeek is not installed or not on PATH. Set ZEEK_PATH to use it.",
            )
        return IntegrationInfo(
            name=self.name,
            installed=True,
            status=IntegrationStatus.AVAILABLE,
            version=self._get_version(),
            path=self._path,
            supported_evidence_types=self.supported_evidence_types(),
            detail="Zeek is available for real PCAP analysis.",
        )

    def analyze(self, evidence) -> AnalysisResult:
        self._resolve()
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")

        if not self._path:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = "Zeek is not installed (NOT_INSTALLED)."
            return result

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        with subprocess_runner.temp_working_dir("tracex_zeek_") as workdir:
            args = [self._path, "-r", str(evidence_path.resolve())]
            result.command = args
            result.tool_version = self._get_version()
            try:
                tool_result = subprocess_runner.run_tool(args, cwd=workdir)
            except subprocess_runner.ToolNotFoundError as exc:
                result.status = AnalysisStatus.UNAVAILABLE
                result.error_message = f"Zeek executable not found: {exc}"
                return result

            result.stdout = tool_result.stdout
            result.stderr = tool_result.stderr
            result.exit_code = tool_result.exit_code
            result.metadata["duration_seconds"] = tool_result.duration_seconds

            if tool_result.timed_out:
                result.status = AnalysisStatus.FAILED
                result.error_message = "Zeek execution timed out."
                return result

            records = self._parse_log_directory(Path(workdir))
            result.records = records
            result.parser_name = "zeek"
            result.metadata["log_files"] = {
                name: str(Path(workdir) / name) for name in _ZEEK_LOG_NAMES
            }
            result.metadata["log_records"] = len(records)

            if records:
                result.status = AnalysisStatus.COMPLETED
            elif tool_result.exit_code == 0:
                result.status = AnalysisStatus.COMPLETED
                result.error_message = "Zeek ran successfully but produced no log records."
            else:
                result.status = AnalysisStatus.FAILED
                result.error_message = (
                    tool_result.stderr.strip()
                    or f"Zeek exited with code {tool_result.exit_code}."
                )
            # Persist a copy of the log summaries before the temp dir is removed.
            result.metadata["log_preview"] = {
                name: self._read_text(Path(workdir) / name)[:2000]
                for name in _ZEEK_LOG_NAMES
                if (Path(workdir) / name).is_file()
            }
        return result

    def _parse_log_directory(self, directory: Path) -> List[Dict]:
        parser = ZeekParser()
        records: List[Dict] = []
        for name in _ZEEK_LOG_NAMES:
            log_path = directory / name
            if not log_path.is_file():
                continue
            content = self._read_text(log_path)
            records.extend(parser.parse(content, log_name=name))
        # Some Zeek installs write rotated logs (e.g. dns.log.gz) - skip those.
        return records

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def parse_output(self, raw_output: str, **kwargs) -> List[Dict]:
        return ZeekParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")