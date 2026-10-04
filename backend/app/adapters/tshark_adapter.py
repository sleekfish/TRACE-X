"""REAL TShark integration.

If TShark is installed, it is executed against PCAP/PCAPNG evidence using a
safe argument array (never ``shell=True``).  If it is not installed, the
adapter reports ``NOT_INSTALLED`` and produces no fabricated results.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from app.adapters.base import AnalysisResult, BaseToolAdapter, IntegrationInfo
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import AnalysisStatus, IntegrationStatus
from app.parsers.tshark_parser import TsharkParser
from app.utils import subprocess_runner
from app.utils.file_detection import EVIDENCE_PCAP

logger = get_logger(__name__)

# Structured fields TShark extracts from every packet (used for -T ek style
# extraction and documented for provenance).
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "http.host",
    "http.request.uri",
    "http.request.method",
    "http.user_agent",
    "tls.handshake.extensions_server_name",
]


class TsharkAdapter(BaseToolAdapter):
    name = "tshark"

    def __init__(self) -> None:
        self._path: Optional[str] = subprocess_runner.find_executable(
            ["tshark"], settings.tshark_path
        )
        self._version: Optional[str] = None
        self._version_checked = False

    def _resolve(self) -> None:
        if self._path is None:
            self._path = subprocess_runner.find_executable(["tshark"], settings.tshark_path)

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
                detail="TShark is not installed or not on PATH. Set TSHARK_PATH to use it.",
            )
        return IntegrationInfo(
            name=self.name,
            installed=True,
            status=IntegrationStatus.AVAILABLE,
            version=self._get_version(),
            path=self._path,
            supported_evidence_types=self.supported_evidence_types(),
            detail="TShark is available for real PCAP analysis.",
        )

    def build_command(self, evidence_path: Path) -> List[str]:
        assert self._path is not None
        args = [self._path, "-r", str(evidence_path), "-T", "json", "-n"]
        limit = settings.tshark_packet_limit
        if limit and limit > 0:
            args += ["-c", str(limit)]
        return args

    def analyze(self, evidence) -> AnalysisResult:
        self._resolve()
        result = AnalysisResult(tool=self.name, status=AnalysisStatus.PENDING)
        result.metadata["adapter_version"] = self.adapter_version
        result.metadata["evidence_sha256"] = getattr(evidence, "sha256", "")

        if not self._path:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = "TShark is not installed (NOT_INSTALLED)."
            return result

        evidence_path = Path(getattr(evidence, "storage_path", ""))
        if not evidence_path.is_file():
            result.status = AnalysisStatus.FAILED
            result.error_message = "Evidence file is missing on disk."
            return result

        args = self.build_command(evidence_path)
        result.command = args
        result.tool_version = self._get_version()

        try:
            tool_result = subprocess_runner.run_tool(args)
        except subprocess_runner.ToolNotFoundError as exc:
            result.status = AnalysisStatus.UNAVAILABLE
            result.error_message = f"TShark executable not found: {exc}"
            return result

        result.stdout = tool_result.stdout
        result.stderr = tool_result.stderr
        result.exit_code = tool_result.exit_code
        result.metadata["duration_seconds"] = tool_result.duration_seconds
        result.metadata["truncated"] = tool_result.truncated

        if tool_result.timed_out:
            result.status = AnalysisStatus.FAILED
            result.error_message = "TShark execution timed out."
            return result
        if tool_result.exit_code != 0 and not tool_result.stdout.strip():
            result.status = AnalysisStatus.FAILED
            result.error_message = (
                tool_result.stderr.strip()
                or f"TShark exited with code {tool_result.exit_code}."
            )
            return result

        result.parser_name = "tshark"
        result.records = self.parse_output(tool_result.stdout)
        result.status = AnalysisStatus.PARTIAL if tool_result.truncated else AnalysisStatus.COMPLETED
        result.metadata["packet_records"] = len(result.records)
        return result

    def parse_output(self, raw_output: str, **kwargs) -> List[dict]:
        return TsharkParser().parse(raw_output, **kwargs)

    def normalize(self, parsed_output, **kwargs):
        raise NotImplementedError("Normalisation is performed by the analysis service.")