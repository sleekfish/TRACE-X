"""Safe external forensic-tool execution.

Centralises EVERY subprocess invocation in the backend so that the same safety
rules apply everywhere:

* argument arrays only - **never** ``shell=True``
* hard execution timeouts
* bounded output capture (stdout/stderr)
* isolated temporary working directories that are always cleaned up
* exit code + duration captured for provenance
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - used safely via argument arrays, never shell=True
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ToolResult:
    """Outcome of a single external tool execution."""

    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    truncated: bool = False
    tool_version: Optional[str] = None
    produced_files: Dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ToolNotFoundError(RuntimeError):
    """Raised when a requested executable cannot be located."""


def find_executable(candidates: Sequence[str], configured_path: Optional[str] = None) -> Optional[str]:
    """Locate an executable given an explicit path and/or name candidates."""
    if configured_path:
        if Path(configured_path).is_file():
            return configured_path
        resolved = shutil.which(configured_path)
        if resolved:
            return resolved
        return None
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def run_tool(
    args: Sequence[str],
    *,
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    max_output_bytes: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
    input_bytes: Optional[bytes] = None,
) -> ToolResult:
    """Run an external forensic tool safely.

    ``args`` MUST be a full argument array whose first element is the resolved
    executable path.  This function never uses ``shell=True``.
    """
    if not args:
        raise ValueError("run_tool requires a non-empty argument array.")
    if isinstance(args, str):
        raise ValueError("run_tool requires an argument array, not a string.")

    timeout = timeout or settings.tool_timeout_seconds
    max_output_bytes = max_output_bytes or settings.max_tool_output_bytes
    command = [str(a) for a in args]

    logger.info("Executing forensic tool: %s", " ".join(command))
    started = time.monotonic()
    timed_out = False
    exit_code = -1
    stdout_bytes = b""
    stderr_bytes = b""

    try:
        completed = subprocess.run(  # noqa: S603 - safe: arg array, no shell
            command,
            cwd=cwd,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            check=False,
        )
        exit_code = completed.returncode
        stdout_bytes = completed.stdout or b""
        stderr_bytes = completed.stderr or b""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -9
        stdout_bytes = exc.stdout or b""
        stderr_bytes = exc.stderr or b""
        logger.warning("Forensic tool timed out after %ss: %s", timeout, command[0])
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise ToolNotFoundError(str(exc)) from exc

    duration = round(time.monotonic() - started, 3)
    truncated = False
    if len(stdout_bytes) > max_output_bytes:
        stdout_bytes = stdout_bytes[:max_output_bytes]
        truncated = True
    if len(stderr_bytes) > max_output_bytes:
        stderr_bytes = stderr_bytes[:max_output_bytes]
        truncated = True

    return ToolResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_seconds=duration,
        timed_out=timed_out,
        truncated=truncated,
    )


def get_tool_version(executable: str, version_args: Sequence[str]) -> Optional[str]:
    """Return the first non-empty line of the tool's version output."""
    try:
        result = run_tool([executable, *version_args], timeout=20)
    except (ToolNotFoundError, ValueError):
        return None
    text = (result.stdout or result.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0].strip()


def temp_working_dir(prefix: str = "tracex_tool_") -> tempfile.TemporaryDirectory:
    """Create an isolated temporary working directory.

    Callers must use this as a context manager (``with``) so the directory is
    always removed afterwards — no temporary artifacts are left behind.
    """
    base = settings.temp_storage_path
    Path(base).mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=base)