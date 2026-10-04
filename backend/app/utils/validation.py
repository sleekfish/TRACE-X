"""Evidence filename / path safety validation."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from app.core.exceptions import ValidationError

_SAFE_EXTENSION_RE = re.compile(r"^[A-Za-z0-9]{1,12}$")
_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_filename(filename: str) -> str:
    """Return a filesystem-safe *display* filename.

    Strips directory components and path-traversal sequences while preserving a
    recognisable name for the investigator.
    """
    if not filename:
        raise ValidationError("Evidence filename must not be empty.")

    # Drop any directory component (handles both / and \ separators).
    base = filename.replace("\\", "/").split("/")[-1].strip()
    base = base.replace("\x00", "")
    if base in ("", ".", ".."):
        raise ValidationError("Invalid evidence filename.")

    cleaned = _UNSAFE_CHARS_RE.sub("_", base)
    # Collapse any residual traversal sequences.
    cleaned = cleaned.replace("..", "_")
    return cleaned[:200] or "evidence"


def safe_storage_name(original_filename: str) -> str:
    """Generate a collision-free storage filename for evidence.

    Uses a random UUID prefix followed by the (validated) extension so uploaded
    files never overwrite one another and never leak the original path.
    """
    safe = sanitize_filename(original_filename)
    extension = ""
    if "." in safe:
        candidate = safe.rsplit(".", 1)[-1]
        if _SAFE_EXTENSION_RE.match(candidate):
            extension = "." + candidate.lower()
    return f"{uuid.uuid4().hex}{extension}"


def ensure_within(base_dir: str | Path, candidate: str | Path) -> Path:
    """Resolve ``candidate`` and ensure it stays inside ``base_dir``.

    Guards against path traversal for any path derived from user input.
    """
    base = Path(base_dir).resolve()
    resolved = (base / candidate).resolve() if not Path(candidate).is_absolute() else Path(candidate).resolve()
    if base != resolved and base not in resolved.parents:
        raise ValidationError(
            "Resolved path escapes the permitted storage directory.",
            {"base_dir": str(base)},
        )
    return resolved