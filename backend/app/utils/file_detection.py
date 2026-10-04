"""Evidence type detection.

Never trust a filename extension alone.  Detection combines magic-byte
signature sniffing with an extension *hint* that is always subordinate to the
actual content.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple

# --- Signature (magic byte) definitions -------------------------------------
_PCAP_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_BE = b"\xa1\xb2\xc3\xd4"
_PCAP_NS = b"\x4d\x3c\xb2\xa1"
_PCAPNG = b"\x0a\x0d\x0d\x0a"
_PCAP_LE_NANO = b"\x4d\x3c\xb2\xa1"
_ZIP = b"PK\x03\x04"
_GZIP = b"\x1f\x8b"
_PDF = b"%PDF"
_ELF = b"\x7fELF"
_PE = b"MZ"
_SQLITE = b"SQLite format 3\x00"

PCAP_SIGNATURES = {_PCAP_LE, _PCAP_BE, _PCAP_NS, _PCAP_LE_NANO}

# Canonical evidence types understood by the adapters.
EVIDENCE_PCAP = "PCAP"
EVIDENCE_JSON = "JSON"
EVIDENCE_NDJSON = "NDJSON"
EVIDENCE_CSV = "CSV"
EVIDENCE_LOG = "LOG"
EVIDENCE_TEXT = "TXT"
EVIDENCE_PDF = "PDF"
EVIDENCE_ARCHIVE = "ARCHIVE"
EVIDENCE_EXECUTABLE = "EXECUTABLE"
EVIDENCE_SQLITE = "SQLITE"
EVIDENCE_YARA = "YARA_RULE"
EVIDENCE_UNKNOWN = "UNKNOWN"


def _sniff_pcap(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] in PCAP_SIGNATURES


def _sniff_pcapng(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _PCAPNG


def _looks_like_json(data: bytes) -> bool:
    stripped = data.lstrip()
    if not stripped:
        return False
    if stripped[:1] not in (b"{", b"["):
        return False
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            json.loads(stripped.decode(encoding))
            return True
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return False


def _looks_like_ndjson(data: bytes) -> bool:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False
    sample = lines[:5]
    ok = 0
    for line in sample:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                ok += 1
        except json.JSONDecodeError:
            return False
    return ok == len(sample)


def _sniff_csv(data: bytes) -> bool:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False
    candidates = [",", "\t", ";", "|"]
    header = lines[0]
    for delimiter in candidates:
        if delimiter in header and header.count(delimiter) >= 1:
            # Check the delimiter count is roughly consistent.
            counts = {ln.count(delimiter) for ln in lines[:10]}
            return len(counts) <= 2
    return False


def detect_evidence_type(filename: str, data: bytes) -> Tuple[str, str]:
    """Return ``(evidence_type, detection_method)`` for the given content.

    ``detection_method`` is ``"signature"`` or ``"extension"`` so provenance
    clearly shows how the type was determined.
    """
    head = data[:65536]
    suffix = Path(filename).suffix.lower().lstrip(".")

    # --- Strong, content-based detection first ------------------------------
    if _sniff_pcapng(head):
        return EVIDENCE_PCAP, "signature"
    if _sniff_pcap(head):
        return EVIDENCE_PCAP, "signature"
    if head.startswith(_ZIP):
        return EVIDENCE_ARCHIVE, "signature"
    if head.startswith(_GZIP):
        return EVIDENCE_ARCHIVE, "signature"
    if head.startswith(_PDF):
        return EVIDENCE_PDF, "signature"
    if head.startswith(_ELF):
        return EVIDENCE_EXECUTABLE, "signature"
    if head.startswith(_SQLITE):
        return EVIDENCE_SQLITE, "signature"

    # --- Structural (text) detection ----------------------------------------
    if _looks_like_json(head):
        return EVIDENCE_JSON, "content"
    if _looks_like_ndjson(head):
        return EVIDENCE_NDJSON, "content"
    if _sniff_csv(head):
        return EVIDENCE_CSV, "content"

    # --- Extension hints (YARA rules are text, PE is not signature-checked) --
    if suffix in {"yar", "yara"}:
        return EVIDENCE_YARA, "extension"
    if suffix in {"pcap", "pcapng", "cap"}:
        return EVIDENCE_PCAP, "extension"
    if suffix in {"json"}:
        return EVIDENCE_JSON, "extension"
    if suffix in {"ndjson", "jsonl"}:
        return EVIDENCE_NDJSON, "extension"
    if suffix in {"csv", "tsv"}:
        return EVIDENCE_CSV, "extension"
    if suffix in {"log", "evtx"}:
        return EVIDENCE_LOG, "extension"
    if suffix in {"exe", "dll", "sys", "bin"} or head.startswith(_PE):
        return EVIDENCE_EXECUTABLE, "extension"
    if suffix in {"txt", "text", "md"}:
        return EVIDENCE_TEXT, "extension"
    if suffix in {"zip", "gz", "tar", "7z", "rar"}:
        return EVIDENCE_ARCHIVE, "extension"

    # --- Fallback: try to decode as text ------------------------------------
    try:
        head.decode("utf-8")
        return EVIDENCE_TEXT, "content"
    except UnicodeDecodeError:
        return EVIDENCE_UNKNOWN, "unknown"


def guess_mime_type(filename: str, data: bytes) -> str:
    """Return a best-effort MIME type."""
    evidence_type, _ = detect_evidence_type(filename, data)
    mapping = {
        EVIDENCE_PCAP: "application/vnd.tcpdump.pcap",
        EVIDENCE_JSON: "application/json",
        EVIDENCE_NDJSON: "application/x-ndjson",
        EVIDENCE_CSV: "text/csv",
        EVIDENCE_LOG: "text/plain",
        EVIDENCE_TEXT: "text/plain",
        EVIDENCE_PDF: "application/pdf",
        EVIDENCE_ARCHIVE: "application/zip",
        EVIDENCE_EXECUTABLE: "application/octet-stream",
        EVIDENCE_SQLITE: "application/vnd.sqlite3",
        EVIDENCE_YARA: "text/plain",
    }
    return mapping.get(evidence_type, "application/octet-stream")