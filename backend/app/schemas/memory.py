"""Persistent forensic memory schemas.

The MEMORY subsystem answers: "have we seen this indicator before, and in
which cases?"  It only ever reports what is actually stored - matches always
carry the case and evidence they came from.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field

from app.schemas.common import APIModel, OptionalUTCDateTime


class MemorySearchRequest(APIModel):
    """Search the persistent forensic memory.

    Provide ``indicators`` explicitly, or ``query`` free text from which
    indicators are extracted automatically.  At least one must be supplied.
    """

    query: Optional[str] = Field(default=None, description="Free text to extract indicators from.")
    indicators: List[str] = Field(default_factory=list, description="Explicit indicator values.")
    indicator_types: List[str] = Field(
        default_factory=list,
        description="Restrict to these indicator types (IP, DOMAIN, HASH, URL, ...).",
    )
    exclude_case_id: Optional[str] = Field(
        default=None, description="Exclude a case (e.g. the case currently open)."
    )
    include_same_case: bool = Field(
        default=False, description="Include matches from exclude_case_id."
    )
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limit: int = Field(default=200, ge=1, le=2000)


class MemoryMatch(APIModel):
    """A stored indicator that matched the search, with full provenance."""

    indicator_id: str
    indicator_type: str
    value: str
    normalized_value: str
    confidence: float
    case_id: str
    case_number: str = ""
    case_title: str = ""
    case_status: str = ""
    evidence_id: Optional[str] = None
    evidence_filename: Optional[str] = None
    source: str = ""
    first_seen: OptionalUTCDateTime = None
    last_seen: OptionalUTCDateTime = None
    is_demo: bool = False
    match_reason: str = ""


class MemoryCaseSummary(APIModel):
    """Aggregate view of a historical case that shares indicators."""

    case_id: str
    case_number: str = ""
    case_title: str = ""
    case_status: str = ""
    shared_indicator_count: int = 0
    shared_indicator_types: List[str] = Field(default_factory=list)
    shared_values: List[str] = Field(default_factory=list)
    max_confidence: float = 0.0
    is_demo: bool = False


class MemorySearchResponse(APIModel):
    searched_values: List[str] = Field(default_factory=list)
    extracted_indicators: List[str] = Field(default_factory=list)
    matches: List[MemoryMatch] = Field(default_factory=list)
    cases: List[MemoryCaseSummary] = Field(default_factory=list)
    total_matches: int = 0
    total_cases: int = 0
    truncated: bool = False
    note: str = ""


class MemoryOverview(APIModel):
    """High-level statistics about what the memory currently holds."""

    total_indicators: int = 0
    unique_normalized_values: int = 0
    indicators_shared_across_cases: int = 0
    total_cases_indexed: int = 0
    top_values: List[MemoryCaseSummary] = Field(default_factory=list)
    note: str = ""