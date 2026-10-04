"""Verification script for the Pydantic schema layer."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.schemas import (  # noqa: E402
    CaseOut,
    CasePage,
    EventOut,
    EvidenceOut,
    GraphResponse,
    MemorySearchResponse,
    TimelineEntry,
    UTCDateTime,
)
from app.schemas.common import Page  # noqa: E402


def main() -> int:
    aware = datetime(2024, 3, 1, 10, 30, 0, tzinfo=timezone.utc)
    naive = datetime(2024, 3, 1, 10, 30, 0)

    case = CaseOut(
        id="case_1",
        case_number="TX-2024-001",
        title="Suspected C2 beaconing",
        status="open",
        severity="high",
        description="",
        is_demo=False,
        created_at=aware,
        updated_at=naive,
    )
    payload = json.loads(case.model_dump_json())
    print("CaseOut.created_at      :", payload["created_at"])
    print("CaseOut.updated_at      :", payload["updated_at"])
    assert payload["created_at"].endswith("Z"), "aware datetime must serialise with Z"
    assert payload["updated_at"].endswith("Z"), "naive datetime must serialise with Z"
    assert payload["created_at"] == "2024-03-01T10:30:00Z", payload["created_at"]
    assert payload["updated_at"] == "2024-03-01T10:30:00Z", payload["updated_at"]

    ev = EvidenceOut(
        id="evd_1",
        case_id="case_1",
        filename="abc.pcap",
        original_filename="capture.pcap",
        evidence_type="PCAP",
        detection_method="signature",
        mime_type="application/vnd.tcpdump.pcap",
        file_size=1024,
        sha256="a" * 64,
        acquisition_source="manual_upload",
        analysis_status="PENDING",
        notes="",
        is_demo=False,
        created_at=aware,
        updated_at=aware,
    )
    print("EvidenceOut nullable sha1:", json.loads(ev.model_dump_json()).get("sha1"))

    event = EventOut(
        id="evt_1",
        case_id="case_1",
        timestamp=None,
        event_type="DNS_QUERY",
        source="tshark",
        description="DNS query for evil.example.com",
        raw_reference="frame=12",
        confidence=0.9,
        event_metadata={"dns_query": "evil.example.com"},
        is_demo=False,
        created_at=aware,
    )
    print("EventOut timestamp (None):", json.loads(event.model_dump_json())["timestamp"])

    # Pagination envelope + computed field.
    page = CasePage(items=[case], total=10, limit=5, offset=0)
    dumped = json.loads(page.model_dump_json())
    print("CasePage keys           :", sorted(dumped.keys()))
    assert dumped["has_more"] is True, dumped
    last = CasePage(items=[case], total=1, limit=5, offset=0)
    assert json.loads(last.model_dump_json())["has_more"] is False
    print("Page.has_more computed  : OK")

    # Generic Page works with other item types.
    generic = Page[TimelineEntry](items=[], total=0, limit=50, offset=0)
    print("Page[TimelineEntry]     :", json.loads(generic.model_dump_json()))

    graph = GraphResponse(
        nodes=[{"id": "n1", "label": "1.2.3.4", "node_type": "IP"}],
        edges=[],
        node_count=1,
        edge_count=0,
    )
    print("GraphResponse           :", json.loads(graph.model_dump_json())["node_count"])

    mem = MemorySearchResponse(searched_values=["1.2.3.4"], total_matches=0)
    print("MemorySearchResponse    :", json.loads(mem.model_dump_json())["searched_values"])

    # OpenAPI schema generation must succeed for the whole package.
    from app.schemas import __all__ as schema_names

    print(f"\nExported schemas        : {len(schema_names)}")
    print("Schema verification complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())