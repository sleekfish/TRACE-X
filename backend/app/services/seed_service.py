"""Idempotent demo-data seeding for TRACE-X MEMORY."""
from __future__ import annotations
from datetime import datetime, timedelta
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models.activity import Activity
from app.models.case import Case
from app.models.enums import AnalysisStatus, CaseStatus, FindingStatus, RelationshipType, Severity
from app.models.event import Event
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.relationship import Relationship
from app.utils.timestamps import utcnow

def _dt(base: datetime, minutes: int) -> datetime:
    return base + timedelta(minutes=minutes)

def seed_demo_data(db: Session, *, force: bool = False) -> dict:
    existing = db.execute(select(func.count()).select_from(Case).where(Case.is_demo.is_(True))).scalar_one()
    if existing and not force:
        return {"seeded": False, "reason": "demo data already present", "cases": existing}
    now = utcnow().replace(microsecond=0)
    cases_spec = [
        ("CASE-001", "Suspicious Network Activity", "Workstation WS-4412 issued repeated DNS and HTTP requests to an unrecognised external host during out-of-hours activity.", CaseStatus.ACTIVE, Severity.HIGH),
        ("CASE-002", "Repeated External Connection", "Endpoint telemetry shows periodic outbound connections to an external address previously observed in an earlier investigation.", CaseStatus.UNDER_REVIEW, Severity.CRITICAL),
        ("CASE-005", "Unusual Outbound Transfer Volume", "NetFlow baseline deviation on the research VLAN. Capture retained and normalised for correlation.", CaseStatus.OPEN, Severity.MEDIUM),
    ]
    cases = {}
    for num, title, desc, status, sev in cases_spec:
        c = Case(case_number=num, title=title, description=desc, status=status, severity=sev, is_demo=True)
        db.add(c)
        cases[num] = c
    db.flush()
    ev_spec = [
        ("EV-001", "CASE-001", "case001-network.pcap", "PCAP", 18_400_000, "9f2a7c41e0b3d58a6c17fe4b92d0a83f5c61e27db9405af8c3d1e6b27a4f9c81d"),
        ("EV-003", "CASE-001", "dns-resolver.log", "LOG", 6_700_000, "b1e47a0c95d23f86be7014ac5f92d837e61a0b45c29f78d3e501ab6c74d29f30"),
        ("EV-006", "CASE-002", "case002-netflow.csv", "CSV", 2_100_000, "4a7c19e2b8f0d635a1c94e70b2d85c3f6e01a92d7b48c05e3f2a91d6c40b8537"),
    ]
    ev = {}
    for eid, cid, fn, etype, size, sha in ev_spec:
        e = Evidence(case_id=cases[cid].id, filename=fn, original_filename=fn, evidence_type=etype, mime_type="application/octet-stream", file_size=size, sha256=sha, storage_path=f"demo/{fn}", acquisition_source="demo", analysis_status=AnalysisStatus.COMPLETED, tool_provenance={"source": "DEMO"}, is_demo=True)
        db.add(e)
        db.flush()
        ev[eid] = e
    ind_spec = [
        ("IND-001", "CASE-001", "EV-001", "IP", "185.239.75.42", -1, 1),
        ("IND-002", "CASE-001", "EV-003", "DOMAIN", "suspicious-domain.com", -2, 4),
        ("IND-006", "CASE-002", "EV-006", "PROCESS", "update-svc.exe", 0, 2),
    ]
    inds = {}
    for iid, cid, eid, itype, val, m0, m1 in ind_spec:
        i = Indicator(case_id=cases[cid].id, evidence_id=ev[eid].id, type=itype, value=val, normalized_value=val.lower(), confidence=0.8, first_seen=_dt(now, m0), last_seen=_dt(now, m1), source="demo", is_demo=True)
        db.add(i)
        db.flush()
        inds[iid] = i
    evt_spec = [
        ("TL-001", "CASE-001", "EV-003", "DNS query", "Network", "DNS query for suspicious-domain.com from 10.42.18.77", -1),
        ("TL-002", "CASE-001", "EV-001", "TCP connection", "Network", "Outbound TCP connection to 185.239.75.42:443 established", 0),
        ("TL-007", "CASE-002", "EV-006", "Repeated connection", "Network", "Periodic outbound connection to 185.239.75.42 observed", 2),
    ]
    evts = {}
    for tid, cid, eid, etype, cat, desc, m in evt_spec:
        e = Event(case_id=cases[cid].id, evidence_id=ev[eid].id, timestamp=_dt(now, m), event_type=etype, source=cat, description=desc, confidence=0.75, event_metadata={"source": "DEMO"}, is_demo=True)
        db.add(e)
        db.flush()
        evts[tid] = e
    fnd_spec = [
        ("F-007", "CASE-001", "Suspicious network indicator observed", Severity.HIGH, FindingStatus.REQUIRES_REVIEW, 0.82),
        ("F-009", "CASE-002", "Recurring external connection", Severity.HIGH, FindingStatus.OPEN, 0.74),
    ]
    fnds = {}
    for fid, cid, title, sev, status, conf in fnd_spec:
        f = Finding(case_id=cases[cid].id, title=title, description=title, severity=sev, status=status, confidence=conf, evidence_ids=[ev["EV-001"].id], indicator_ids=[inds["IND-001"].id], event_ids=[evts["TL-002"].id], historical_cases=[], provenance={"source": "DEMO"}, is_demo=True)
        db.add(f)
        db.flush()
        fnds[fid] = f
    rel_spec = [
        ("indicator", inds["IND-001"].id, "case", cases["CASE-001"].id, RelationshipType.CASE_INDICATOR),
        ("indicator", inds["IND-001"].id, "case", cases["CASE-002"].id, RelationshipType.SHARED_INDICATOR),
        ("indicator", inds["IND-001"].id, "case", cases["CASE-005"].id, RelationshipType.HISTORICAL_CORRELATION),
    ]
    for st, sid, tt, tid, rt in rel_spec:
        db.add(Relationship(source_type=st, source_id=sid, target_type=tt, target_id=tid, relationship_type=rt, confidence=0.8, requires_review=False, is_demo=True))
    db.add(Activity(action="demo.seeded", entity_type="case", entity_id=cases["CASE-001"].id, description="Demo dataset seeded.", timestamp=now))
    db.commit()
    return {"seeded": True, "cases": len(cases), "evidence": len(ev), "indicators": len(inds), "events": len(evts), "findings": len(fnds)}