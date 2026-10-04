"""Evidence ingestion and integrity endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_actor_id, get_session
from app.schemas.common import Message
from app.schemas.evidence import (
    EvidenceDetail,
    EvidenceIntegrity,
    EvidenceOut,
    EvidencePage,
    EvidenceUpdate,
)
from app.services.evidence_service import EvidenceService
from app.utils.hashing import hash_file
from app.utils.timestamps import utcnow

router = APIRouter(prefix="/evidence", tags=["evidence"])


def _to_detail(service: EvidenceService, evidence) -> EvidenceDetail:
    detail = EvidenceDetail.model_validate(evidence)
    detail.storage_path = evidence.storage_path or ""
    detail.supported_tools = service.supported_tools(evidence)
    return detail


@router.get("", response_model=EvidencePage, summary="List evidence")
def list_evidence(
    case_id: Optional[str] = None,
    evidence_type: Optional[str] = None,
    analysis_status: Optional[str] = None,
    include_demo: bool = True,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> EvidencePage:
    rows, total = EvidenceService(db).list_evidence(
        case_id=case_id,
        evidence_type=evidence_type,
        analysis_status=analysis_status,
        include_demo=include_demo,
        limit=limit,
        offset=offset,
    )
    return EvidencePage(
        items=[EvidenceOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/upload",
    response_model=EvidenceDetail,
    status_code=201,
    summary="Upload evidence",
)
async def upload_evidence(
    file: UploadFile = File(..., description="Evidence file to ingest."),
    case_id: str = Form(..., description="Owning case id."),
    acquisition_source: str = Form(default="manual_upload"),
    notes: str = Form(default=""),
    actor_id: Optional[str] = Depends(get_actor_id),
    db: Session = Depends(get_session),
) -> EvidenceDetail:
    service = EvidenceService(db)
    evidence = service.create_from_stream(
        case_id=case_id,
        original_filename=file.filename or "upload.bin",
        stream=file.file,
        acquisition_source=acquisition_source,
        uploaded_by=actor_id,
        notes=notes,
    )
    return _to_detail(service, evidence)


@router.get("/{evidence_id}", response_model=EvidenceDetail, summary="Get evidence")
def get_evidence(evidence_id: str, db: Session = Depends(get_session)) -> EvidenceDetail:
    service = EvidenceService(db)
    return _to_detail(service, service.get_evidence(evidence_id))


@router.get(
    "/{evidence_id}/integrity",
    response_model=EvidenceIntegrity,
    summary="Re-hash and verify integrity",
)
def verify_integrity(
    evidence_id: str, db: Session = Depends(get_session)
) -> EvidenceIntegrity:
    service = EvidenceService(db)
    evidence = service.get_evidence(evidence_id)
    path = service.resolve_path(evidence)
    hashes = hash_file(path)
    verified = hashes["sha256"] == evidence.sha256
    return EvidenceIntegrity(
        evidence_id=evidence.id,
        filename=evidence.original_filename,
        stored_sha256=evidence.sha256,
        computed_sha256=hashes["sha256"],
        stored_sha1=evidence.sha1,
        computed_sha1=hashes.get("sha1"),
        stored_md5=evidence.md5,
        computed_md5=hashes.get("md5"),
        verified=verified,
        verified_at=utcnow(),
    )


@router.get(
    "/{evidence_id}/download",
    summary="Download the preserved original file",
)
def download_evidence(evidence_id: str, db: Session = Depends(get_session)) -> FileResponse:
    service = EvidenceService(db)
    evidence = service.get_evidence(evidence_id)
    path: Path = service.resolve_path(evidence)
    return FileResponse(
        path=str(path),
        filename=evidence.original_filename,
        media_type=evidence.mime_type or "application/octet-stream",
    )


@router.patch("/{evidence_id}", response_model=EvidenceDetail, summary="Update evidence")
def update_evidence(
    evidence_id: str,
    payload: EvidenceUpdate,
    db: Session = Depends(get_session),
) -> EvidenceDetail:
    service = EvidenceService(db)
    evidence = service.get_evidence(evidence_id)
    if payload.notes is not None:
        evidence.notes = payload.notes
    if payload.acquisition_source is not None:
        evidence.acquisition_source = payload.acquisition_source
    if payload.evidence_type is not None:
        evidence.evidence_type = payload.evidence_type
    service.commit()
    return _to_detail(service, evidence)


@router.delete("/{evidence_id}", response_model=Message, summary="Delete evidence")
def delete_evidence(evidence_id: str, db: Session = Depends(get_session)) -> Message:
    service = EvidenceService(db)
    evidence = service.get_evidence(evidence_id)
    try:
        path = Path(evidence.storage_path)
        if path.is_file():
            path.unlink()
    except OSError:  # pragma: no cover - best effort file removal
        pass
    db.delete(evidence)
    service.commit()
    return Message(message=f"Evidence '{evidence_id}' deleted.")