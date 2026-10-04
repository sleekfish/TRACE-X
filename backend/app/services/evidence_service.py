"""Evidence ingestion, integrity verification and retrieval."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adapters.registry import registry
from app.core.config import settings
from app.core.exceptions import NotFoundError, PayloadTooLargeError, ValidationError
from app.models.case import Case
from app.models.enums import AnalysisStatus
from app.models.evidence import Evidence
from app.schemas.evidence import EvidenceUpdate
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService
from app.utils import file_detection
from app.utils.hashing import hash_file
from app.utils.timestamps import utcnow
from app.utils.validation import ensure_within, safe_storage_name, sanitize_filename


class EvidenceService(BaseService):
    """Upload, verify and manage evidence items."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)
        self.storage_root = Path(settings.evidence_storage_path)

    # --- Queries ------------------------------------------------------------
    def get_evidence(self, evidence_id: str) -> Evidence:
        return self.get_or_404(Evidence, evidence_id, "Evidence")

    def resolve_path(self, evidence: Evidence) -> Path:
        """Return the on-disk path, guaranteeing it stays inside storage."""
        path = ensure_within(self.storage_root, evidence.storage_path)
        if not path.is_file():
            raise NotFoundError(
                "Evidence file is no longer present on disk.",
                {"evidence_id": evidence.id, "path": str(path)},
            )
        return path

    def list_evidence(
        self,
        *,
        case_id: Optional[str] = None,
        evidence_type: Optional[str] = None,
        analysis_status: Optional[str] = None,
        include_demo: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[Evidence], int]:
        stmt = select(Evidence).order_by(Evidence.created_at.desc())
        if case_id:
            stmt = stmt.where(Evidence.case_id == case_id)
        if evidence_type:
            stmt = stmt.where(Evidence.evidence_type == evidence_type)
        if analysis_status:
            stmt = stmt.where(Evidence.analysis_status == analysis_status)
        if not include_demo:
            stmt = stmt.where(Evidence.is_demo.is_(False))
        return self.paginate(stmt, limit=limit, offset=offset)

    def supported_tools(self, evidence: Evidence) -> List[str]:
        return [adapter.name for adapter in registry.for_evidence_type(evidence.evidence_type)]

    # --- Ingestion ----------------------------------------------------------
    def create_from_stream(
        self,
        *,
        case_id: str,
        original_filename: str,
        stream: BinaryIO,
        acquisition_source: str = "manual_upload",
        uploaded_by: Optional[str] = None,
        notes: str = "",
        is_demo: bool = False,
        max_bytes: Optional[int] = None,
    ) -> Evidence:
        """Persist an evidence item from a binary stream.

        The file is streamed to disk (never fully buffered in memory), hashed
        while streaming, and its type is detected from actual content - never
        from the extension alone.
        """
        if not self.db.get(Case, case_id):
            raise ValidationError(f"Case '{case_id}' does not exist.", {"case_id": case_id})

        limit = max_bytes or settings.max_upload_size_bytes
        display_name = sanitize_filename(original_filename)
        storage_name = safe_storage_name(original_filename)
        case_dir = self.storage_root / case_id.replace("/", "_").replace("\\", "_")
        case_dir.mkdir(parents=True, exist_ok=True)
        destination = case_dir / storage_name

        sha256 = None
        try:
            with open(destination, "wb") as handle:
                total = 0
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise PayloadTooLargeError(
                            "Uploaded evidence exceeds the maximum allowed size.",
                            {"max_bytes": limit, "received_bytes": total},
                        )
                    handle.write(chunk)
            hashes = hash_file(destination)
            sha256 = hashes["sha256"]

            with open(destination, "rb") as handle:
                head = handle.read(65536)
            evidence_type, detection_method = file_detection.detect_evidence_type(
                display_name, head
            )
            mime_type = file_detection.guess_mime_type(display_name, head)
            file_size = destination.stat().st_size

            # Duplicate detection within the same case (advisory, not blocking).
            duplicate = self.db.execute(
                select(Evidence).where(
                    Evidence.case_id == case_id, Evidence.sha256 == sha256
                )
            ).scalars().first()

            evidence = Evidence(
                case_id=case_id,
                filename=storage_name,
                original_filename=display_name,
                evidence_type=evidence_type,
                detection_method=detection_method,
                mime_type=mime_type,
                file_size=file_size,
                sha256=sha256,
                sha1=hashes["sha1"],
                md5=hashes["md5"],
                storage_path=str(destination),
                acquisition_source=acquisition_source or "manual_upload",
                uploaded_by=uploaded_by,
                analysis_status=AnalysisStatus.PENDING,
                notes=notes or "",
                is_demo=is_demo,
            )
            if duplicate is not None:
                evidence.tool_provenance = {
                    "duplicate_of": duplicate.id,
                    "duplicate_detected_at": utcnow().isoformat(),
                }
            self.db.add(evidence)
            self.db.flush()
            log_activity(
                self.db,
                action=ActivityAction.EVIDENCE_UPLOADED,
                user_id=uploaded_by,
                case_id=case_id,
                entity_type="evidence",
                entity_id=evidence.id,
                description=(
                    f"Evidence '{display_name}' uploaded "
                    f"({evidence.evidence_type}, {file_size} bytes)."
                ),
                metadata={"sha256": sha256, "duplicate_of": (duplicate.id if duplicate else None)},
            )
            self.commit()
        except Exception:
            # Never leave a partial file behind.
            try:
                if destination.exists():
                    destination.unlink()
            except OSError:
                pass
            raise
        return evidence

    def create_from_path(
        self,
        *,
        case_id: str,
        source_path: str,
        original_filename: Optional[str] = None,
        acquisition_source: str = "manual_upload",
        uploaded_by: Optional[str] = None,
        notes: str = "",
        is_demo: bool = False,
    ) -> Evidence:
        """Ingest evidence from an existing file on disk."""
        source = Path(source_path)
        if not source.is_file():
            raise ValidationError(
                "Source evidence file does not exist.", {"source_path": str(source)}
            )
        with open(source, "rb") as handle:
            return self.create_from_stream(
                case_id=case_id,
                original_filename=original_filename or source.name,
                stream=handle,
                acquisition_source=acquisition_source,
                uploaded_by=uploaded_by,
                notes=notes,
                is_demo=is_demo,
            )

    # --- Mutations ----------------------------------------------------------
    def update_evidence(
        self, evidence_id: str, payload: EvidenceUpdate, *, actor_id: Optional[str] = None
    ) -> Evidence:
        evidence = self.get_evidence(evidence_id)
        if payload.notes is not None:
            evidence.notes = payload.notes
        if payload.acquisition_source is not None:
            evidence.acquisition_source = payload.acquisition_source
        if payload.evidence_type is not None:
            evidence.evidence_type = payload.evidence_type
            evidence.detection_method = "manual_override"
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.EVIDENCE_UPDATED,
            user_id=actor_id,
            case_id=evidence.case_id,
            entity_type="evidence",
            entity_id=evidence.id,
            description=f"Evidence '{evidence.original_filename}' updated.",
        )
        self.commit()
        return evidence

    def delete_evidence(self, evidence_id: str, *, actor_id: Optional[str] = None) -> None:
        evidence = self.get_evidence(evidence_id)
        case_id = evidence.case_id
        name = evidence.original_filename
        try:
            path = ensure_within(self.storage_root, evidence.storage_path)
            if path.is_file():
                path.unlink()
        except (OSError, ValidationError):
            pass
        self.db.delete(evidence)
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.EVIDENCE_DELETED,
            user_id=actor_id,
            case_id=case_id,
            entity_type="evidence",
            entity_id=evidence_id,
            description=f"Evidence '{name}' deleted.",
        )
        self.commit()

    def set_analysis_status(
        self, evidence: Evidence, status: str, *, commit: bool = True
    ) -> Evidence:
        evidence.analysis_status = status
        self.db.flush()
        if commit:
            self.commit()
        return evidence

    # --- Integrity ----------------------------------------------------------
    def verify_integrity(self, evidence_id: str, *, actor_id: Optional[str] = None) -> dict:
        """Re-hash the stored file and compare against the recorded hashes."""
        evidence = self.get_evidence(evidence_id)
        path = self.resolve_path(evidence)
        computed = hash_file(path)

        verified = bool(evidence.sha256) and computed["sha256"] == evidence.sha256
        result = {
            "evidence_id": evidence.id,
            "filename": evidence.original_filename,
            "stored_sha256": evidence.sha256,
            "computed_sha256": computed["sha256"],
            "stored_sha1": evidence.sha1,
            "computed_sha1": computed["sha1"],
            "stored_md5": evidence.md5,
            "computed_md5": computed["md5"],
            "verified": verified,
            "verified_at": utcnow(),
        }
        log_activity(
            self.db,
            action=ActivityAction.EVIDENCE_VERIFIED,
            user_id=actor_id,
            case_id=evidence.case_id,
            entity_type="evidence",
            entity_id=evidence.id,
            description=(
                f"Integrity check for '{evidence.original_filename}': "
                f"{'verified' if verified else 'MISMATCH'}."
            ),
            metadata={"verified": verified},
        )
        self.commit()
        return result

    # --- Housekeeping -------------------------------------------------------
    def recompute_hashes(self, evidence_id: str) -> Evidence:
        """Recompute and persist hashes for an evidence item."""
        evidence = self.get_evidence(evidence_id)
        path = self.resolve_path(evidence)
        hashes = hash_file(path)
        evidence.sha256 = hashes["sha256"]
        evidence.sha1 = hashes["sha1"]
        evidence.md5 = hashes["md5"]
        evidence.file_size = path.stat().st_size
        self.commit()
        return evidence

    def storage_usage(self, case_id: Optional[str] = None) -> int:
        stmt = select(func.coalesce(func.sum(Evidence.file_size), 0))
        if case_id:
            stmt = stmt.where(Evidence.case_id == case_id)
        return int(self.db.execute(stmt).scalar() or 0)