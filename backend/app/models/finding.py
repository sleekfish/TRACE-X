"""Finding model."""

from __future__ import annotations

from sqlalchemy import Boolean, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.models.enums import FindingStatus, Severity
from app.models.mixins import TimestampMixin, new_id


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: new_id("fnd_"))
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.REQUIRES_REVIEW, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    indicator_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    event_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    historical_cases: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding {self.title!r} ({self.status})>"