"""Analysis job model - records every forensic tool execution."""

from __future__ import annotations

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.models.enums import AnalysisSource, AnalysisStatus
from app.models.mixins import TimestampMixin, new_id


class AnalysisJob(Base, TimestampMixin):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: new_id("job_"))
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True
    )
    tool: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default=AnalysisStatus.PENDING, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), default=AnalysisSource.REAL, nullable=False)
    command: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    started_at: Mapped["DateTime | None"] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped["DateTime | None"] = mapped_column(DateTime, nullable=True)
    stdout: Mapped[str] = mapped_column(Text, default="", nullable=False)
    stderr: Mapped[str] = mapped_column(Text, default="", nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tool_version: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    events_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    indicators_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    job_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AnalysisJob {self.tool} {self.status}>"