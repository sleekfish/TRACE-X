"""Audit / activity log model."""

from __future__ import annotations

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.models.mixins import new_id
from app.utils.timestamps import utcnow


class Activity(Base):
    __tablename__ = "activities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: new_id("act_"))
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    case_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    activity_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    timestamp: Mapped["DateTime"] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Activity {self.action} {self.entity_type}:{self.entity_id}>"