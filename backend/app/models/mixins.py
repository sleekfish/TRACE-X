"""Shared model helpers."""

from __future__ import annotations

import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.utils.timestamps import utcnow


def new_id(prefix: str = "") -> str:
    """Generate a short, readable unique identifier."""
    token = uuid.uuid4().hex[:12]
    return f"{prefix}{token}" if prefix else token


class TimestampMixin:
    """Adds created_at / updated_at columns to a model."""

    created_at: Mapped["DateTime"] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    updated_at: Mapped["DateTime"] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )