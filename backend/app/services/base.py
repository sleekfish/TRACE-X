"""Shared service-layer helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Type, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationError

M = TypeVar("M")

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


class BaseService:
    """Base class holding the request-scoped database session."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # --- Helpers ------------------------------------------------------------
    @staticmethod
    def clamp_limit(limit: int, maximum: int = MAX_LIMIT) -> int:
        if limit is None:
            return DEFAULT_LIMIT
        return max(1, min(int(limit), maximum))

    @staticmethod
    def clamp_offset(offset: int) -> int:
        return max(0, int(offset or 0))

    def count(self, stmt: Select) -> int:
        """Count rows for a SELECT statement."""
        subquery = stmt.order_by(None).subquery()
        return int(self.db.execute(select(func.count()).select_from(subquery)).scalar() or 0)

    def paginate(
        self,
        stmt: Select,
        *,
        limit: int,
        offset: int,
        maximum: int = MAX_LIMIT,
    ) -> tuple[List[Any], int]:
        """Execute ``stmt`` with pagination, returning ``(rows, total)``."""
        safe_limit = self.clamp_limit(limit, maximum)
        safe_offset = self.clamp_offset(offset)
        total = self.count(stmt)
        rows = list(self.db.execute(stmt.limit(safe_limit).offset(safe_offset)).scalars().all())
        return rows, total

    def get_or_404(self, model: Type[M], entity_id: str, label: str = "Record") -> M:
        instance = self.db.get(model, entity_id)
        if instance is None:
            raise NotFoundError(f"{label} '{entity_id}' was not found.")
        return instance

    def commit(self) -> None:
        self.db.commit()

    def flush(self) -> None:
        self.db.flush()

    def rollback(self) -> None:
        self.db.rollback()

    # --- Validation ---------------------------------------------------------
    @staticmethod
    def require_one_of(value: Any, allowed: Sequence[str], field: str) -> str:
        """Validate that ``value`` is one of ``allowed``."""
        if value not in allowed:
            raise ValidationError(
                f"Invalid {field} '{value}'.",
                {"allowed": list(allowed)},
            )
        return str(value)

    def apply_updates(self, instance: Any, updates: Dict[str, Any]) -> Any:
        """Apply a non-empty mapping of field updates to an ORM instance."""
        for field, value in updates.items():
            if value is not None:
                setattr(instance, field, value)
        return instance