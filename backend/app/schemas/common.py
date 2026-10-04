"""Shared schema primitives (base model, datetime handling, pagination)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, computed_field

from app.utils.timestamps import to_iso_z

T = TypeVar("T")

# All timestamps are stored as naive UTC and serialised to ISO-8601 with a "Z".
UTCDateTime = Annotated[
    datetime,
    PlainSerializer(to_iso_z, return_type=Optional[str], when_used="json"),
]

OptionalUTCDateTime = Optional[UTCDateTime]


class ORMModel(BaseModel):
    """Base schema for models read directly from SQLAlchemy objects."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class APIModel(BaseModel):
    """Base schema for request/response payloads."""

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)


class Message(APIModel):
    """Simple acknowledgement payload."""

    message: str
    detail: Dict[str, Any] = Field(default_factory=dict)


class ErrorDetail(APIModel):
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(APIModel):
    error: ErrorDetail


class Page(APIModel, Generic[T]):
    """Standard paginated envelope used by every list endpoint."""

    items: List[T] = Field(default_factory=list)
    total: int = 0
    limit: int = 50
    offset: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total