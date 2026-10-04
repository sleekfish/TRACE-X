"""Authentication and user schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import EmailStr, Field

from app.models.enums import UserRole
from app.schemas.common import APIModel, ORMModel, UTCDateTime


class UserBase(APIModel):
    name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    role: str = UserRole.INVESTIGATOR


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserRegister(UserCreate):
    """Self-service registration payload."""


class UserUpdate(APIModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


class UserOut(ORMModel):
    id: str
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: UTCDateTime
    updated_at: UTCDateTime


class LoginRequest(APIModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class Token(APIModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class TokenPayload(APIModel):
    sub: str
    email: str = ""
    role: str = UserRole.VIEWER
    exp: Optional[int] = None


class UserList(APIModel):
    items: List[UserOut] = Field(default_factory=list)
    total: int = 0