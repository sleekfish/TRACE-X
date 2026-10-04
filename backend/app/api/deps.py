"""Shared FastAPI dependencies for the TRACE-X MEMORY API.

Authentication is *optional* by default so the platform remains fully usable
without a configured identity provider (single-analyst workstation mode).
When a bearer token is supplied it is validated; when it is absent the request
is treated as an anonymous local session.
"""

from __future__ import annotations

from typing import Optional

import jwt
from fastapi import Depends, Header
from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.db.database import get_db
from app.models.enums import UserRole
from app.models.user import User


def get_session(db: Session = Depends(get_db)) -> Session:
    """Request-scoped database session."""
    return db


def get_optional_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Resolve the caller from a bearer token, or ``None`` for local sessions."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError("Authorization header must be 'Bearer <token>'.")
    try:
        from app.core.security import decode_access_token

        payload = decode_access_token(token.strip())
    except jwt.PyJWTError as exc:  # type: ignore[attr-defined]
        raise AuthenticationError("Invalid or expired access token.") from exc
    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Access token is missing a subject.")
    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationError("The token's user no longer exists.")
    if not user.is_active:
        raise PermissionDeniedError("This account has been deactivated.")
    return user


def get_actor_id(user: Optional[User] = Depends(get_optional_user)) -> Optional[str]:
    """Return the acting user id for audit logging (``None`` when anonymous)."""
    return user.id if user is not None else None


def require_user(user: Optional[User] = Depends(get_optional_user)) -> User:
    """Require an authenticated user (used by user-management endpoints)."""
    if user is None:
        raise AuthenticationError("Authentication is required for this operation.")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """Require an authenticated administrator."""
    if user.role != UserRole.ADMIN:
        raise PermissionDeniedError("Administrator privileges are required.")
    return user