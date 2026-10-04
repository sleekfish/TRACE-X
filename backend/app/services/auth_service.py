"""Authentication and user-management services."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.security import create_access_token, hash_password, verify_password
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.auth import UserCreate, UserUpdate
from app.services.activity_service import ActivityAction, log_activity
from app.services.base import BaseService


class AuthService(BaseService):
    """User registration, authentication and administration."""

    # --- Lookups ------------------------------------------------------------
    def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email.strip().lower())
        return self.db.execute(stmt).scalars().first()

    def get_by_id(self, user_id: str) -> User:
        return self.get_or_404(User, user_id, "User")

    def list_users(self, *, limit: int = 50, offset: int = 0) -> tuple[List[User], int]:
        stmt = select(User).order_by(User.created_at.desc())
        return self.paginate(stmt, limit=limit, offset=offset)

    # --- Mutations ----------------------------------------------------------
    def create_user(self, payload: UserCreate, *, actor_id: Optional[str] = None) -> User:
        email = payload.email.strip().lower()
        if self.get_by_email(email):
            raise ConflictError(
                f"A user with email '{email}' already exists.",
                {"email": email},
            )
        if payload.role not in UserRole.ALL:
            raise ValidationError(
                f"Invalid role '{payload.role}'.", {"allowed": UserRole.ALL}
            )

        user = User(
            name=payload.name.strip(),
            email=email,
            password_hash=hash_password(payload.password),
            role=payload.role,
            is_active=True,
        )
        self.db.add(user)
        self.db.flush()
        log_activity(
            self.db,
            action=ActivityAction.REGISTER,
            user_id=actor_id or user.id,
            entity_type="user",
            entity_id=user.id,
            description=f"User '{user.email}' created with role '{user.role}'.",
        )
        self.commit()
        return user

    def register(self, payload: UserCreate) -> User:
        if not settings.allow_registration:
            raise PermissionDeniedError("Self-service registration is disabled.")
        # Public registration can never self-assign admin.
        if payload.role == UserRole.ADMIN:
            payload = payload.model_copy(update={"role": UserRole.INVESTIGATOR})
        return self.create_user(payload)

    def authenticate(self, email: str, password: str) -> User:
        user = self.get_by_email(email)
        if user is None or not verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid email or password.")
        if not user.is_active:
            raise PermissionDeniedError("This account has been deactivated.")
        return user

    def issue_token(self, user: User) -> str:
        return create_access_token(user.id, role=user.role)

    def update_user(self, user_id: str, payload: UserUpdate, *, actor_id: Optional[str] = None) -> User:
        user = self.get_by_id(user_id)
        if payload.role is not None:
            if payload.role not in UserRole.ALL:
                raise ValidationError(
                    f"Invalid role '{payload.role}'.", {"allowed": UserRole.ALL}
                )
            user.role = payload.role
        if payload.name is not None:
            user.name = payload.name.strip()
        if payload.is_active is not None:
            user.is_active = payload.is_active
        if payload.password:
            user.password_hash = hash_password(payload.password)
        self.db.flush()
        log_activity(
            self.db,
            action="user.updated",
            user_id=actor_id,
            entity_type="user",
            entity_id=user.id,
            description=f"User '{user.email}' updated.",
        )
        self.commit()
        return user

    def ensure_default_admin(self, email: str, password: str, name: str = "Administrator") -> User:
        """Create the bootstrap admin when no users exist yet."""
        existing = self.db.execute(select(User).limit(1)).scalars().first()
        if existing is not None:
            return existing
        user = User(
            name=name,
            email=email.strip().lower(),
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        self.db.add(user)
        self.db.flush()
        log_activity(
            self.db,
            action="user.bootstrap",
            user_id=user.id,
            entity_type="user",
            entity_id=user.id,
            description="Bootstrap administrator account created.",
        )
        self.commit()
        return user


def get_auth_service(db: Session) -> AuthService:
    return AuthService(db)