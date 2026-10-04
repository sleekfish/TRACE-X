"""Authentication and user management endpoints."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_optional_user, get_session, require_admin
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    Token,
    UserCreate,
    UserList,
    UserOut,
    UserUpdate,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def _token_response(service: AuthService, user: User) -> Token:
    token = service.issue_token(user)
    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=Token, summary="Authenticate and issue a JWT")
def login(payload: LoginRequest, db: Session = Depends(get_session)) -> Token:
    service = AuthService(db)
    user = service.authenticate(payload.email, payload.password)
    return _token_response(service, user)


@router.get("/me", response_model=UserOut, summary="Current user")
def me(
    user: User = Depends(get_optional_user),
    db: Session = Depends(get_session),
) -> UserOut:
    if user is not None:
        return UserOut.model_validate(user)
    from datetime import datetime

    now = datetime.utcnow()
    return UserOut(
        id="local-session",
        name="Local Analyst",
        email="analyst@tracex.example",
        role="investigator",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@router.get("/users", response_model=UserList)
def list_users(
    limit: int = 50,
    offset: int = 0,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_session),
) -> UserList:
    rows, total = AuthService(db).list_users(limit=limit, offset=offset)
    return UserList(items=[UserOut.model_validate(r) for r in rows], total=total)


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: str,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_session),
) -> UserOut:
    return UserOut.model_validate(AuthService(db).get_by_id(user_id))


@router.post("/register", response_model=Token, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_session)) -> Token:
    service = AuthService(db)
    user = service.register(payload)
    return _token_response(service, user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_session),
) -> UserOut:
    user = AuthService(db).update_user(user_id, payload, actor_id=admin.id)
    return UserOut.model_validate(user)