"""Health, readiness and metadata endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.adapters.registry import registry
from app.core.config import settings
from app.db.database import get_db

router = APIRouter(tags=["system"])


@router.get("/health", summary="Liveness probe")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@router.get("/ready", summary="Readiness probe (database + adapters)")
def ready(db: Session = Depends(get_db)) -> Dict[str, Any]:
    database_ok = True
    database_error = ""
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - readiness must never raise
        database_ok = False
        database_error = str(exc)

    infos = registry.integration_infos()
    available = [info.name for info in infos if info.installed]

    return {
        "status": "ready" if database_ok else "degraded",
        "database": {"ok": database_ok, "error": database_error},
        "adapters": {
            "total": len(infos),
            "available": available,
            "real_analysis_available": bool(registry.real_analysis_capable()),
        },
    }


@router.get("/meta", summary="Static platform metadata")
def meta() -> Dict[str, Any]:
    return {
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "environment": settings.environment,
        "api_docs_enabled": settings.api_docs_enabled,
        "kimi_enabled": bool(settings.kimi_api_key),
        "registration_enabled": settings.allow_registration,
        "max_upload_size_bytes": settings.max_upload_size_bytes,
    }