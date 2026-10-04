"""TRACE-X MEMORY FastAPI application entrypoint."""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routers import (activity, ai, analysis, auth, cases, dashboard, events, evidence, findings, graph, health, indicators, integrations, memory, reports, search, timeline)
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.db.database import SessionLocal, init_db
from app.services.auth_service import AuthService
from app.services.seed_service import seed_demo_data
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("tracex")
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_directories()
    if settings.auto_create_tables:
        init_db()
    db = SessionLocal()
    try:
        AuthService(db).ensure_default_admin("admin@tracex.example", "admin123!", "TRACE-X Administrator")
        if settings.seed_demo_on_startup:
            seed_demo_data(db)
    finally:
        db.close()
    log.info("TRACE-X MEMORY ready (%s)", settings.environment)
    yield
app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan, docs_url="/docs" if settings.api_docs_enabled else None, redoc_url="/redoc" if settings.api_docs_enabled else None, openapi_url="/openapi.json" if settings.api_docs_enabled else None)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
register_exception_handlers(app)
for _r in (health, auth, cases, evidence, findings, indicators, events, timeline, graph, search, memory, reports, integrations, analysis, activity, dashboard, ai):
    app.include_router(_r.router, prefix="/api")
@app.get("/")
def root():
    return {"name": settings.app_name, "version": settings.app_version, "docs": "/docs", "api": "/api"}