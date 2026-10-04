"""External integration / forensic tool endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.schemas.analysis import ToolInfo
from app.schemas.integration import IntegrationCheckResult, IntegrationStatusOut
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=IntegrationStatusOut, summary="Integration status")
def list_integrations(db: Session = Depends(get_session)) -> IntegrationStatusOut:
    service = DashboardService(db)
    integrations = service.integrations()
    available = [info.name for info in integrations if info.installed]
    unavailable = [info.name for info in integrations if not info.installed]
    return IntegrationStatusOut(
        integrations=integrations,
        real_analysis_available=bool(available),
        available_tools=available,
        unavailable_tools=unavailable,
        note=(
            "Tool availability is probed on this host. Adapters whose binary is "
            "not installed never produce synthetic output."
        ),
    )


@router.get(
    "/{name}",
    response_model=ToolInfo,
    summary="Status of a single integration",
)
def get_integration(name: str, db: Session = Depends(get_session)) -> ToolInfo:
    return DashboardService(db).integration(name)


@router.post(
    "/{name}/check",
    response_model=IntegrationCheckResult,
    summary="Re-probe a single integration",
)
def check_integration(name: str, db: Session = Depends(get_session)) -> IntegrationCheckResult:
    info = DashboardService(db).integration(name)
    return IntegrationCheckResult(
        name=info.name,
        status=info.status,
        detail=info.detail,
        version=info.version,
    )