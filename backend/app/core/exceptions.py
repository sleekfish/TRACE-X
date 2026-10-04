"""Domain exceptions and their HTTP mappings."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# Use numeric codes so we do not depend on Starlette constant names, which were
# renamed (422 UNPROCESSABLE_ENTITY -> UNPROCESSABLE_CONTENT, 413
# REQUEST_ENTITY_TOO_LARGE -> CONTENT_TOO_LARGE).
HTTP_413_PAYLOAD_TOO_LARGE = 413
HTTP_422_UNPROCESSABLE = 422


class TraceXError(Exception):
    """Base class for all TRACE-X domain errors."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "tracex_error"

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(TraceXError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(TraceXError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class ValidationError(TraceXError):
    status_code = HTTP_422_UNPROCESSABLE
    code = "validation_error"


class AuthenticationError(TraceXError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "authentication_error"


class PermissionDeniedError(TraceXError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "permission_denied"


class PayloadTooLargeError(TraceXError):
    status_code = HTTP_413_PAYLOAD_TOO_LARGE
    code = "payload_too_large"


class IntegrationUnavailableError(TraceXError):
    """A forensic tool / external integration is not available."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "integration_unavailable"


def _error_body(
    code: str, message: str, details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def register_exception_handlers(app: FastAPI) -> None:
    """Attach global exception handlers to the FastAPI application."""

    @app.exception_handler(TraceXError)
    async def _tracex_handler(_: Request, exc: TraceXError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=HTTP_422_UNPROCESSABLE,
            content=_error_body(
                "validation_error",
                "Request validation failed.",
                {"errors": exc.errors()},
            ),
        )