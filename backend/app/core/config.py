"""Centralised application configuration.

All configuration is sourced from environment variables (and an optional
``.env`` file).  Secrets are NEVER hard-coded and NEVER exposed to clients.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ directory (…/backend/app/core/config.py -> parents[2] == backend)
BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_STORAGE_DIR = BACKEND_DIR / "storage"


class Settings(BaseSettings):
    """Runtime settings for the TRACE-X MEMORY backend."""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application --------------------------------------------------------
    app_name: str = "TRACE-X MEMORY"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    api_docs_enabled: bool = True

    # --- Database -----------------------------------------------------------
    # SQLite by default so the backend runs with zero configuration.
    # Set to postgresql+psycopg://user:pass@host:5432/db in production.
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'tracex.db').as_posix()}"

    # --- Authentication -----------------------------------------------------
    jwt_secret: str = "tracex-development-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 720
    allow_registration: bool = True

    # --- CORS ---------------------------------------------------------------
    cors_origins: str = "*"

    # --- Storage ------------------------------------------------------------
    evidence_storage_path: str = str(DEFAULT_STORAGE_DIR / "evidence")
    report_storage_path: str = str(DEFAULT_STORAGE_DIR / "reports")
    temp_storage_path: str = str(DEFAULT_STORAGE_DIR / "temp")
    max_upload_size_bytes: int = 200 * 1024 * 1024  # 200 MB

    # --- Forensic process execution safety ----------------------------------
    tool_timeout_seconds: int = 300
    max_tool_output_bytes: int = 5_000_000

    # --- Forensic tool paths (None => auto-detect on PATH) ------------------
    tshark_path: Optional[str] = None
    zeek_path: Optional[str] = None
    yara_path: Optional[str] = None
    yara_rules_path: Optional[str] = None

    # Maximum number of packets TShark will decode per evidence item.
    # 0 means "no limit" (bounded only by MAX_TOOL_OUTPUT_BYTES).
    tshark_packet_limit: int = 20000

    # --- External integrations (optional) -----------------------------------
    velociraptor_url: Optional[str] = None
    velociraptor_api_key: Optional[str] = None
    siem_url: Optional[str] = None
    siem_api_key: Optional[str] = None
    siem_type: Optional[str] = None

    # --- Kimi K3 (explanation layer only) -----------------------------------
    kimi_api_key: Optional[str] = None
    kimi_base_url: str = "https://api.moonshot.ai/v1"
    kimi_model: str = "kimi-k3"

    # --- Startup behaviour --------------------------------------------------
    auto_create_tables: bool = True
    seed_demo_on_startup: bool = False

    # ------------------------------------------------------------------ utils
    @property
    def cors_origin_list(self) -> List[str]:
        raw = (self.cors_origins or "").strip()
        if not raw or raw == "*":
            return ["*"]
        return [origin.strip() for origin in raw.split(",") if origin.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def ensure_directories(self) -> None:
        """Create the storage directories if they do not yet exist."""
        for path in (
            self.evidence_storage_path,
            self.report_storage_path,
            self.temp_storage_path,
        ):
            Path(path).mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()