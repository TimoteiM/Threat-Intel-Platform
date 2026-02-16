"""
Application configuration.

Loads from environment variables / .env file.
All settings are validated at startup — if something is missing, the app won't start.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ─── API Keys ───
    anthropic_api_key: str
    anthropic_model: str = "claude-sonnet-4-20250514"
    virustotal_api_key: str = ""

    # ─── Database ───
    database_url: str = "postgresql+asyncpg://threatintel:threatintel@localhost:5432/threatintel"
    database_sync_url: str = "postgresql://threatintel:threatintel@localhost:5432/threatintel"

    # ─── Redis ───
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # ─── Storage ───
    artifact_storage: str = "local"  # "local" or "s3"
    artifact_local_path: str = "./artifacts"
    s3_bucket: str = "threat-intel-artifacts"
    s3_endpoint_url: str = "http://localhost:9000"

    # ─── App ───
    app_env: str = "development"
    app_debug: bool = True
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    log_level: str = "INFO"

    # ─── Investigation Defaults ───
    max_analyst_iterations: int = 3
    collector_timeout: int = 30
    default_collectors: str = "dns,http,tls,whois,asn,intel,vt"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    @property
    def default_collectors_list(self) -> list[str]:
        return [c.strip() for c in self.default_collectors.split(",")]

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
