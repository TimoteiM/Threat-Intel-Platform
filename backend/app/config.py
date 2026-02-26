"""
Application configuration.

Loads from environment variables / .env file.
All settings are validated at startup — if something is missing, the app won't start.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Always resolve .env relative to this file's directory (backend/).
# Use .resolve() to convert __file__ to an absolute path first —
# when Celery starts workers, __file__ may be relative to CWD,
# causing .parent.parent to resolve against the wrong directory.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = str(_BACKEND_DIR / ".env")

# Explicitly load the .env file into OS environment variables NOW,
# at import time. This ensures all keys are visible regardless of
# the process CWD or how pydantic-settings resolves the env_file path.
# override=False means OS env vars (if set manually) still take priority.
load_dotenv(_ENV_FILE, override=False)
print(f"[config] Loaded .env from: {_ENV_FILE}", flush=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # silently ignore unknown env vars
    )

    # —— API Keys ———
    anthropic_api_key: str
    anthropic_model: str = "claude-sonnet-4-20250514"
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    phishtank_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""           # optional — public scans work without key

    # —— Database ———
    database_url: str = "postgresql+asyncpg://threatintel:threatintel@localhost:5432/threatintel"
    database_sync_url: str = "postgresql://threatintel:threatintel@localhost:5432/threatintel"

    # —— Redis ———
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # —— Storage ———
    artifact_storage: str = "local"  # "local" or "s3"
    artifact_local_path: str = "./artifacts"
    s3_bucket: str = "threat-intel-artifacts"
    s3_endpoint_url: str = "http://localhost:9000"

    # —— App ———
    app_env: str = "development"
    app_debug: bool = True
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    log_level: str = "INFO"

    # —— Investigation Defaults ———
    max_analyst_iterations: int = 1
    collector_timeout: int = 20
    default_collectors: str = "dns,http,tls,whois,asn,intel,vt"
    upload_file_deep_scan_default: bool = False
    collector_retry_attempts: int = 2
    collector_retry_backoff_sec: float = 1.5
    investigation_slow_log_threshold_sec: int = 45
    evidence_schema_version: str = "1.1"
    report_schema_version: str = "1.1"

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
    s = Settings()
    print(
        f"[config] Settings loaded — VT key: {'SET' if s.virustotal_api_key else 'EMPTY!'}",
        flush=True,
    )
    return s
