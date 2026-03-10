"""
Application configuration.

Loads from environment variables / .env file.
All settings are validated at startup — if something is missing, the app won't start.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_CANDIDATES = [
    _BACKEND_DIR / ".env",           # backend/.env (container /app/.env)
    _BACKEND_DIR.parent / ".env",    # repo root .env for local runs
]
_ENV_FILE_PATH = next((p for p in _ENV_CANDIDATES if p.exists()), None)
_ENV_FILE = str(_ENV_FILE_PATH) if _ENV_FILE_PATH else None

if _ENV_FILE is not None:
    # Explicitly load the selected .env file at import time.
    # override=False means existing OS env vars still take priority.
    load_dotenv(_ENV_FILE, override=False)
    print(f"[config] Loaded .env from: {_ENV_FILE}", flush=True)
else:
    print("[config] No .env file found; using process environment only", flush=True)

# Prefer project-local Playwright browser cache if present (useful on Windows
# when global %LOCALAPPDATA% cache is missing or locked).
_LOCAL_PLAYWRIGHT_DIR = _BACKEND_DIR / ".playwright"
if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ and _LOCAL_PLAYWRIGHT_DIR.exists():
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(_LOCAL_PLAYWRIGHT_DIR)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # silently ignore unknown env vars
    )

    # —— API Keys ———
    openai_api_key: str = ""
    openai_model: str = "gpt-5-mini"
    # Optional Anthropic fallback fields (used only when OpenAI fails/returns empty output)
    anthropic_api_key: str = ""
    anthropic_model: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    phishtank_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""           # optional — public scans work without key
    google_safe_browsing_api_key: str = ""
    url_lexical_model_path: str = ""

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
    analyst_timeout_seconds: int = 75
    collector_timeout: int = 20
    default_collectors: str = "dns,http,tls,whois,asn,intel,vt"
    intel_crtsh_timeout_seconds: int = 8
    intel_urlhaus_timeout_seconds: int = 6
    intel_cache_ttl_hours: int = 24

    @model_validator(mode="after")
    def _validate_ai_provider_keys(self) -> "Settings":
        if not self.openai_api_key and not self.anthropic_api_key:
            raise ValueError(
                "At least one AI provider key must be set: OPENAI_API_KEY or ANTHROPIC_API_KEY."
            )
        return self

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
    try:
        s = Settings()
    except ValidationError as exc:
        candidates = ", ".join(str(p) for p in _ENV_CANDIDATES)
        raise RuntimeError(
            "Configuration validation failed. Ensure required keys are set "
            "(OPENAI_API_KEY or ANTHROPIC_API_KEY). "
            f"Checked .env candidates: {candidates}"
        ) from exc
    print(
        f"[config] Settings loaded — VT key: {'SET' if s.virustotal_api_key else 'EMPTY!'}",
        flush=True,
    )
    return s
