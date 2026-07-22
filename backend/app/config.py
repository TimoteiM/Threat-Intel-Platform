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
from pydantic import AliasChoices, Field, ValidationError, model_validator
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
    openai_model: str = "gpt-5.6-luna"
    # OpenAI is the primary AI provider; Anthropic is used as fallback.
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-haiku-4-5-20251001"
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    phishtank_api_key: str = ""
    otx_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("OTX_API_KEY", "OTX_Api_Key", "ALIENVAULT_OTX_API_KEY"),
    )
    shodan_api_key: str = ""
    urlscan_api_key: str = ""           # optional — public scans work without key
    brave_search_api_key: str = ""
    brave_search_base_url: str = "https://api.search.brave.com/res/v1/web/search"
    brave_search_count: int = 10
    anyrun_api_key: str = ""
    anyrun_api_key_fallback: str = ""
    opencti_api_key: str = ""
    opencti_api_url: str = ""          # e.g. https://opencti.yourorg.com
    opencti_verify_ssl: bool = True    # set False for self-signed/internal certs
    spamhaus_sia_token: str = ""
    spamhaus_sia_username: str = ""
    spamhaus_sia_password: str = ""
    spamhaus_sia_base_url: str = "https://api.spamhaus.org"
    spamhaus_sia_timeout_seconds: int = 8
    anyrun_sandbox_os: str = "windows"
    anyrun_privacy_type: str = "owner"
    anyrun_timeout_url_domain_seconds: int = 120
    anyrun_timeout_file_hash_seconds: int = 90
    anyrun_url_sandbox_analysis_timeout: int = 120  # opt_timeout sent to AnyRun for URL/domain tasks
    anyrun_url_sandbox_mitm: bool = True            # HTTPS MITM proxy — captures form POSTs on phishing pages
    anyrun_max_upload_mb: int = 100
    anyrun_parallel_limit_retries: int = 8
    anyrun_parallel_backoff_seconds: int = 10
    anyrun_transient_retries: int = 3
    anyrun_transient_backoff_seconds: int = 6
    hybrid_analysis_api_key: str = ""
    hybrid_analysis_base_url: str = "https://hybrid-analysis.com/api/v2"
    hybrid_analysis_environment_id: int = 160
    google_safe_browsing_api_key: str = ""
    url_lexical_model_path: str = ""
    url_lexical_use_lightgbm: bool = False
    api_health_daily_limit_overrides: str = ""
    api_health_monthly_limit_overrides: str = ""

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
    analyst_timeout_seconds: int = 180
    analyst_max_output_tokens: int = 16000
    collector_timeout: int = 20
    urlscan_analysis_timeout_seconds: int = 75
    default_collectors: str = "dns,http,tls,whois,asn,intel,vt,threat_feeds,brave_osint,urlscan,hybrid_analysis"
    intel_crtsh_timeout_seconds: int = 8
    intel_urlhaus_timeout_seconds: int = 6
    intel_cache_ttl_hours: int = 24
    proxy_profiles: str = ""  # e.g. "US=http://user:pass@host:port,IN=http://user:pass@host:port"
    anyrun_proxy_countries: str = ""  # e.g. "BE,US,IN" for AnyRun residential proxy geo choices

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

    @property
    def api_health_daily_limit_overrides_map(self) -> dict[str, float]:
        return _parse_limit_overrides(self.api_health_daily_limit_overrides)

    @property
    def api_health_monthly_limit_overrides_map(self) -> dict[str, float]:
        return _parse_limit_overrides(self.api_health_monthly_limit_overrides)


def _parse_limit_overrides(raw: str) -> dict[str, float]:
    overrides: dict[str, float] = {}
    for part in (raw or "").split(","):
        item = part.strip()
        if not item or ":" not in item:
            continue
        provider, limit = item.split(":", 1)
        provider_key = provider.strip().lower()
        limit_text = limit.strip()
        if not provider_key or not limit_text:
            continue
        try:
            overrides[provider_key] = float(limit_text)
        except ValueError:
            continue
    return overrides


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
