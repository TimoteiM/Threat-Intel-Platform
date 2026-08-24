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
    # Second AbuseIPDB account, used when the first is out of daily checks.
    abuseipdb_api_key2: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ABUSEIPDB_API_KEY2", "ABUSEIPDB_API_KEY_2", "ABUSEIPDB_API_KEY_FALLBACK"
        ),
    )
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
    # Additional accounts, used in order once the one before it is exhausted or
    # rate-limited. They are separate ANY.RUN accounts, so each carries its own
    # quota and its own parallel-task allowance.
    anyrun_api_key_fallback: str = ""
    anyrun_api_key2: str = Field(
        default="",
        validation_alias=AliasChoices("ANYRUN_API_KEY2", "ANYRUN_API_KEY_2", "ANYRUN_API_KEY_FALLBACK2"),
    )
    anyrun_api_key3: str = Field(
        default="",
        validation_alias=AliasChoices("ANYRUN_API_KEY3", "ANYRUN_API_KEY_3", "ANYRUN_API_KEY_FALLBACK3"),
    )
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
    # How many sandbox tasks this plan may run at once. Submissions are queued
    # to this number rather than racing each other into "403 Parallel task limit".
    anyrun_max_parallel_submissions: int = 1
    # How long a sandbox task waits for a free slot before deferring. A slot is
    # held for the whole analysis, so this allows a couple of full runs ahead in
    # the queue while still bounding how long a worker thread can be parked.
    anyrun_submission_queue_wait_seconds: int = 600
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
    # Fetch VT's sandbox behaviour summary for hash/file observables.
    # Costs one extra VT request per hash — disable on tight free-tier quotas.
    vt_fetch_file_behaviour: bool = True
    default_collectors: str = "dns,http,tls,whois,asn,intel,vt,threat_feeds,brave_osint,urlscan,hybrid_analysis"
    intel_crtsh_timeout_seconds: int = 8
    intel_urlhaus_timeout_seconds: int = 6
    intel_cache_ttl_hours: int = 24
    proxy_profiles: str = ""  # e.g. "US=http://user:pass@host:port,IN=http://user:pass@host:port"
    anyrun_proxy_countries: str = ""  # comma-separated codes, or "*" for every active AnyRun residential geo

    # —— Alert-body investigations ———
    # VirusTotal's free tier allows 4 requests/min · 500/day. One alert body can
    # carry dozens of indicators, so VT is spent only where nothing else answers:
    # file hashes. Domains/URLs/IPs are covered by the DNS/WHOIS/ASN/intel/
    # threat-feed/URLScan/OpenCTI chain. Set false to let VT run on every type.
    alert_vt_hash_only: bool = True
    # Let the AI propose ATT&CK techniques the deterministic signals cannot see.
    # Every proposal is whitelist-checked and must quote evidence that exists,
    # so this widens what is found without widening what can be invented.
    alert_attack_ai_enabled: bool = True
    # Add indicators an alert run concluded on to the watchlist, so a verdict
    # that changes later is noticed rather than silently going stale.
    alert_watchlist_autoenrol: bool = True
    alert_watchlist_autoenrol_interval: str = "weekly"
    # Only enrol indicators that concluded at or above this risk score — the
    # point is to re-check what mattered, not to watch the whole internet.
    alert_watchlist_autoenrol_min_risk: int = 40
    # POST alert.updated to the original sender when a re-check changes a verdict.
    alert_reverdict_notify: bool = True
    # Reuse a recent concluded investigation of the same indicator instead of
    # re-running its collectors.
    alert_reuse_prior_investigations: bool = True
    alert_prior_investigation_max_age_days: int = 7
    # Domains and URLs extracted from an alert body get a real investigation —
    # full collector set (VT included) plus the AI analyst — instead of the
    # inline collector run. The alert run waits for them; anything still running
    # at the deadline is reported as "investigating" and fills in when read.
    # —— Alert ingest (another platform POSTing us alert bodies) ———
    # An identical alert body delivered again within this window returns the run
    # it already produced instead of investigating it a second time.
    alert_ingest_dedupe: bool = True
    alert_ingest_dedupe_window_minutes: int = 60
    # Signs the callback body: X-Alert-Signature: sha256=<hmac>. Empty = unsigned.
    alert_callback_secret: str = ""
    alert_callback_timeout_seconds: int = 15
    alert_callback_max_retries: int = 5
    # Callback targets on loopback/link-local are always refused; private ranges
    # are allowed because the receiving platform usually lives on the same LAN.
    alert_callback_allow_private: bool = True

    alert_spawn_investigations: bool = True
    alert_spawn_observable_types: str = "domain,url"
    alert_investigation_wait_seconds: int = 1500  # < the task's 1740s soft limit
    alert_investigation_poll_seconds: int = 5

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
