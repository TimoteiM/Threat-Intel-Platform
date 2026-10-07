"""
Application configuration.

Loads from environment variables / .env file.
All settings are validated at startup — if something is missing, the app won't start.
"""

from __future__ import annotations

import re as _re

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import SecretStr, AliasChoices, Field, ValidationError, model_validator
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


# `<base>/tenants/<tenant_id>` and the same with `/raw`. The tenant segment is
# bounded to the column width so a pathological URL cannot be walked into the
# trusted set, and it may not contain a slash.
_TENANT_INGEST_PATH_RE = _re.compile(r"^(?P<base>.+?)/tenants/[^/]{1,64}(?:/raw)?$")


def matches_trusted_ingest_path(path: str, trusted: "frozenset[str] | set[str]") -> bool:
    """Whether `path` is one of the trusted ingest endpoints.

    A free function rather than only a Settings method because the
    authentication middleware applies the same rule, and the rule must have one
    implementation. Copied into the middleware it would be a second copy to
    keep in step, and the failure mode of drift here is a 401 on the one caller
    that cannot retry.
    """
    candidate = (path or "").rstrip("/") or "/"
    if candidate in trusted:
        return True
    match = _TENANT_INGEST_PATH_RE.match(candidate)
    return bool(match and match.group("base") in trusted)


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
    # Per-million-token rates for models this app calls, as JSON:
    #   {"gpt-5.6-luna": {"input": 1.25, "output": 10.0}}
    # Anthropic models are priced from a built-in table; anything else has to be
    # supplied here, because a guessed rate is worse than an absent one.
    ai_model_prices: str = ""
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
    # How long ANY.RUN runs a submitted *file*, in seconds — the `opt_timeout`
    # it is given, not how long we wait for the answer.
    #
    # This was hardcoded at 60, against an SDK default of 240. Sixty seconds
    # covers booting the VM and opening the sample, and leaves ANY.RUN's
    # automated interactivity almost nothing: an analyst watching the video of
    # a submitted zip saw the archive unpacked and then nothing at all until
    # the recording ended. The run had finished.
    anyrun_file_sandbox_analysis_timeout: int = 240
    # ─── Case lifecycle ───
    # How long a case must go without a new alert before it is answered and
    # closed. Ten minutes covers 90% of within-case alert gaps (p90 = 8.8 min,
    # measured over 7,285 gaps in real cases); the tail past it is what the
    # escalation hold in alert_case_closure_service is for.
    case_quiet_period_minutes: int = 10
    # The resolution target a case is measured against, for SLA reporting.
    case_sla_target_minutes: int = 60
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

    # Hosts whose alerts are excluded from *measurement* only — detection
    # quality, ATT&CK coverage and tuning advice. Comma-separated SQL LIKE
    # patterns, matched case-insensitively.
    #
    # Windows-Test-Device alone is 3,274 of 14,542 runs: 22.6% of the corpus is
    # a lab machine. Rule signal-to-noise computed over it describes the lab,
    # and a tuning recommendation derived from it would be applied to a real
    # estate.
    #
    # Deliberately never applied to alert lists, cases or scoring. A test host
    # that is genuinely compromised is still an incident, and a filter that
    # hides alerts is a filter that hides one of those.
    metrics_excluded_host_patterns: str = "%test-device%,%pftest%,%-teste-%"

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

    # ── Authentication ──
    # "enforce" denies anything without a credential; "monitor" logs the same
    # decision and lets the request through, so a live ingest can be migrated
    # onto an API key before anything starts being rejected.
    auth_mode: str = "enforce"
    # Signs session cookies. Generated per boot when unset, which logs everyone
    # out on restart — acceptable as a default, but set it in .env for real use.
    session_secret: str = ""
    session_ttl_seconds: int = 12 * 60 * 60
    # Only over HTTPS; this deployment is plain HTTP, so it defaults off. A
    # Secure cookie on http:// is simply never sent, which locks out the UI.
    session_cookie_secure: bool = False
    # Printed once on first boot so there is a way in. Leave empty to generate.
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    # Senders that may reach the ingest route without a credential, because they
    # cannot be given one — an appliance whose webhook has no header field.
    # Comma-separated addresses or CIDRs, matched against the real peer address.
    # This is weaker than a key: anything able to occupy or spoof one of these
    # addresses inherits the exemption, so keep it to exact hosts.
    ingest_trusted_cidrs: str = ""
    # The only paths the exemption can reach, and only by POST. Without this the
    # allowance would cover deletes and reads from the same address.
    ingest_trusted_paths: str = "/api/alert-investigations,/api/alert-investigations/raw"

    # —— CAPEv2 sandbox ————————————————————————————————————————————————
    # Off until a base URL and a token are both present, so a deployment that
    # has not stood up the reverse proxy keeps working exactly as before.
    #
    # The token lives here and nowhere else: not in Postgres, not in an API
    # response, not in the frontend bundle, and not in a log line. See
    # app/services/cape_client.py for the redaction that enforces the last one.
    cape_enabled: bool = False
    # The internal HTTPS reverse proxy, including the /apiv2 prefix. CAPE itself
    # binds 127.0.0.1 on its own host, so this is never CAPE's own port.
    # Administrator-controlled configuration only — no request may supply it,
    # which is what keeps this integration from becoming an SSRF gadget.
    cape_api_base_url: str = ""
    cape_api_token: str = ""
    cape_verify_tls: bool = True
    # A custom internal CA, for a proxy whose certificate a public root does not
    # chain to. Path inside the backend container.
    cape_ca_bundle: str = ""
    cape_connect_timeout_seconds: int = 10
    cape_request_timeout_seconds: int = 60
    # Passed to CAPE as the guest execution timeout, not used as an HTTP timeout.
    cape_analysis_timeout_seconds: int = 180
    cape_poll_interval_seconds: int = 10
    cape_max_poll_duration_seconds: int = 900
    # Internet access is activated per analysis on this deployment, so every
    # submission has to ask for it explicitly or the sample runs isolated and
    # its network behaviour — the part an alert is usually about — is missing.
    cape_route: str = "internet"
    cape_reuse_existing_analysis: bool = True
    # The brief said PDFs could not be detonated because no reader was
    # installed, and the panel warned so on every PDF. Task 8 disproves it:
    # the guest ran C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroCEF.exe
    # for 287 seconds and CAPE scored the document 10/10. A warning that says
    # "this was not opened" about a file that was opened is worse than none,
    # so it is off — set true again if the reader is removed from the image.
    cape_pdf_dynamic_unsupported: bool = False
    # Detonate a file the moment an analyst uploads it, rather than waiting for
    # a second click. Uploading a sample to a malware analysis platform is the
    # request; asking again afterwards only adds latency to an analysis that
    # takes minutes anyway.
    #
    # Scoped to uploads on purpose. An alert-spawned investigation has no file
    # to submit — it works from hashes and hostnames extracted from alert text
    # — so this cannot fan out across a ticket. Reuse still applies: a sample
    # CAPE has already analysed is adopted, and no machine is occupied.
    cape_auto_detonate_uploads: bool = True

    # A domain or URL investigation detonates the target automatically, at the
    # same moment the AnyRun sandbox starts, instead of waiting for an analyst
    # to press "Detonate URL in sandbox" afterwards.
    cape_auto_detonate_urls: bool = True
    # How long an investigation waits inline before carrying on without the
    # report. Measured on this instance, a fresh URL detonation takes 271-321s
    # (a 180s enforced analysis timeout plus queueing and report processing), so
    # this budget catches an adopted or already-completed analysis and defers
    # the rest. A deferred report is merged when it lands and the analyst re-run
    # over it — see _annotate_investigation in tasks/cape_task.py.
    cape_inline_wait_seconds: int = 120
    # Fast polling while an investigation is waiting on it. The workflow's own
    # 30s cadence is right for a background poll and too slow for a 120s window.
    # Floor of 5s because CAPE throttles at roughly one request per five.
    cape_inline_poll_seconds: int = 5

    # ── OpenSearch: the log store the alerts come from ───────────────────────
    #
    # Read-only, and read with an admin account, which is why the password is a
    # SecretStr: pydantic renders it as `**********` in a repr, a traceback and
    # a model_dump, so a validation error or a debug log cannot leak it. Reach
    # the value with .get_secret_value(), which only opensearch_client does.
    opensearch_node1: str = ""
    opensearch_node2: str = ""
    opensearch_node3: str = ""
    opensearch_username: str = ""
    opensearch_password: SecretStr = SecretStr("")
    opensearch_enabled: bool = True
    # Verification is on by default and the cluster presents an internal CA, so
    # a bundle has to be supplied the way CAPE's was. See docs/alert-log-context.md.
    opensearch_verify_tls: bool = True
    opensearch_ca_bundle: str = ""
    opensearch_connect_timeout_seconds: int = 5
    opensearch_request_timeout_seconds: int = 20
    # One index per UTC day; a 20-minute window names the one or two it needs
    # rather than fanning out across all 120.
    opensearch_index_pattern: str = "wazuh-alerts-4.x-*"
    # Wazuh writes both. `timestamp` is the alert's own clock and `@timestamp`
    # is Filebeat's; measured on this cluster they differ by about a second.
    # The event clock is the one every other time question here reads.
    opensearch_timestamp_field: str = "timestamp"

    # ── Log context around an alert ──────────────────────────────────────────
    alert_log_context_enabled: bool = True
    alert_log_window_minutes: int = 10
    # A caller can ask for more, but not for an unbounded read: this cluster
    # takes 23 million documents a day, so a 20-minute window on a busy host is
    # six figures of logs and no analyst reads those.
    alert_log_max_hits: int = 500
    alert_log_page_size: int = 100
    # How long a case may spend gathering logs for its members before it stops
    # and reports what it has.
    alert_log_case_max_hits: int = 2000
    # A real-time alert's window ends in the future. The follow-up runs this
    # long after the window closes, late enough that the tail has been indexed.
    alert_log_followup_delay_seconds: int = 120
    alert_log_followup_max_attempts: int = 5
    # How far back a follow-up re-reads before its high-water mark, to catch
    # documents whose event time fell inside the covered slice but which were
    # indexed after it was read. Measured on this cluster over two hours:
    # indexing lag is p50 0.53s, p99 4.2s, p99.9 11.4s, max 15.8s. Five minutes
    # is that maximum nineteen times over, which leaves room for a Filebeat
    # backlog without re-reading the whole window. Overlapping costs nothing
    # but a few duplicate hits, which merge on index:id.
    alert_log_overlap_seconds: int = 300
    # Page a frozen view of the indices rather than a live one. Off only for a
    # cluster that refuses to open a Point in Time.
    opensearch_use_point_in_time: bool = True
    # Re-running the analyst over late logs costs a model call per alert and
    # rewrites the run payload. Off by default: the late logs are attached, the
    # analysis is marked as having been formed without them, and an analyst
    # decides. See docs/alert-log-context.md.
    alert_log_reanalyse_on_complete: bool = False
    # Observed, not configured here: daily indices run 120 days back on this
    # cluster. Used to tell "retry this" from "the logs are gone".
    opensearch_retention_days: int = 120
    # A belt-and-braces pin on the tenant boundary. Verified 2026-09-24: this
    # cluster (C00-Indexer) is written to by exactly one Wazuh manager —
    # wm-c00.siembiot.int accounts for all 2,593,308,014 documents across all
    # 120 alert indices — so the boundary today is that the cluster is
    # dedicated, not that anything filters. That is a deployment property, and
    # deployment properties change without the code noticing. With these set,
    # every query carries the filter, so a second manager appearing on this
    # cluster widens nothing.
    #
    # Leave empty to query unpinned; the status then says so, because "no
    # tenant filter" should be visible rather than assumed.
    opensearch_tenant_field: str = "manager.name"
    opensearch_tenant_values: str = ""

    # ── Alert tenancy ────────────────────────────────────────────────────────
    #
    # The one tenant an existing single-tenant ingest credential may still post
    # to without naming it. Confined to a credential holding exactly this
    # tenant and nothing else; everything else must send tenant_id. Set to ""
    # to end the transition and make tenant_id mandatory for every sender.
    alert_ingest_legacy_tenant: str = "c00"
    # How many tokens of SIEM log context the analyst prompt may carry. 6,000 is
    # the starting point; measured against a real 297-event window the selection
    # saturates at about 3,400, so this has headroom for a busier host.
    alert_log_ai_budget_tokens: int = 6000
    # Whether the ranked log events are sent to the model automatically.
    #
    # Off. The ranking still runs and its picks are marked "relevant" in the log
    # view, but nothing is sent unless an analyst selects it. Measured after a
    # day of sending automatically: input tokens per call went from 5,877 to
    # 6,794, about +15.6% — real, and spent on every alert including the
    # overwhelming majority that are noise. An analyst deciding costs nothing
    # and is better targeted than a ranking.
    #
    # Turning this on restores automatic context for deployments that want it.
    alert_log_ai_autosend: bool = False

    @property
    def opensearch_tenant_value_list(self) -> list[str]:
        return [v.strip() for v in str(self.opensearch_tenant_values or "").split(",") if v.strip()]


    # Report formats to try, in order. The full JSON report is authoritative for
    # malscore, signatures and network indicators; `lite` is the smaller
    # fallback for an instance that only has that one enabled.
    # `json` only. `lite` was in this list on the assumption it was a reduced
    # JSON report; measured against the live instance it is a ZIP archive
    # (16MB, containing dump.pcap), so it can never parse. When the JSON report
    # is too large the fallback is /tasks/get/iocs/, not another report format.
    cape_report_formats: str = "json"
    # A report is analyst evidence, not a stream to ingest unbounded. CAPE
    # reports for a busy sample reach tens of megabytes.
    cape_max_report_bytes: int = 64 * 1024 * 1024
    cape_max_upload_bytes: int = 100 * 1024 * 1024

    # —— Microsoft Entra ID (Azure AD) single sign-on ————————————————————
    # Off until a tenant, client id and secret are all present, so a deployment
    # that has not registered an application keeps working on passwords alone
    # and the sign-in page shows no button that cannot work.
    #
    # Tenant-specific on purpose: the "common" authority would accept a token
    # issued by ANY Microsoft tenant, including one an attacker creates in two
    # minutes, and a domain check alone does not save you — the display name and
    # even an unverified domain can be chosen by whoever owns that tenant. The
    # GUID here is the only thing that pins sign-in to your directory.
    oidc_tenant_id: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # Must match a Redirect URI registered on the app registration, exactly,
    # including scheme, host, port and path. Entra rejects plain http for
    # anything but localhost, so this is an https URL in any real deployment.
    oidc_redirect_url: str = ""
    # A second gate behind the tenant pin: guest accounts invited into your
    # directory authenticate against your tenant but carry their own domain.
    # Empty means any account in the tenant, guests included.
    oidc_allowed_domains: str = ""
    # Create a local record the first time someone signs in. With this off,
    # only people an administrator has already added can use SSO.
    oidc_auto_provision: bool = True
    oidc_default_role: str = "analyst"
    # Comma-separated addresses that get "admin" when provisioned. Existing
    # accounts keep the role they already have — this never demotes anyone.
    oidc_admin_emails: str = ""
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
    # `cape` included so a manual investigation or a file submission consults
    # the on-premises sandbox without the analyst having to remember to tick
    # it. It is a lookup, not a detonation — see app/collectors/cape_collector.
    # The weak-signal cluster and the lexical URL model are reported but do not
    # move the verdict. Both key heavily on URL shape — length, dot count,
    # subdomain depth — and legitimate deep links score MEDIUM on all three, so
    # they were escalating ordinary SharePoint and Office URLs to suspicious on
    # their own. They remain visible as findings, because the observation is
    # still worth an analyst's eye; what they no longer do is decide.
    #
    # Set true to restore the previous behaviour.
    # Whether URL-*shape* signals (length, entropy, depth, dot count, and the
    # lexical model's aggregate score, which they dominate) may move a verdict.
    # Off: they are reported, and only semantic features escalate. See
    # docs/weak-signals.md.
    url_shape_affects_score: bool = False

    default_collectors: str = "dns,http,tls,whois,asn,intel,vt,threat_feeds,brave_osint,urlscan,hybrid_analysis,cape"
    # Collectors that never run on the automatic alert path, however they would
    # otherwise be selected. An alert fans out over many indicators, so a
    # per-request provider that is worth it once for an analyst investigating a
    # domain by hand is not worth it dozens of times a ticket.
    #
    # This is the third mechanism of its kind and the most general: ANY.RUN is
    # held back by external_context["sandbox_suppressed"], and the alert
    # service's own OPT_IN_COLLECTORS covers inline indicator triage. This one
    # covers full investigations *spawned* from an alert, which take the
    # platform defaults and were the gap.
    alert_excluded_collectors: str = "brave_osint"
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

    # —— Correlated cases ———
    # How much a case's score must climb above its last recorded snapshot before
    # that counts as an escalation worth telling someone about. Too low and a
    # case re-notifies on every routine alert it absorbs; too high and a case
    # that walks up steadily never trips at all.
    correlation_escalation_delta: int = 20
    # Cases below this never escalate regardless of how far they climbed — a
    # jump from 5 to 25 is arithmetic, not an incident. This gates a delta:
    # "how bad must a case already be for getting worse to be worth a page".
    correlation_escalation_min_score: int = 50
    # A separate bar, deliberately not the one above: "how bad must a case be on
    # arrival, with no climb at all, to be worth interrupting someone". It
    # answers a different question and will be tuned against different feedback
    # — a single-recompute 96 with no movement over time is a stronger claim
    # than a case watched climbing — so it gets its own lever. Defaulted to the
    # same value so nothing changes today; expect it to drift upward.
    correlation_opened_high_min_score: int = 50
    # Where case.escalated and case.opened_high are POSTed. Empty disables both;
    # the decision logic still runs and records, so turning it on later does not
    # replay a backlog.
    correlation_webhook_url: str = ""

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
    def ingest_trusted_networks(self) -> list:
        """Parsed once. An unparseable entry is dropped with a warning rather
        than widening the allowance by accident."""
        import ipaddress as _ip
        import logging as _logging

        networks: list[Any] = []
        for raw in str(self.ingest_trusted_cidrs or "").split(","):
            entry = raw.strip()
            if not entry:
                continue
            try:
                networks.append(_ip.ip_network(entry, strict=False))
            except ValueError:
                _logging.getLogger(__name__).error(
                    "INGEST_TRUSTED_CIDRS entry %r is not an address or CIDR — ignoring it", entry
                )
        return networks

    @property
    def metrics_excluded_hosts(self) -> tuple[str, ...]:
        return tuple(
            p.strip() for p in str(self.metrics_excluded_host_patterns or "").split(",") if p.strip()
        )

    @property
    def ingest_trusted_path_set(self) -> frozenset[str]:
        return frozenset(
            p.strip() for p in str(self.ingest_trusted_paths or "").split(",") if p.strip()
        )

    def is_trusted_ingest_path(self, path: str) -> bool:
        """Whether a network-admitted sender may post to this path.

        The configured list names the collection endpoints. The tenant-scoped
        forms — `<base>/tenants/<tenant_id>` and `<base>/tenants/<tenant_id>/raw`
        — are the same endpoints with the tenant moved into the URL, because
        NiFi can template a path per flow but cannot carry a header.

        Derived rather than configured. Listing every tenant's path by hand is
        a list someone has to remember to extend, and the failure mode is a 401
        on the one caller that cannot retry — which is how ingest stopped for
        four hours the last time this contract moved.
        """
        return matches_trusted_ingest_path(path, self.ingest_trusted_path_set)

    @property
    def cape_configured(self) -> bool:
        """Enabled, and actually able to talk to something. Not half-on."""
        return bool(
            self.cape_enabled
            and str(self.cape_api_base_url or "").strip()
            and str(self.cape_api_token or "").strip()
        )

    @property
    def cape_base_url(self) -> str:
        """The base, without a trailing slash, so path joins stay predictable."""
        return str(self.cape_api_base_url or "").strip().rstrip("/")

    @property
    def cape_tls_verify(self):
        """What requests/httpx should be given for `verify`.

        A CA bundle path when one is configured, otherwise the boolean. Turning
        verification off is a development affordance only; cape_client warns
        loudly every time it does it, because an unverified TLS connection to a
        malware sandbox is an invitation to feed this platform whatever someone
        on the path would like it to believe.
        """
        bundle = str(self.cape_ca_bundle or "").strip()
        if bundle:
            return bundle
        return bool(self.cape_verify_tls)

    @property
    def cape_report_format_list(self) -> list[str]:
        formats = [f.strip().lower() for f in str(self.cape_report_formats or "").split(",") if f.strip()]
        return formats or ["json"]

    @property
    def oidc_configured(self) -> bool:
        """All four required pieces present. Anything less is not half-on."""
        return all(
            str(getattr(self, name, "") or "").strip()
            for name in ("oidc_tenant_id", "oidc_client_id", "oidc_client_secret", "oidc_redirect_url")
        )

    @property
    def oidc_allowed_domain_list(self) -> list[str]:
        return [d.strip().lower().lstrip("@") for d in str(self.oidc_allowed_domains or "").split(",") if d.strip()]

    @property
    def oidc_admin_email_set(self) -> frozenset[str]:
        return frozenset(
            e.strip().lower() for e in str(self.oidc_admin_emails or "").split(",") if e.strip()
        )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    @property
    def default_collectors_list(self) -> list[str]:
        return [c.strip() for c in self.default_collectors.split(",")]

    @property
    def alert_excluded_collector_set(self) -> frozenset[str]:
        return frozenset(
            c.strip() for c in str(self.alert_excluded_collectors or "").split(",") if c.strip()
        )

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
