# Technical Reference — Domain Threat Investigation Platform

This document covers the internal architecture, data flow, component design, and engineering decisions for developers and security engineers extending or operating the platform.

---

## Table of Contents

1. [Stack Overview](#1-stack-overview)
2. [Repository Layout](#2-repository-layout)
3. [Request & Task Lifecycle](#3-request--task-lifecycle)
4. [Evidence Collectors](#4-evidence-collectors)
5. [Signal Engine](#5-signal-engine)
6. [AI Analyst Engine](#6-ai-analyst-engine)
7. [Database Schema](#7-database-schema)
8. [API Endpoints](#8-api-endpoints)
9. [Celery Task Graph](#9-celery-task-graph)
10. [Security Controls](#10-security-controls)
11. [Configuration Reference](#11-configuration-reference)
12. [Adding a New Collector](#12-adding-a-new-collector)
13. [Running Locally Without Docker](#13-running-locally-without-docker)

---

## 1. Stack Overview

| Layer | Technology | Role |
|---|---|---|
| Frontend | Next.js 14 (App Router), React 18, Recharts | UI, SSE consumer, PDF trigger |
| API | FastAPI + Uvicorn | REST + Server-Sent Events |
| Task Queue | Celery 5 + Redis | Parallel collector execution, scheduling |
| AI | Anthropic SDK (Claude Sonnet) | Evidence analysis, classification, reporting |
| Database | PostgreSQL 16 + SQLAlchemy 2 (async) | Persistent storage for all artefacts |
| Migrations | Alembic | Schema versioning |
| Screenshots | Playwright (Chromium) | Visual evidence capture |
| Image Analysis | Pillow | Perceptual hash & histogram comparison |
| PDF Export | WeasyPrint + Jinja2 | Report rendering |
| Artifact Storage | Local filesystem or S3-compatible | Raw collector output, screenshots |

---

## 2. Repository Layout

```
threat-intel/
├── backend/
│   ├── app/
│   │   ├── analyst/              # Claude AI integration
│   │   │   ├── orchestrator.py   # Iterative analysis loop
│   │   │   ├── prompt_builder.py # Builds system + user message arrays
│   │   │   ├── system_prompt.py  # Full LLM operating specification
│   │   │   ├── response_parser.py# Parses JSON block from LLM response
│   │   │   └── attack_mapper.py  # MITRE ATT&CK technique enrichment
│   │   ├── api/                  # FastAPI routers (one file per domain)
│   │   │   ├── router.py         # Aggregates all sub-routers
│   │   │   ├── investigations.py
│   │   │   ├── batches.py
│   │   │   ├── sse.py            # Server-Sent Events stream
│   │   │   ├── export.py         # PDF / Markdown / JSON export
│   │   │   ├── pivots.py         # Infrastructure pivot queries
│   │   │   ├── iocs.py           # IOC retrieval
│   │   │   ├── watchlist.py      # Domain monitoring
│   │   │   ├── ip_lookup.py      # Standalone IP reputation
│   │   │   ├── dashboard.py
│   │   │   ├── enrichment.py
│   │   │   ├── attack.py
│   │   │   ├── artifacts.py
│   │   │   ├── reference_images.py
│   │   │   ├── geo.py
│   │   │   └── whois_history.py
│   │   ├── collectors/           # Evidence gathering modules
│   │   │   ├── base.py           # Abstract BaseCollector
│   │   │   ├── registry.py       # Collector name → class mapping
│   │   │   ├── dns_collector.py
│   │   │   ├── http_collector.py
│   │   │   ├── tls_collector.py
│   │   │   ├── whois_collector.py
│   │   │   ├── asn_collector.py
│   │   │   ├── intel_collector.py
│   │   │   ├── vt_collector.py
│   │   │   ├── threat_feeds_collector.py
│   │   │   ├── email_security.py
│   │   │   ├── domain_similarity.py
│   │   │   ├── visual_comparison.py
│   │   │   ├── subdomain_collector.py
│   │   │   ├── redirect_analysis.py
│   │   │   ├── js_analysis.py
│   │   │   ├── infrastructure_pivot.py
│   │   │   ├── favicon_intel.py
│   │   │   └── signals.py        # Post-collection signal generator
│   │   ├── db/
│   │   │   ├── session.py        # Async + sync engine factories
│   │   │   └── repository.py     # Data access layer
│   │   ├── middleware/
│   │   │   └── rate_limit.py     # Sliding-window rate limiter
│   │   ├── models/
│   │   │   ├── database.py       # SQLAlchemy ORM models
│   │   │   └── schemas.py        # Pydantic v2 schemas (all types)
│   │   ├── services/
│   │   │   ├── investigation_service.py
│   │   │   ├── batch_service.py
│   │   │   ├── export_service.py
│   │   │   └── pivot_service.py
│   │   ├── storage/
│   │   │   └── artifact_store.py # Local / S3 abstraction
│   │   ├── tasks/
│   │   │   ├── celery_app.py     # Celery configuration + Beat schedule
│   │   │   ├── investigation_task.py
│   │   │   ├── collector_task.py
│   │   │   ├── analysis_task.py
│   │   │   ├── batch_task.py
│   │   │   └── watchlist_task.py
│   │   ├── templates/
│   │   │   └── report.html       # Jinja2 PDF report template
│   │   ├── utils/
│   │   │   ├── domain.py         # TLD extraction, domain validation
│   │   │   └── hashing.py        # SHA-256, MurmurHash3 helpers
│   │   ├── config.py             # Pydantic Settings
│   │   ├── dependencies.py       # FastAPI DI (DBSession)
│   │   └── main.py               # App factory
│   ├── alembic/
│   │   └── versions/             # 006 migrations
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── app/                  # Next.js App Router pages
│       ├── components/           # React components
│       │   ├── investigation/    # Form, progress, enrichment
│       │   ├── report/           # 7-tab report viewer
│       │   ├── batch/            # Batch upload & campaign view
│       │   ├── layout/           # Header, navigation
│       │   └── shared/           # Badges, spinners, tabs
│       ├── lib/
│       │   ├── api.ts            # Typed API client
│       │   └── types.ts          # TypeScript interfaces
│       └── styles/
│           └── globals.css       # CSS variables, Leaflet import
├── browser-extension/            # Chrome/Firefox extension
├── docker-compose.yml
├── .env.example
└── Makefile
```

---

## 3. Request & Task Lifecycle

```
POST /api/investigations
          │
          ▼
 InvestigationService.create()
  ├─ Validates domain
  ├─ Creates DB record (state=PENDING)
  └─ Enqueues run_investigation.delay()
          │
          ▼
 [Celery] run_investigation()
  ├─ Sets state=GATHERING
  ├─ Publishes SSE: "gathering_started"
  └─ Launches Celery chord:
      ┌─────────────────────────────────────────┐
      │  run_collector("dns", ...)              │
      │  run_collector("http", ...)             │  ← parallel
      │  run_collector("tls", ...)              │
      │  run_collector("whois", ...)            │
      │  run_collector("asn", ...)              │
      │  run_collector("intel", ...)            │
      │  run_collector("vt", ...)               │
      │  run_collector("threat_feeds", ...)     │
      └─────────────────────────────────────────┘
                        │
                        ▼ chord callback
 [Celery] run_analysis()
  ├─ Aggregates all collector results
  ├─ Runs email_security analysis
  ├─ Runs subdomain enumeration (DNS resolution)
  ├─ Captures screenshots (Playwright, if client_domain set)
  ├─ Computes domain similarity (if client_domain set)
  ├─ Computes visual similarity (Pillow, if screenshots captured)
  ├─ Runs redirect_analysis (multi-UA probing)
  ├─ Runs js_analysis (Playwright sandbox)
  ├─ Runs favicon_intel (Shodan, optional)
  ├─ Runs infrastructure_pivot (HackerTarget reverse IP, NS clustering)
  ├─ Generates signals (35+ investigative clues)
  ├─ Detects data gaps
  ├─ Calls analyst.analyze(evidence) → Claude API
  │   ├─ Iteration 0: Full evidence → Claude → JSON+report
  │   ├─ If state=insufficient_data: collect more, iterate (up to MAX_ANALYST_ITERATIONS)
  │   └─ Iteration N: Final classification
  ├─ Parses response JSON (classification, findings, IOCs, risk_score)
  ├─ Persists report to DB
  ├─ Sets investigation state=CONCLUDED / FAILED
  └─ Publishes SSE: "analysis_complete"
          │
          ▼
 Frontend SSE consumer receives update
  └─ Re-fetches /api/investigations/{id}/report
     └─ Renders 7-tab report view
```

### SSE Progress Events

Events are published via Redis pub/sub to the SSE endpoint (`/api/sse/subscribe/{id}`):

| Event | Trigger |
|---|---|
| `gathering_started` | Chord launched |
| `collector_complete` | Each collector finishes |
| `collector_failed` | Collector timeout / error |
| `analysis_started` | Chord callback begins |
| `analysis_iteration` | Each Claude iteration |
| `analysis_complete` | Report persisted |
| `investigation_failed` | Unrecoverable error |

---

## 4. Evidence Collectors

All collectors extend `BaseCollector` which handles timing, error capture, and artifact storage. Collectors are identified by name (string key in `registry.py`) and instantiated by the Celery task.

### BaseCollector contract

```python
class BaseCollector:
    name: str                         # Registry key
    timeout: int                      # Max seconds (default 30)

    def collect(self) -> dict:        # Public entry point
        # Records started_at, calls _collect(), records completed_at
        ...

    def _collect(self) -> dict:       # Override in subclass
        ...
```

### Collector Details

#### `dns_collector` — DNS Resolution
- **Library:** `dnspython`
- **Resolvers:** 8.8.8.8, 1.1.1.1, 9.9.9.9 (falls back across them)
- **Records:** A, AAAA, CNAME, MX (with priority), NS, TXT, DMARC (`_dmarc.<domain>`), SPF
- **Output schema:** `DNSEvidence`
  ```json
  {
    "a": ["93.184.216.34"],
    "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
    "mx": [{"host": "mail.example.com", "priority": 10}],
    "ns": ["a.iana-servers.net", "b.iana-servers.net"],
    "txt": ["v=spf1 -all"],
    "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "spf": "v=spf1 -all"
  }
  ```

#### `http_collector` — Web Content Analysis
- **Library:** `requests` (30s timeout, 10 redirect limit, custom UA)
- **Attempts:** HTTPS first, HTTP fallback
- **Captures:**
  - Full redirect chain (URL, status_code, server header per hop)
  - Page `<title>`, `<meta>` description
  - Login form presence (detects `<form>` with `type="password"`)
  - Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
  - Server fingerprint (Server header + X-Powered-By)
  - Brand impersonation phrases (12 hardcoded patterns: "verify your account", "account suspended", etc.)
  - Phishing kit indicators (regex: `eval()`, `atob()`, `String.fromCharCode`, Telegram Bot API URL, `document.write`)
  - External resource domains (script/img/link src, up to 20)
  - Favicon hash (MurmurHash3 of fetched `/favicon.ico`)
- **Output schema:** `HTTPEvidence`

#### `tls_collector` — TLS Certificate Analysis
- **Library:** Python `ssl` module + `cryptography`
- **Port:** 443 (SNI-enabled)
- **Captures:**
  - Issuer CN, O, C
  - Subject CN
  - Subject Alternative Names (all SANs)
  - `not_before` / `not_after` in ISO 8601
  - `valid_days_remaining` (integer)
  - SHA-256 fingerprint (hex)
  - Self-signed detection (issuer == subject)
  - Wildcard detection (`*.` prefix in SANs)
  - Certificate chain length
  - Serial number
- **Output schema:** `TLSEvidence`

#### `whois_collector` — Domain Registration Data
- **Library:** `python-whois`
- **Captures:**
  - Registrar name
  - `creation_date`, `expiration_date`, `updated_date` (ISO 8601)
  - `domain_age_days` (computed)
  - `privacy_protected` (bool: "redacted", "proxy", "privacy" keywords in registrant)
  - Registrant org, country, email
  - Name servers list
- **Output schema:** `WHOISEvidence`

#### `asn_collector` — IP Geolocation & Hosting
- **Source:** DNS A record → `ip-api.com/json/{ip}?fields=...`
- **Free, no API key required**
- **Captures:**
  - ASN number and org (`AS15169 Google LLC`)
  - Country, region, city
  - ISP name
  - Reverse DNS hostname
  - CDN detection: Cloudflare, Akamai, Fastly, Amazon CloudFront, Azure CDN flags
  - Cloud/hosting provider detection (AWS, GCP, Azure, DigitalOcean, Hetzner, etc.)
- **Output schema:** `ASNEvidence`

#### `intel_collector` — Threat Intelligence
- **Sources:**
  - `crt.sh` — Certificate Transparency logs (domain + wildcard `*.domain`)
  - DNS blocklists: SURBL, Spamhaus DBL, URIBL (DNS-based lookups)
  - abuse.ch URLhaus (HTTP API)
- **Captures:**
  - Related certificates: serial, domain names, issuer, timestamps (up to 50)
  - Discovered subdomains (from cert SANs, up to 100)
  - Blocklist hits (list of blocklist names with reason)
  - Certificate burst detection (5+ certs in 7-day window)
  - Short-lived certificate detection (<30 days validity)
- **Output schema:** `IntelEvidence`

#### `vt_collector` — VirusTotal (Optional)
- **Requires:** `VIRUSTOTAL_API_KEY`
- **API:** VirusTotal v3 `/domains/{domain}`
- **Captures:**
  - Malicious / suspicious / harmless / undetected vendor counts
  - Per-vendor results (up to 20)
  - Domain categories (Forcepoint, Symantec, etc.)
  - Popularity ranks (Alexa, Majestic, Cisco Umbrella)
  - Last analysis stats date
  - Community reputation score
- **Output schema:** `VirusTotalEvidence`

#### `threat_feeds_collector` — External Threat Feeds (Optional)
- **Requires:** `ABUSEIPDB_API_KEY` (PhishTank key optional for higher rate limits)
- **Sources:**
  - **AbuseIPDB** — resolves domain to IP, queries `/api/v2/check` (90-day window, verbose)
  - **PhishTank** — checks domain URL against known phishing DB
  - **ThreatFox** (abuse.ch) — IOC search via POST API
  - **OpenPhish** — community phishing feed check
- **Graceful degradation:** Missing API key → skips that feed, continues with others
- **Output schema:** `ThreatFeedEvidence`

#### `email_security` — Email Configuration Analysis
- **No API required** — pure DNS + analysis
- **Checks:**
  - DMARC policy parsing (`p=none/quarantine/reject`, `pct`, `aspf`, `adkim`)
  - SPF record parsing (all qualifier: `-all`, `~all`, `+all`, `?all`)
  - DKIM selector probing (10 common selectors: `default`, `google`, `selector1`, `mail`, etc.)
  - MX record blocklist check (SURBL, Spamhaus)
  - Computed `spoofability_score`: `low/medium/high`
  - `email_security_score` (0-100)
- **Output schema:** `EmailSecurityEvidence`

#### `domain_similarity` — Typosquatting Detection (Optional)
- **Requires:** `client_domain` parameter in the investigation request
- **Pure Python, no API**
- **Techniques detected:**
  - **Character omission** — `paypa.com` (missing `l`)
  - **Character insertion** — `paypaall.com` (extra char)
  - **Character transposition** — `paypla.com` (swap)
  - **Character replacement** — `payp4l.com` (digit swap)
  - **TLD swap** — `paypal.net` vs `paypal.com`
  - **Hyphenation** — `pay-pal.com`
  - **Subdomain impersonation** — `paypal.malicious.com`
  - **Combosquatting** — `paypal-secure.com`
- **Homoglyph detection:** Latin/Cyrillic lookalike substitutions (`о`→`o`, `а`→`a`, `rn`→`m`)
- **Levenshtein edit distance** computed
- **Visual similarity score** (0-100) based on character-level comparison
- **Output schema:** `DomainSimilarityEvidence`

#### `visual_comparison` — Screenshot Analysis (Optional)
- **Requires:** `client_domain` or uploaded reference image; Playwright/Chromium in worker
- **Process:**
  1. Captures 1280×800 Chromium screenshot of investigated domain
  2. Captures 1280×800 Chromium screenshot of client domain (or loads uploaded reference)
  3. Computes perceptual hash (aHash + dHash via Pillow)
  4. Computes histogram similarity (Pearson correlation of colour histograms)
  5. Weighted composite: `0.6 × phash_similarity + 0.4 × histogram_similarity`
- **Classifications:**
  - `is_visual_clone`: similarity ≥ 0.80
  - `is_partial_clone`: 0.50 ≤ similarity < 0.80
- **Screenshot artifacts** stored to artifact store (local/S3)
- **Output schema:** `VisualComparisonEvidence`

#### `redirect_analysis` — Multi-UA Redirect Probing
- **Three User-Agents:** Desktop Chrome, Googlebot, Mobile Chrome
- **Detects:**
  - Different final URLs per UA → `cloaking_detected=True`
  - Different HTTP status codes per UA
  - Excessive redirect chains (>5 hops)
  - Protocol downgrade (HTTPS → HTTP)
  - Bot blocking (403 for Googlebot — flagged but not treated as evasion)
  - Intermediate redirect domains (identifies known tracker/redirector domains)
- **Output schema:** `RedirectAnalysisEvidence`
- **Note:** Content hash differences across UAs are intentionally NOT flagged as cloaking

#### `js_analysis` — JavaScript Sandbox
- **Runs in Playwright** (Chromium, full page load with network interception)
- **Captures:**
  - All network requests (total, external count)
  - POST endpoints analysis (URL, parameters, `is_credential_form` detection)
  - Browser fingerprinting API usage (canvas, WebGL, AudioContext, navigator)
  - Tracking pixels (1×1 images, known tracker domains)
  - WebSocket connections
  - Data exfiltration indicators
- **Output schema:** `JSAnalysisEvidence`

#### `infrastructure_pivot` — Related Domain Discovery
- **Sources:**
  - **HackerTarget** reverse IP lookup API (free, no key)
  - Internal DB: NS clustering (domains sharing nameservers)
  - Internal DB: Registrant pivot (same registrar + registrant_org)
- **Captures up to 500 co-hosted domains per IP**
- **Output schema:** `InfrastructurePivotEvidence`

#### `favicon_intel` — Favicon Hash Intelligence
- **Reads** `http.favicon_hash` from HTTP collector output
- **Queries** Shodan API (optional, requires `SHODAN_API_KEY`)
- **Returns** list of hosts sharing the same favicon hash
- **Output schema:** `FaviconIntelEvidence`

---

## 5. Signal Engine

`backend/app/collectors/signals.py` — runs after all collectors finish, before the AI analyst.

Signals are **investigative clues**, not conclusions. Each maps to one or more evidence fields with a severity level. The analyst must validate each signal against technical plausibility before using it in classification.

### Signal Categories & Examples

| Category | Signal ID | Trigger | Severity |
|---|---|---|---|
| `infrastructure_age` | `sig_very_young_domain` | domain age < 7 days | high |
| `infrastructure_age` | `sig_young_domain` | domain age < 30 days | medium |
| `registration` | `sig_whois_privacy` | WHOIS privacy enabled | info |
| `certificate` | `sig_self_signed` | TLS cert is self-signed | medium |
| `certificate` | `sig_cert_expiring` | expires in < 7 days | medium |
| `certificate` | `sig_free_cert` | Let's Encrypt / ZeroSSL | info |
| `certificate` | `sig_many_sans` | >20 SANs in cert | info |
| `content` | `sig_login_form` | password form detected | info |
| `content` | `sig_phishing_indicators` | `eval()`, `atob()`, Telegram API found | high |
| `content` | `sig_brand_impersonation` | "verify your account" phrases | medium |
| `behavior` | `sig_long_redirect` | >3 redirect hops | medium |
| `behavior` | `sig_cross_domain_redirect` | redirects to different domain | medium |
| `security_posture` | `sig_no_hsts` | no HSTS header | low |
| `security_posture` | `sig_no_csp` | no CSP header | low |
| `email_security` | `sig_no_dmarc` | no DMARC record | low |
| `email_security` | `sig_dmarc_none` | DMARC `p=none` (monitor only) | medium |
| `email_security` | `sig_spf_softfail` | SPF `~all` | medium |
| `email_security` | `sig_spf_permissive` | SPF `+all` | high |
| `email_security` | `sig_no_spf` | no SPF record | medium |
| `email_security` | `sig_mx_blocklisted` | MX server on blocklist | high |
| `email_security` | `sig_high_spoofability` | computed spoofability=high | high |
| `similarity` | `sig_typosquatting_detected` | similarity techniques detected | high |
| `similarity` | `sig_homoglyph_detected` | Cyrillic/Latin substitution | high |
| `similarity` | `sig_high_domain_similarity` | similarity score >70 | high |
| `visual` | `sig_visual_clone` | is_visual_clone=True | critical |
| `visual` | `sig_partial_visual_clone` | is_partial_clone=True | high |
| `reputation` | `sig_blocklist_hit` | in SURBL/Spamhaus/URIBL | high |
| `reputation` | `sig_urlhaus_listed` | in URLhaus malware feed | critical |
| `reputation` | `sig_vt_malicious` | VT malicious vendors ≥1 | high |
| `threat_feeds` | `sig_abuseipdb_high` | AbuseIPDB score ≥75 | high |
| `threat_feeds` | `sig_phishtank_match` | verified PhishTank match | critical |
| `threat_feeds` | `sig_threatfox_match` | ThreatFox IOC match | high |
| `infrastructure` | `sig_shared_infrastructure` | many co-hosted domains (pivot) | medium |
| `infrastructure` | `sig_cert_burst` | 5+ certs in 7-day window | medium |

### Data Gaps

Alongside signals, the engine also generates `DataGap` entries — structured notes about what could not be collected and the impact:

```json
{
  "field": "whois.creation_date",
  "reason": "WHOIS lookup failed with timeout",
  "impact": "Cannot determine domain age — a key indicator for infrastructure_age signals"
}
```

---

## 6. AI Analyst Engine

Located in `backend/app/analyst/`.

### Prompt Architecture

Two-layer prompt:

**System prompt** (`system_prompt.py`) defines:
- Role constraints (no hallucination, no gut-feeling classification)
- 5-step methodology (baseline plausibility → anomalies → attacker necessity test → hypothesis comparison → classification)
- Classification thresholds
- Output format contract (JSON block + narrative report)
- Prompt injection guard (operator-supplied fields are data, not instructions)

**User message** (`prompt_builder.py`) injects:
1. Context headers (domain, investigation_id, iteration count)
2. Contextual guidance blocks for each optional analysis type (similarity, visual, email security, redirect, JS) — these set LLM expectations before the raw evidence JSON
3. `<machine_collected_evidence>` — the full serialized `CollectedEvidence` object (`external_context` excluded)
4. `<operator_supplied_context>` — operator text (SOC notes, additional context) in a clearly fenced block with a data-only warning

### Iterative Analysis

The orchestrator (`orchestrator.py`) supports up to `MAX_ANALYST_ITERATIONS` (default 3) rounds:

1. **Iteration 0:** Full evidence → Claude
2. Claude returns `investigation_state: "insufficient_data"` → `data_needed` list populated
3. System collects additional data (e.g., HTTP response from a specific path)
4. **Iteration 1:** Updated evidence → Claude with conversation history preserved
5. Repeat until `investigation_state: "concluded"` or iteration cap reached

### Classification Rules

```
benign      → Domain fully explained by legitimate service operation
suspicious  → Unusual behavior present but attacker NOT required to explain it
malicious   → Behavior REQUIRES attacker-controlled infrastructure to explain
inconclusive→ Evidence insufficient to distinguish explanations
```

The "attacker necessity test" is the critical gate: if a misconfiguration or unusual-but-valid setup explains the evidence, the domain cannot be classified as `malicious`.

### Output

Claude produces:
1. A valid JSON block with classification, confidence, risk_score (0-100), findings (severity + MITRE ATT&CK technique), IOCs, recommended_action, primary_reasoning
2. A human-readable Markdown report (6 sections: Executive Summary, Risk Assessment, Technical Evidence Analysis, Indicators & Pivots, Hypothesis Comparison, Recommended Actions, Appendix)

### Prompt Injection Defense

Operator-supplied text (`soc_ticket_notes`, `additional_context`) is:
- Truncated (1000 chars max each)
- Wrapped in `<operator_supplied_context>` with an explicit data-only header
- Excluded from the `machine_collected_evidence` JSON blob
- Covered by system prompt constraint rule 9 which instructs Claude to never follow instructions embedded in these fields

---

## 7. Database Schema

### Tables

**`investigations`**

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Investigation ID |
| `domain` | VARCHAR(255) | Investigated domain |
| `client_domain` | VARCHAR(255) NULL | Client domain for similarity comparison |
| `state` | VARCHAR(20) | `pending/gathering/analyzing/concluded/failed` |
| `classification` | VARCHAR(20) NULL | `benign/suspicious/malicious/inconclusive` |
| `confidence` | VARCHAR(10) NULL | `low/medium/high` |
| `risk_score` | INTEGER NULL | 0-100 |
| `recommended_action` | VARCHAR(20) NULL | `monitor/investigate/block/hunt` |
| `batch_id` | UUID FK NULL | Parent batch (if bulk) |
| `analyst_iterations` | INTEGER | Number of Claude rounds |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |
| `concluded_at` | TIMESTAMPTZ NULL | |

**`collector_results`** — Raw per-collector output

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `investigation_id` | UUID FK | |
| `collector_name` | VARCHAR(50) | e.g., `"dns"`, `"http"` |
| `status` | VARCHAR(20) | `success/failed/timeout` |
| `evidence_json` | JSONB | Full collector output |
| `started_at` | TIMESTAMPTZ | |
| `completed_at` | TIMESTAMPTZ | |
| `duration_ms` | INTEGER | |
| `error` | TEXT NULL | Error message if failed |

**`evidence`** — Aggregated evidence (post-processing output)

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `investigation_id` | UUID FK | |
| `evidence_json` | JSONB | Full `CollectedEvidence` object |
| `signals` | JSONB | List of `Signal` objects |
| `data_gaps` | JSONB | List of `DataGap` objects |
| `created_at` | TIMESTAMPTZ | |

**`reports`** — Analyst output

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `investigation_id` | UUID FK | |
| `report_json` | JSONB | Parsed JSON from Claude response |
| `narrative` | TEXT | Full Markdown report |
| `iteration` | INTEGER | Which iteration produced this |
| `created_at` | TIMESTAMPTZ | |

**`iocs`** — Extracted indicators

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `investigation_id` | UUID FK | |
| `ioc_type` | VARCHAR(20) | `ip/domain/url/hash/email` |
| `value` | TEXT | Indicator value |
| `context` | TEXT | Relevance description |
| `confidence` | VARCHAR(10) | `low/medium/high` |

**`watchlist`** — Monitored domains

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `domain` | VARCHAR(255) | |
| `status` | VARCHAR(20) | `active/alerting/inactive` |
| `last_checked` | TIMESTAMPTZ NULL | |
| `last_classification` | VARCHAR(20) NULL | |
| `created_at` | TIMESTAMPTZ | |

**`ip_lookups`** — IP reputation history

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | |
| `ip` | VARCHAR(45) | IPv4 or IPv6 |
| `abuse_score` | INTEGER NULL | AbuseIPDB score |
| `isp` | VARCHAR(255) NULL | |
| `country_code` | VARCHAR(10) NULL | |
| `threatfox_count` | INTEGER | ThreatFox IOC matches |
| `result_json` | JSONB | Full response |
| `queried_at` | TIMESTAMPTZ | |

---

## 8. API Endpoints

Base URL: `http://localhost:8000`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/investigations` | Start investigation |
| `GET` | `/api/investigations` | List (`?state=`, `?search=`, `?limit=`, `?offset=`) |
| `GET` | `/api/investigations/{id}` | Investigation metadata |
| `GET` | `/api/investigations/{id}/evidence` | Full evidence JSON |
| `GET` | `/api/investigations/{id}/report` | Analyst report JSON |
| `POST` | `/api/investigations/{id}/enrich` | Add external CTI / re-analyze |
| `GET` | `/api/sse/subscribe/{id}` | SSE progress stream |
| `POST` | `/api/batches` | Upload bulk domain list |
| `GET` | `/api/batches` | List batches |
| `GET` | `/api/batches/{id}` | Batch detail |
| `GET` | `/api/batches/{id}/campaigns` | Campaign clustering |
| `GET` | `/api/dashboard/stats` | Aggregate platform statistics |
| `POST` | `/api/artifacts/{id}` | Download artifact (screenshot, cert, etc.) |
| `POST` | `/api/reference-images/{domain}` | Upload reference screenshot |
| `HEAD` | `/api/reference-images/{domain}` | Check if reference exists |
| `GET` | `/api/investigations/{id}/pivots` | Infrastructure pivot data |
| `GET` | `/api/investigations/{id}/iocs` | IOC list |
| `GET` | `/api/attack/techniques` | MITRE ATT&CK technique library |
| `POST` | `/api/investigations/{id}/export` | Export PDF/Markdown/JSON |
| `POST` | `/api/watchlist` | Add domain to watchlist |
| `GET` | `/api/watchlist` | List watchlist |
| `DELETE` | `/api/watchlist/{id}` | Remove from watchlist |
| `GET` | `/api/whois-history/{domain}` | WHOIS change history |
| `POST` | `/api/tools/ip-lookup` | IP reputation lookup |
| `GET` | `/api/tools/ip-lookup/history` | IP lookup history |
| `GET` | `/api/tools/ip-lookup/history/{id}` | Retrieve past lookup |
| `DELETE` | `/api/tools/ip-lookup/history/{id}` | Delete past lookup |

### Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /api/investigations` | 10 per minute per IP |
| `POST /api/tools/ip-lookup` | 20 per minute per IP |
| `POST /api/batches` | 3 per minute per IP |
| `POST /api/watchlist` | 15 per minute per IP |

Exceeding limits returns HTTP 429 with `Retry-After` header.

---

## 9. Celery Task Graph

```
celery_app.py — broker: redis://redis:6379/0
              — result_backend: redis://redis:6379/1
              — serializer: json
              — concurrency: 4 workers
              — task_time_limit: 600s (hard)
              — task_soft_time_limit: 540s (soft)

Registered tasks:
  app.tasks.investigation_task.run_investigation
  app.tasks.collector_task.run_collector
  app.tasks.analysis_task.run_analysis
  app.tasks.batch_task.run_batch_investigation
  app.tasks.watchlist_task.watchlist_check

Beat schedule:
  watchlist-scheduled-checks → watchlist_check() every hour (crontab minute=0)
```

---

## 10. Security Controls

| Control | Implementation |
|---|---|
| **Security headers** | `SecurityHeadersMiddleware` adds `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` (production only) |
| **CORS** | Explicit origin allowlist (`CORS_ORIGINS` env var), explicit method list, explicit header list |
| **Rate limiting** | Sliding-window in-memory limiter per `{IP}:{method}:{path}` |
| **API docs** | Swagger UI disabled in production (`APP_ENV != development`) |
| **Exception handling** | Global handler returns generic 500 in production (no stack traces) |
| **API keys** | All keys default to `""`, loaded exclusively from `.env`; no hardcoded values in source |
| **Prompt injection** | Operator text excluded from evidence JSON; wrapped in `<operator_supplied_context>` with data-only header; system prompt constraint rule 9 |
| **Input validation** | All API inputs validated by Pydantic v2 models with strict types |
| **IP validation** | `/api/tools/ip-lookup` validates with `ipaddress.ip_address()` before any API call |

---

## 11. Configuration Reference

All configuration is in `backend/app/config.py` as a Pydantic `Settings` class. Values are loaded from environment variables (`.env` file takes priority over class defaults).

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | `""` | Required for AI analysis |
| `ANTHROPIC_MODEL` | `"claude-sonnet-4-20250514"` | Claude model to use |
| `VIRUSTOTAL_API_KEY` | `""` | Optional — skipped if empty |
| `ABUSEIPDB_API_KEY` | `""` | Optional — skipped if empty |
| `PHISHTANK_API_KEY` | `""` | Optional — higher rate limits |
| `SHODAN_API_KEY` | `""` | Optional — favicon intel |
| `DATABASE_URL` | `"postgresql+asyncpg://..."` | Async SQLAlchemy URL |
| `DATABASE_SYNC_URL` | `"postgresql://..."` | Sync URL (Alembic) |
| `REDIS_URL` | `"redis://redis:6379/0"` | Redis connection |
| `CELERY_BROKER_URL` | `"redis://redis:6379/0"` | Celery broker |
| `CELERY_RESULT_BACKEND` | `"redis://redis:6379/1"` | Celery result store |
| `APP_ENV` | `"development"` | `development` or `production` |
| `CORS_ORIGINS` | `"http://localhost:3000"` | Comma-separated |
| `MAX_ANALYST_ITERATIONS` | `3` | Max Claude follow-up rounds |
| `COLLECTOR_TIMEOUT` | `30` | Seconds per collector |
| `DEFAULT_COLLECTORS` | `"dns,http,tls,whois,asn,intel,vt"` | Comma-separated collector list |
| `ARTIFACT_STORAGE` | `"local"` | `local` or `s3` |
| `ARTIFACT_LOCAL_PATH` | `"./artifacts"` | Local artifact directory |
| `LOG_LEVEL` | `"INFO"` | Python logging level |

---

## 12. Adding a New Collector

1. Create `backend/app/collectors/my_collector.py`:

```python
from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta

class MyCollector(BaseCollector):
    name = "my_collector"
    timeout = 30

    def _collect(self) -> dict:
        # self.domain is available
        result = {}
        # ... fetch data ...
        return result
```

2. Register in `backend/app/collectors/registry.py`:

```python
from app.collectors.my_collector import MyCollector

COLLECTOR_REGISTRY = {
    ...
    "my_collector": MyCollector,
}
```

3. Add to `DEFAULT_COLLECTORS` in `.env`:

```
DEFAULT_COLLECTORS=dns,http,tls,whois,asn,intel,vt,my_collector
```

4. Add a Pydantic schema in `backend/app/models/schemas.py` and a field on `CollectedEvidence`.

5. Add signals in `backend/app/collectors/signals.py` if needed.

6. Add TypeScript types in `frontend/src/lib/types.ts`.

---

## 13. Running Locally (Backend + Frontend + Celery)

This section is the practical local runbook for this repository.

Important rule: use one runtime mode at a time.
- Local-only mode: local Postgres/Redis + local API + local Celery + local frontend
- Docker-only mode: everything in docker compose
- Do not mix local API/Celery with docker API/Celery

### 13.1 Prerequisites

- Python 3.12+
- Node.js LTS (includes `npm`)
- PostgreSQL running locally
- Redis/Valkey running locally
- Playwright Chromium installed for screenshot/JS collectors

### 13.2 Backend Setup (Windows PowerShell)

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium

# Prepare env file (if missing)
Copy-Item ..\.env.example .\.env

# Apply DB migrations
python -m alembic upgrade head
```

Required env keys in `backend/.env`:
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default: `gpt-5-mini`)
- `REDIS_URL`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`
- `DATABASE_URL`
- `DATABASE_SYNC_URL`

Optional fallback keys:
- `ANTHROPIC_API_KEY`
- `ANTHROPIC_MODEL`

### 13.3 Start API + Celery Worker (recommended script)

Use the repository helper script from `backend`:

```powershell
.\run_celery_local.ps1 -CleanStart
```

What it does:
- starts FastAPI (`uvicorn`) in background
- starts Celery worker in background
- writes logs in `backend/logs`
- writes PIDs and log paths to `backend/logs/celery-local-last.json`

Optional flags:
- `-ApiPort 8000`
- `-WorkerConcurrency 8`
- `-StartBeat` (also starts Celery Beat)

### 13.4 Frontend Start

From a separate terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend URL:
- `http://localhost:3000`

Backend URL:
- `http://127.0.0.1:8000`

### 13.5 How To See Logs

The run script detaches processes, so output goes to files, not terminal.

Tail latest worker logs:

```powershell
Get-Content .\logs\celery-worker-*.out.log -Tail 100 -Wait
Get-Content .\logs\celery-worker-*.err.log -Tail 100 -Wait
```

Tail latest API logs:

```powershell
Get-Content .\logs\api-*.out.log -Tail 100 -Wait
Get-Content .\logs\api-*.err.log -Tail 100 -Wait
```

Show last started PIDs/log files:

```powershell
Get-Content .\logs\celery-local-last.json | ConvertFrom-Json | Format-List
```

### 13.6 Stop API + Celery

From `backend`:

```powershell
$p = Get-Content .\logs\celery-local-last.json | ConvertFrom-Json
Stop-Process -Id $p.api_pid,$p.worker_pid -Force
if ($p.beat_pid) { Stop-Process -Id $p.beat_pid -Force }
```

### 13.7 Quick Health/Status Checks

API listener:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen
```

Celery ping:

```powershell
.\venv\Scripts\celery.exe -A app.tasks.celery_app inspect ping
```

Backend syntax sanity:

```powershell
python -m py_compile app/config.py app/tasks/analysis_task.py
```

Frontend build sanity:

```powershell
cd ..\frontend
npm run -s build
```

### 13.8 Common Issues

`npm is not recognized`:
- Node.js is not installed or not in PATH.
- Install Node.js LTS and reopen terminal.

`Error: No nodes replied within time constraint`:
- worker may still be starting or Redis is unavailable.
- check `backend/logs/celery-worker-*.err.log`
- confirm Redis is running and `CELERY_BROKER_URL` is correct.

Port 8000 conflict:
- stale `uvicorn` process is already running.
- stop existing API processes, then run `.\run_celery_local.ps1 -CleanStart`.

Screenshot/JS collector browser error on Windows worker:
- reinstall Chromium in backend venv:
```powershell
python -m playwright install chromium
```
