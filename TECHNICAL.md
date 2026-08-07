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
| `GET` | `/api/exclusions` | List the exclusion list (`?indicator_type=`, `?search=`, `?active=`) |
| `POST` | `/api/exclusions` | Exclude a domain/IP/URL/hash — reason required |
| `POST` | `/api/exclusions/check` | Which of these indicators are already excluded? |
| `PATCH` | `/api/exclusions/{id}` | Edit reason / expiry / scope / active |
| `DELETE` | `/api/exclusions/{id}` | Remove an exclusion |
| `GET` | `/api/whois-history/{domain}` | WHOIS change history |
| `POST` | `/api/tools/ip-lookup` | IP reputation lookup |
| `GET` | `/api/tools/ip-lookup/history` | IP lookup history |
| `GET` | `/api/tools/ip-lookup/history/{id}` | Retrieve past lookup |
| `DELETE` | `/api/tools/ip-lookup/history/{id}` | Delete past lookup |
| `POST` | `/api/alert-investigations/extract` | Parse an alert body, return extracted indicators (no collectors) |
| `POST` | `/api/alert-investigations` | Investigate every indicator found in a raw alert body — also the ingest endpoint for other platforms (`callback_url`, `external_ref`, `dedupe`). Holds the request and returns the report list; `?wait=false` returns as soon as it is queued |
| `POST` | `/api/alert-investigations/raw` | Same, with the alert as a `text/plain` body and the options as query params |
| `GET` | `/api/alert-investigations` | List alert-body runs (`?search=`, `?verdict=`) |
| `GET` | `/api/alert-investigations/{run_id}/export` | Download the run's JSON report list (`?format=reports\|full\|ndjson`) |
| `GET` | `/api/alert-investigations/{run_id}` | Run status + aggregated indicator reports |
| `POST` | `/api/alert-investigations/{run_id}/cancel` | Cancel a queued/running alert-body run |
| `DELETE` | `/api/alert-investigations/{run_id}` | Delete an alert-body run **and the investigations it spawned** |

### Alert Body Investigations

`POST /api/alert-investigations` accepts raw alert text (SIEM/SOAR alert, ticket
note, forwarded warning), extracts its IOCs — URLs, domains, IPs, hashes; emails
are kept as context and their domain is investigated — and queues one collector
run per indicator. Defanged notation (`hxxp://`, `evil[.]com`, `1[.]2[.]3[.]4`)
is refanged before extraction; private/reserved IPs are reported but not looked
up. Extracted IPs additionally go through the IP Lookup tool
(AbuseIPDB + ThreatFox), and the lookup is saved to IP Lookup history. In
parallel the raw alert goes through the AI Assistant (`alert_analysis` mode,
with its sanitisation), and that analysis leads the exported list.

```jsonc
// Request
{ "alert_body": "…", "context": "optional", "requested_collectors": ["vt", "threat_feeds"],
  "max_indicators": 30, "run_ip_lookup": true, "run_ai": true,
  "reuse_prior_investigations": null }   // null → ALERT_REUSE_PRIOR_INVESTIGATIONS

// GET /api/alert-investigations/{run_id} once status == "completed"
{
  "schema_version": "1.0",
  "status": "completed",
  "summary": { "overall_verdict": "malicious", "highest_risk_score": 95,
               "indicators_total": 3, "ai_analysis": "completed", … },
  "extraction": { "counts": { "url": 1, "ip": 2 }, "total": 3, "investigable_total": 2, … },
  "reports": [                                 // ← reusable list-of-JSON contract
    {
      "schema_version": "1.0",
      "report_type": "ai_assistant",           // always first when run_ai is true
      "status": "completed",
      "assistant_session_id": "…",             // openable in the AI Assistant workspace
      "report_markdown": "## Event Interpretation…",
      "incident_graph": { "nodes": [ … ], "edges": [ … ] },
      "sanitization_summary": { "hosts": 1, "ips": 2 }
    },
    {
      "schema_version": "1.0",
      "report_type": "indicator",
      "indicator": { "value": "45.147.230.131", "type": "ip", "observable_type": "ip", … },
      "status": "completed",                   // completed | failed | skipped
      "verdict": { "classification": "malicious", "risk_score": 93, "confidence": 0.9,
                   "reasons": [ … ], "sources": ["vt", "opencti", "ip_lookup"] },
      "findings": [                            // ← only what was actually found
        { "source": "VirusTotal", "collector": "vt", "type": "reputation", "severity": "high",
          "summary": "8 of 91 engines flag this as malicious",
          "data": { "malicious": 8, "total_engines": 91, "flagged_by": [ … ],
                    "detections": ["Trojan.Win32.Emotet"] } },
        { "source": "OpenCTI", "collector": "opencti", "type": "threat_intel", "severity": "medium",
          "summary": "Known observable (score 60)", "data": { … } }
      ],
      "sources_checked": ["vt", "threat_feeds", "opencti", "asn", "ip_lookup"],
      "collector_runs": [ { "collector": "vt", "status": "completed", "duration_ms": 812 } ],
      "errors": [], "started_at": "…", "completed_at": "…", "duration_ms": 4120
    }
  ],
  "ai_report": { … },            // same object as reports[0]
  "indicator_reports": [ … ]     // same objects as reports[1:]
}
```

**Findings, not evidence dumps.** A source that found nothing contributes no
finding — that it ran at all is recorded in `sources_checked` / `collector_runs`.
Every `data` block is pruned of null/empty values. Finding `type` is one of
`reputation`, `file_profile`, `sandbox_behaviour`, `infrastructure`,
`registration`, `web`, `threat_intel`, `blocklist`, `certificate`; `severity` is
`high | medium | low | info` and findings are ordered most severe first. Pass
`"include_raw_evidence": true` to also get the untouched collector output under
`evidence` / `ip_lookup`.

Hash/file indicators additionally get a `file_profile` finding (names the sample
was submitted under, type, size, Authenticode signature and signers, VT threat
label, non-undetected sandbox verdicts, imphash, PE sections) and a
`sandbox_behaviour` finding (processes, commands, files written, registry keys,
DNS lookups, network traffic, ATT&CK techniques) from VT's behaviour summary.
That behaviour lookup costs one extra VT request per hash and can be turned off
with `VT_FETCH_FILE_BEHAVIOUR=false`.

**Two extraction passes: a library for recall, our rules for precision.**
`app/services/alert_ioc_extraction_service.py` runs its own regexes first, then
folds in [ioc-finder](https://github.com/fhightower/ioc-finder) as a second pass.
The library is a *candidate generator*: it knows patterns (CVEs, scheme-less
URLs, defanging spellings we never wrote a rule for) but nothing about context,
so every value it returns goes through the same validation as our own matches —
public-suffix check, field-name and file-name guards, eTLD+1 collapse, digest-set
grouping, URL-host de-duplication, private-IP classification. Measured on a real
Wazuh document, the library alone returns `data.win`, `decoder.name` and
`alert.category` as domains (all valid TLDs, all field names); after validation
the run has one domain, one context-only IP and one hash. It is called with
`parse_domain_from_url=False` so a URL's host is not investigated twice, and a
missing library degrades to our own pass rather than failing the run.

CVEs are **report-only**: extracted, listed, and marked
`skip_reason="cve_reported_as_context"`, because no collector resolves a CVE
today. Enrichment (NVD/CIRCL, CISA KEV) is a later step if volume justifies it.

The extraction result carries both shapes — the rich indicator list the pipeline
runs on, and a flat `by_type` view for consumers that only want values:

```jsonc
{ "indicators": [ { "type": "domain", "value": "evil-corp.com", "investigable": true,
                    "occurrences": 2, "hostnames": ["mail.evil-corp.com"], … }, … ],
  "by_type": { "ips": [ … ], "domains": [ … ], "urls": [ … ],
               "hashes": { "md5": [ … ], "sha1": [], "sha256": [ … ] },
               "emails": [ … ], "cves": ["CVE-2026-1234"] } }
```

`by_type` lists everything extracted, including values the pipeline reports but
never investigates (private IPs, e-mail addresses, CVEs) — the rich list is where
`investigable` and `skip_reason` say which is which, so nothing disappears
silently.

**Hostnames collapse to their registered domain.** `exprdsh002.int.expertware.net`
is extracted as `expertware.net`, with the FQDNs that folded into it listed under
`hostnames` (`["exprdsh002.int.expertware.net"]`). Reputation, WHOIS and
threat-feed data live at eTLD+1, so ten hosts of one site are one investigation
instead of ten. Multi-part suffixes are handled through the public suffix list
(`app/utils/domain_utils.extract_registered_domain`): `mail.corp.example.co.uk` →
`example.co.uk`. A domain already covered by an extracted URL is not investigated
again as a bare domain.

**Endpoint telemetry is understood, not just scanned for IOCs.** A Sysmon/EDR
event carries one file hash and nothing else to look up — the evidence is the
process story. `app/services/endpoint_event_service.py` parses these events
field-by-field (the only reliable boundary is the next known field name, since
values contain colons, spaces, quotes and backslashes) and scores their
behaviour:

```jsonc
{ "report_type": "endpoint_event",
  "event": { "type": "process_create", "utc_time": "…", "image": "…\\bash.exe",
             "command_line": "…", "parent_image": "…", "host_user": "INT\\user",
             "integrity_level": "Medium", "process_id": "4336",
             "hashes": { "md5": "…", "sha256": "…", "imphash": "…" },
             "fields": { …every parsed field… } },
  "verdict":  { "classification": "suspicious", "risk_score": 50, … },
  "findings": [ { "severity": "medium", "summary": "Forced process termination",
                  "data": { "explanation": "…", "matched": "taskkill //F" } }, … ] }
```

Signals are deterministic and each carries why it matters: encoded PowerShell,
hidden/bypass flags, download cradles, in-memory execution, shadow-copy and
event-log tampering, Defender exclusions, credential-store access, persistence,
forced process termination, recon bursts, lateral-movement tooling, obfuscated
or very long command lines, execution from user-writable or cloud-sync paths,
elevated integrity, and Office-spawning-a-shell parent/child chains. The highest
severity sets the event's risk (high 80 · medium 50 · low 25 · info 5), and
`_merge_event_summary()` folds those verdicts into the run summary — an alert
whose only content is a process deleting shadow copies rolls up as malicious
rather than "nothing found". `summary.events_total` / `events_flagged` count
them, and a body containing only endpoint telemetry is accepted (no more 422 for
"no investigable indicators").

Process artefacts stay context: image paths and process names are reported and
scored, never turned into indicators, because no collector takes a Windows path
and the file hash is already the investigable identity. Sysmon `Hashes:` fields
are read as one file — MD5 + SHA1 + SHA256 of the same binary collapse to a
single indicator (SHA256 preferred, the rest carried as `other_digests`), and
IMPHASH is never investigated as a file hash since no file-reputation source can
resolve one.

**Domains and URLs get a real investigation, not just inline collectors.** A few
collectors are enough to triage an IP or a hash, but a domain deserves the full
pipeline, so the alert-body run does what an analyst would do:

```
domain / url  →  recent concluded investigation exists?  →  reuse its verdict
                 otherwise → create an Investigation, run the standard pipeline
                             (every supported collector incl. VirusTotal + the
                             AI analyst), wait for it, fold the verdict in
ip            →  inline collectors + IP Lookup (AbuseIPDB, ThreatFox)
hash          →  inline collectors (VirusTotal, OpenCTI, threat feeds)
```

Those investigations appear in the investigations list like any other, with
their own report an analyst can open — the indicator report carries
`investigation: { investigation_id, url, state, classification, risk_score,
recommended_action, executive_summary }`, its `findings` are built from the
investigation's evidence plus the analyst's own findings, and `verdict.reasons`
are the report's key evidence lines. `summary.investigation_ids` lists every
investigation an alert run started.

The run waits for all of them, bounded by `ALERT_INVESTIGATION_WAIT_SECONDS`
(default 1500s, under the task's 1740s soft limit). Anything still running at
that point is reported as `"status": "investigating"` with its id, and
`summary.indicators_investigating` counts them; the verdict is folded in
automatically the next time the run is read or exported (`GET /{run_id}` and
`/export` hydrate pending reports and persist the result), so an export taken
later is complete without re-running anything. Note the queue interaction: the
alert task holds one worker slot while it waits, so with the default
`worker_concurrency=8` a burst of simultaneous alert runs can leave the spawned
investigations queued — they still finish, and the reports still hydrate; give
alert-body runs their own queue/worker if that becomes the norm. Set
`"spawn_investigations": false` on the request (or `ALERT_SPAWN_INVESTIGATIONS=false`)
to keep everything on the inline path, or narrow the scope with
`ALERT_SPAWN_OBSERVABLE_TYPES`.

**Prior investigations are checked before collectors run.** Every extracted
indicator is looked up against the `investigations` table
(`app/services/indicator_history_service.py`). A match is reported on the
indicator as `prior_investigation` (investigation id, state, classification,
risk score, `age_days`, `total_investigations`, `reusable`) — the IOC preview in
`POST /api/alert-investigations/extract` carries it too, so the analyst sees what
is already known before starting. When the match is **concluded** and fresh
enough, the run reuses its verdict instead of re-collecting: the report comes
back with `"status": "reused"`, `sources_checked: ["prior_investigation"]` and
empty `collector_runs`, and `summary.indicators_reused` counts them. Set
`"reuse_prior_investigations": false` on the request (or
`ALERT_REUSE_PRIOR_INVESTIGATIONS=false`) to always collect fresh.

**"Fresh enough" depends on the verdict**, because the two directions of drift
are not equally dangerous. A domain that is clean today and weaponised on Friday
is how staged phishing works, so a benign verdict expires quickly; a malicious
one going stale only ever costs an unnecessary look at something already called
bad. Multipliers on `ALERT_PRIOR_INVESTIGATION_MAX_AGE_DAYS` (default 7):

| Verdict | Multiplier | Reused for (default) |
|---|---|---|
| `malicious` | ×4 | 28 days |
| `benign` | ×0.5 | 3.5 days |
| `suspicious` | ×0.5 | 3.5 days |
| `inconclusive` | ×0 | never — it is not a verdict, and the collector that was rate-limited last time may succeed now |

A `low` confidence verdict is quartered again on top (a low-confidence benign
lasts under a day). Each indicator's `prior_investigation` carries the
`reuse_max_age_days` actually applied, so a re-collection of something looked at
yesterday is explainable rather than odd. Raising
`ALERT_PRIOR_INVESTIGATION_MAX_AGE_DAYS` scales all four tiers together.

**The exclusion list is checked before anything else.** Indicators on it
(`/exclusions`, `app/services/exclusion_service.py`) never reach a collector at
all — see below.

### The exclusion list

The corporate estate dominates alert volume — its own domains, its egress ranges,
the hashes of software it deploys on purpose — and each one costs a collector
round trip to conclude what the analyst already knew. The **Exclusion** tab
(`/exclusions`) says so once. A listed indicator is reported `benign` with the
exclusion row as the reason, and no collector, VirusTotal call, spawned
investigation or AI token is spent on it.

Matching is narrow — an entry only ever matches what it says
(`app/services/exclusion_service.py`):

| Type | Matches |
|---|---|
| `domain` | exact, plus subdomains unless `match_subdomains` is off. `expertware.net` covers `mail.expertware.net` but **not** `notexpertware.net` — the suffix match is anchored on the dot |
| `ip` | an address, or every address in a CIDR (`10.0.0.0/8`). Prefixes shorter than /8 (IPv4) or /32 (IPv6) are refused as too broad |
| `url` | exact, after normalising scheme case and the trailing slash |
| `hash` | exact, case-insensitive, MD5/SHA-1/SHA-256 |

An excluded **domain also covers URLs pointing at it**, so whitelisting the
domain covers its links.

Two safety properties are deliberate. `reason` is **mandatory** — an unexplained
whitelist entry is how a real detection gets silenced for a year. And
`expires_at` lets an exclusion added during an incident lapse on its own instead
of depending on somebody remembering to remove it. Every row carries `hit_count`
and `last_hit_at`, so a stale entry earning nothing is visible as one.

Nothing is hidden. The excluded indicator stays in the extraction and gets a full
report with `"status": "excluded"`, `sources_checked: ["exclusion"]`, and the
entry (with who added it and why) attached — a wrong verdict leads straight back
to the row that caused it. `summary.indicators_excluded` counts them separately
from `indicators_investigated`, and `extraction.excluded_total` appears on the
run and in the ingest response as `excluded_count`.

The list is applied twice: in the API before the run is created (so the work is
never queued) and again in the worker (which re-extracts from the stored body,
and may see a list that grew while the alert waited). Hit counts are recorded
from the worker pass. If an alert's indicators are *all* excluded, the run still
happens and reports them — but the AI analysis is skipped too, since there would
be nothing for it to read.

**VirusTotal is spent on hashes only.** The free tier allows 4 requests/min ·
500/day, and one alert body can carry dozens of indicators. VT therefore runs for
`hash`/`file` indicators, where no other source gives a multi-engine verdict;
domains, URLs and IPs are answered by the DNS/WHOIS/ASN/intel/threat-feeds/
URLScan/OpenCTI chain and by IP Lookup. Requesting `vt` for a domain is silently
dropped from that indicator's collector list. Set `ALERT_VT_HASH_ONLY=false` to
let VT run on every observable type again. (This applies to alert-body runs;
single-observable investigations still use VT for every type.)

### Receiving alerts from another platform

`POST /api/alert-investigations` is the ingest endpoint: any platform can POST a
raw alert body and get the finished report list back.

**The request is held until the investigation finishes.** The response body is
then the report list itself — byte-for-byte what `/export?format=report` returns —
so a sender gets a finished report from a single call, with no queueing, polling
or webhook to wire up:

```jsonc
// Request — alert_body is the only required field
{ "alert_body": "…raw SIEM/SOAR alert text…",
  "title": "optional", "context": "optional ticket note",
  "external_ref": "INC-8842",                       // your id, echoed everywhere
  "callback_url": "http://soc.internal:8080/hooks/alert",   // optional
  "run_ai": true, "max_indicators": 30, "dedupe": true }

// Response — 200, the report list
[ { "report_type": "executive_summary", … },
  { "report_type": "indicator", "indicator": { "value": "evil-corp.net", … }, … } ]
```

`wait_timeout` (default 300s, max 900) bounds how long the connection is held.
On timeout the run keeps going and the caller gets `202` with the queued
response below — the same shape `wait=false` returns immediately. The UI posts
`?wait=false` because it navigates to the run page and polls it there.

```jsonc
// Response with ?wait=false (or 202 after wait_timeout)
{ "run_id": "6fc927a3-…", "status": "queued", "deduplicated": false,
  "external_ref": "INC-8842",
  "indicators": [ … what was extracted, with prior-investigation matches … ],
  "indicator_count": 2, "investigable_count": 1,
  "links": { "run":    "/api/alert-investigations/6fc927a3-…",
             "report": "/api/alert-investigations/6fc927a3-…/export?format=report",
             "reports":"…?format=reports", "full": "…?format=full",
             "cancel": "…/cancel", "ui": "/alert-investigations/6fc927a3-…" },
  "callback": { "url": "http://soc.internal:8080/hooks/alert", "status": "pending" } }
```

A sender that stores `links.report` needs to know nothing else about the API.
Waiting is what a report generator wants; `wait=false` is for a caller that will
come back for the result — a UI, or a queue-and-forget integration with a
`callback_url`.

**Raw text ingest.** `POST /api/alert-investigations/raw` takes the alert *as the
request body* — no JSON wrapper, no escaping. A Sysmon line or a Windows command
line is full of `"` and `\`, and hand-escaping it into a JSON string is where
integrations (and Postman sessions) actually break. Everything the JSON form
takes as a field is a query parameter here:

```bash
curl -X POST "$API/api/alert-investigations/raw?title=Sysmon%20EID1&external_ref=INC-777&run_ai=true" \
     -H "Content-Type: text/plain" --data-binary @event.txt
```

`?collectors=dns,vt` sets `requested_collectors`; `title`, `context`,
`external_ref`, `callback_url`, `dedupe`, `run_ai`, `run_ip_lookup`,
`spawn_investigations`, `reuse_prior_investigations`, `include_raw_evidence` and
`max_indicators` all work the same as in the JSON body — including `wait` and
`wait_timeout`, so this route also holds the request and answers with the report
list by default. The body is decoded as UTF-8 with replacement, so a log
forwarder's mangled byte costs a character rather than the whole alert.

**Webhook delivery.** When `callback_url` is set, the finished run is POSTed to it
by `tasks.deliver_alert_callback`:

```
POST <callback_url>
X-Alert-Event: alert.completed | alert.failed
X-Alert-Run-Id: <run id>
X-Alert-Signature: sha256=<hmac>        ← only when ALERT_CALLBACK_SECRET is set

{ "event", "run_id", "external_ref", "status", "overall_verdict",
  "highest_risk_score", "delivered_at", "document_count",
  "documents": [ …the format=report list… ] }
```

Delivery retries with exponential backoff (`ALERT_CALLBACK_MAX_RETRIES`, default
5); 4xx from the receiver is treated as final since retrying changes nothing. The
outcome is recorded on the run under `result_json.callback`
(`status`, `attempts`, `http_status`, `error`), so a failed delivery is visible
without reading logs. Polling stays available regardless — the webhook is an
addition, not a replacement.

**Duplicate deliveries.** No alert is investigated twice. Two keys are matched, in
this order:

| Key | Stored as | Window |
|---|---|---|
| The sender's alert id — `external_ref`, taken from `_id`/`id`/`alert_id`/`event.id` | `external_ref` column | none: an id identifies the alert itself, at any age |
| SHA-256 of the whitespace-normalised alert body | `alert_body_hash` column | `ALERT_INGEST_DEDUPE_WINDOW_MINUTES` (default 60) |

The id is checked first because it survives what the hash does not: the same
Wazuh document re-delivered with a new `@timestamp`, extra enrichment fields or
different line wrapping hashes differently but is still the same alert. The body
hash then catches senders that pass no id at all.

**A duplicate gets the report the first delivery produced.** Under the default
`wait=true` the response body is the same report list a first delivery returns —
a re-send costs nothing and still answers with a report, so the sender needs no
special case. Usually the matched run is already finished and the report comes
back at once; if the first delivery is still being investigated, the second waits
for the same answer rather than starting a second copy of the work.

That it *was* a duplicate is reported without changing the shape of the list: on
the executive summary as `ingest`, and in the response headers.

```jsonc
// Response headers on every synchronous ingest
X-Alert-Run-Id: b12a43d2-…
X-Alert-Deduplicated: true          // "false" on a first delivery
X-Alert-Deduplicated-By: external_ref

// documents[0] — the executive summary — carries the same fact in the body
{ "report_type": "executive_summary", "overall_verdict": "malicious", …,
  "ingest": {
    "deduplicated": true, "deduplicated_by": "external_ref",
    "run_id": "b12a43d2-…", "external_ref": "N6oRTp0BfK3wjRjJ8ksL",
    "message": "Duplicate delivery — alert id N6oRTp0BfK3wjRjJ8ksL was already
                investigated as run b12a43d2-…. Nothing was re-investigated;
                this is that run's report." } }
```

With `?wait=false` the queued-shaped response comes back instead, carrying
`deduplicated`, `deduplicated_by`, `message` and `links` — that is what the UI
uses, since it navigates to the run page.

Either way no collector, VirusTotal quota or AI token is spent a second time, so
at-least-once delivery and sender retries are free. Send `"dedupe": false` to
force a fresh run. Runs that ended `failed` or `cancelled` are never reused, so a
re-delivery retries them.

**Security posture.** The endpoint is **not authenticated** — deployments are
expected to restrict it at the network layer (firewall/VPN/reverse proxy). Two
consequences are handled in code: the route is rate-limited to 20 requests per
minute per IP (`app/middleware/rate_limit.py`), and `callback_url` is validated
before anything is queued — http/https only, and loopback, link-local (including
`169.254.169.254`), multicast and reserved addresses are refused so an
unauthenticated caller cannot use the service as a request proxy. Private ranges
stay allowed because the receiving platform is usually on the same LAN; set
`ALERT_CALLBACK_ALLOW_PRIVATE=false` to refuse those too. A host that does not
resolve is rejected at ingest with 400 rather than accepted and retried.

**Exporting the report list.** `GET /api/alert-investigations/{run_id}/export`
serves the run as a list of self-describing JSON documents, so a reporting
platform pulls a finished alert with one request. Both list formats have the
same shape — an array whose every element carries its own `report_type` — they
differ only in depth:

```jsonc
// format=reports (default) — the lean integration contract
[
  { "report_type": "ai_assistant", "report_markdown": "…", "incident_graph": { … } },
  { "report_type": "indicator", "indicator": { "value": "evil-corp.net", … },
    "verdict": { … }, "findings": [ … ], "investigation": { "investigation_id": "…", "url": "…" } },
  { "report_type": "indicator", … }
]

// format=report — report-ready: what another platform needs to rebuild our SOC report
[
  { "report_type": "executive_summary", … },   // as below

  { "report_type": "indicator",
    "indicator": { "value": "myspotifypremium.info", … }, "status": "completed",
    "verdict": { "classification": "malicious", "risk_score": 80, … },
    "investigation": { "investigation_id": "…", "url": "/investigations/…", "state": "concluded",
                       "classification": "malicious", "risk_score": 80, "recommended_action": "block" },
    "soc_report": {                            // ← the SOC PDF's own data model
      "title": "SOC Investigation Report", "subtitle": "…", "generated_at": "…",
      "classification": "MALICIOUS",
      "verdict": { "classification", "confidence", "risk_score", "recommended_action",
                   "risk_level", "risk_rationale" },
      "case_metadata": [ { "label": "Case ID", "value": "…" }, … ],
      "summary": "…",                          // 1. Executive Summary
      "assessment_points": [ … ],              // 2. Analyst Assessment
      "key_evidence": [ { "source", "ref", "value", "relevance" }, … ],   // 3. Evidence Matrix
      "findings": [ { "severity", "title", "description", "arguments": [ … ] }, … ],  // 4. Findings
      "iocs": [ { "type", "value", "context", "confidence" }, … ],        // 5. IOCs
      "recommendations": [ … ],                // 6. Recommended SOC Actions
      "derived_intelligence": {                // 7. + 8.
        "confidence_engine": { "verdict", "score", "confidence", "confidence_percent",
                               "components", "reasons" },
        "ioc_quality": { "summary": { … }, "items": [ … 30 rows … ], "total_items": 103 } },
      "signals": [ { "severity", "description" }, … ],       // Appendix: generated signals
      "evidence_sections": [ { "title", "rows": [ … ], "table": { … } }, … ],  // Appendix: technical evidence
      "collector_status": [ … ], "contradicting_evidence": [ … ], "data_gaps": [ … ],
      "technical_narrative": "…",
      "methodology": [ … ] } },
  …
]

// format=full — everything, raw evidence included
[
  { "report_type": "executive_summary",       // ← run metadata + the AI reading, merged
    "run_id": "…", "title": "…", "status": "completed",
    "overall_verdict": "malicious", "highest_risk_score": 80,
    "summary": { … }, "extraction": { … }, "alert_body": "…",
    "prior_investigations": { … }, "spawned_investigations": { … },
    "investigations": [ { "investigation_id": "…", "url": "…", "indicator": "evil-corp.net",
                          "classification": "malicious", "reused": false } ],
    "ai_analysis": { "status": "completed", "report_markdown": "…", "incident_graph": { … } } },

  { "report_type": "indicator",               // ← one per indicator, investigation included
    "indicator": { … }, "verdict": { … }, "findings": [ … ],
    "investigation": { "investigation_id": "…", "state": "concluded",
                       "report": { … full analyst report … },
                       "collector_runs": [ … ],
                       "evidence": { … full collector evidence … } } },
  …
]
```

```bash
curl -OJ  "$API/api/alert-investigations/$RUN_ID/export"                    # lean list
curl -OJ  "$API/api/alert-investigations/$RUN_ID/export?format=report"      # report-ready list
curl -OJ  "$API/api/alert-investigations/$RUN_ID/export?format=full"        # everything
curl -s   "$API/api/alert-investigations/$RUN_ID/export?format=report&download=false" | jq '.[1].soc_report.findings'
curl -s   "$API/api/alert-investigations/$RUN_ID/export?format=report&ndjson=true" | while read -r doc; do …; done
```

| Query | Values | Default | Meaning |
|---|---|---|---|
| `format` | `reports` · `report` · `full` · `envelope` · `ndjson` | `reports` | Lean list · report-ready list · everything · run object with `reports` nested · lean list as NDJSON |
| `ndjson` | `true` · `false` | `false` | Serialise the chosen list one document per line |
| `evidence` | `true` · `false` | `true` | `format=full` only — include each investigation's raw collector evidence |
| `download` | `true` · `false` | `true` | `attachment` vs `inline` Content-Disposition |
| `pretty` | `true` · `false` | `true` | Indent the JSON (ignored when `ndjson`) |

Every domain/URL indicator carries a report, whether this run investigated it or
reused an earlier one: a freshly spawned investigation appears under
`investigation`, a reused one under `prior_investigation` (with its `age_days`
and `total_investigations` intact), and both get the same `soc_report` in
`format=report` and the same `report`/`evidence` in `format=full`.

**Which one to hand to a reporting platform: `format=report`.** `soc_report` is
built by `app/services/export_service.build_soc_report_document()`, the same
function behind our PDF export — `templates/soc_report.html` renders nothing but
that dict, so a consumer that walks these keys produces the same document we do,
section for section. What it leaves behind is what the report never prints:
AnyRun process trees, HAR captures, screenshot blobs, full IOC inventories. On a
one-domain alert run that is **64 KB / ~1.9k lines** instead of **2.3 MB / ~47k
lines** for `format=full`. Everything the PDF *does* print is already summarised
inside `soc_report` — `key_evidence` (evidence matrix), `evidence_sections`
(technical appendix), `signals`, and the first 30 `ioc_quality.items`, matching
the template's own cap, with `total_items` recording how many exist.

Every response carries `X-Alert-Run-Status`, `X-Alert-Report-Count` and
`X-Alert-Schema-Version`, so a poller can tell a finished export from a partial
one without a second call — exporting a still-running alert returns whatever
reports exist so far (an empty array while collectors are starting) rather than
an error. The filename is `alert-<title-slug>-<run_id>-<shape>.<ext>`. The UI
downloads through this same endpoint (list page → **Export**, detail page →
**Download JSON list** = `reports`, **Download report list** = `report`,
**Download raw evidence list** = `full`, plus **Copy export URL**), so what an
analyst saves is byte-for-byte what the other platform receives.

**Deleting a run takes its investigations with it.** `DELETE
/api/alert-investigations/{run_id}` removes the run *and* every investigation it
spawned, with their evidence, reports and collector results (FK cascade). Two
things are deliberately kept: an investigation the run merely **reused** — it
existed before the alert — and any investigation **another alert run still
references**, since deleting that would leave the other run's reports pointing at
nothing. The response says exactly what happened:

```jsonc
{ "run_id": "…", "deleted": true,
  "deleted_investigations": ["82a67c1c-…"],
  "kept_investigations":    ["fe37f697-…"] }   // still referenced elsewhere
```

Running investigations have their Celery task revoked before deletion, so a
worker cannot write to a row that has gone. In the UI the control is on the run
detail page (**Delete run**) and on each list row; both confirms state how many
investigations will go with the run — the list row gets the count from
`spawned_investigation_count`.

**Previewing what will be sent.** `/alert-investigations/{run_id}/report`
(detail page → **Preview report**) renders the `format=report` export document by
document: the executive summary with its investigation index and the AI reading,
then every indicator — each domain/URL expanded into the full SOC report
(verdict, case metadata, executive summary, analyst assessment, evidence matrix,
findings with their evidence arguments, IOCs, recommended actions, derived
verdict, IOC quality, signals, technical evidence appendix, methodology), and
every IP/hash with its findings, or its skip reason when it was context-only.
The page fetches the export endpoint itself — nothing is re-derived from other
APIs — so the preview cannot show anything the integrator will not receive. Each
document has a **View JSON** toggle showing the raw element, and the header
counts coverage: full SOC reports, IOC-only findings, still running, context-only.

Verdict scoring is deterministic (no AI) and mirrors the thresholds in
`app/services/decision_engine.py`, so external platforms pushing alert bodies get
the same triage a full investigation would reach. `indicator_reports` is versioned
by `schema_version` — additive changes only within a major version.

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
| `OPENAI_API_KEY` | `""` | Primary provider API key |
| `OPENAI_MODEL` | `"gpt-5.6-luna"` | Primary AI model |
| `ANTHROPIC_API_KEY` | `""` | Fallback provider API key |
| `ANTHROPIC_MODEL` | `"claude-haiku-4-5-20251001"` | Fallback AI model |
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
| `ALERT_VT_HASH_ONLY` | `true` | Alert-body runs spend VirusTotal on hashes only |
| `ALERT_REUSE_PRIOR_INVESTIGATIONS` | `true` | Reuse a recent concluded investigation of the same indicator |
| `ALERT_PRIOR_INVESTIGATION_MAX_AGE_DAYS` | `7` | Base reuse window — scaled per verdict (malicious ×4, benign/suspicious ×0.5, inconclusive never, low confidence ×0.25) |
| `ALERT_INGEST_DEDUPE` | `true` | Reuse the run an identical alert body already produced |
| `ALERT_INGEST_DEDUPE_WINDOW_MINUTES` | `60` | How long that run stays reusable |
| `ALERT_CALLBACK_SECRET` | `""` | HMAC key for `X-Alert-Signature` (empty = unsigned) |
| `ALERT_CALLBACK_TIMEOUT_SECONDS` | `15` | Per-attempt webhook timeout |
| `ALERT_CALLBACK_MAX_RETRIES` | `5` | Webhook retry budget |
| `ALERT_CALLBACK_ALLOW_PRIVATE` | `true` | Allow callback targets on RFC1918 addresses |
| `ALERT_SPAWN_INVESTIGATIONS` | `true` | Extracted domains/URLs get a full investigation |
| `ALERT_SPAWN_OBSERVABLE_TYPES` | `"domain,url"` | Which indicator types spawn one |
| `ALERT_INVESTIGATION_WAIT_SECONDS` | `1500` | How long an alert run waits for them |
| `ALERT_INVESTIGATION_POLL_SECONDS` | `5` | Poll interval while waiting |
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
- `OPENAI_MODEL` (default: `gpt-5.6-luna`)
- `REDIS_URL`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`
- `DATABASE_URL`
- `DATABASE_SYNC_URL`

Optional fallback keys:
- `ANTHROPIC_API_KEY`
- `ANTHROPIC_MODEL` (default: `claude-haiku-4-5-20251001`)

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
