# Domain Threat Investigation Platform

Automated, evidence-based domain threat investigation platform powered by Claude AI. Collects intelligence from 10+ sources, detects phishing kits and brand impersonation, captures visual evidence, maps findings to MITRE ATT&CK, and produces analyst-grade reports — all from a single domain submission.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [How an Investigation Works](#how-an-investigation-works)
- [Evidence Collectors](#evidence-collectors)
- [Signal Generation](#signal-generation)
- [AI Analysis Engine](#ai-analysis-engine)
- [MITRE ATT\&CK Integration](#mitre-attck-integration)
- [Dashboard \& Analytics](#dashboard--analytics)
- [Batch Processing \& Campaign Detection](#batch-processing--campaign-detection)
- [Frontend](#frontend)
- [API Reference](#api-reference)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [External Services \& Data Sources](#external-services--data-sources)

---

## Architecture Overview

```
                          +-------------+
                          |   Frontend  |  Next.js 14 / React 18
                          |  port 3000  |  Recharts, SSE progress
                          +------+------+
                                 |
                            /api/* proxy
                                 |
                          +------+------+
                          |   FastAPI   |  REST + SSE endpoints
                          |  port 8000  |  Pydantic v2 schemas
                          +------+------+
                                 |
              +------------------+------------------+
              |                                     |
       +------+------+                      +-------+-------+
       | PostgreSQL   |                      |    Valkey     |
       |   port 5432  |                      |   port 6379   |
       | Evidence,    |                      | Celery broker |
       | Reports,     |                      | SSE pub/sub   |
       | Artifacts    |                      | Result backend|
       +-------------+                      +-------+-------+
                                                     |
                                              +------+------+
                                              | Celery      |
                                              | Worker      |
                                              | 4 processes |
                                              +------+------+
                                                     |
                          +----------+----------+----+----+----------+
                          |          |          |         |           |
                        DNS       HTTP       TLS      WHOIS        ASN
                       Collector  Collector  Collector Collector  Collector
                          |          |          |         |           |
                        Intel     VirusTotal  Domain   Visual     Subdomain
                       Collector  Collector   Similarity Comparison Enumeration
```

**Stack:** FastAPI + Celery + PostgreSQL + Valkey + Next.js + Playwright + Claude AI

---

## Agent Workflows

- Project agent rules: `AGENTS.md`
- Task routing playbook: `docs/AGENT_PLAYBOOK.md`

Use these when working with Codex/agent sessions to keep planning, execution, and verification consistent.

---

## How an Investigation Works

Every investigation follows a strict, reproducible pipeline:

### Step 1 — Domain Submission

The user submits a domain (e.g. `login-secure-bank.com`) with optional context:
- **Client domain** — the legitimate domain being impersonated (e.g. `bank.com`), enabling typosquatting analysis and visual comparison
- **Specific URL** — a deep URL to screenshot instead of the homepage
- **Reference image** — a pre-captured screenshot of the client's website
- **Context** — SOC notes, OpenCTI observables, Flare findings

### Step 2 — Parallel Evidence Collection

Seven collectors execute simultaneously as a Celery chord (parallel tasks with a shared callback):

| Collector | Source | What It Extracts |
|-----------|--------|-----------------|
| DNS | Public nameservers (8.8.8.8, 1.1.1.1, 9.9.9.9) via `dnspython` | A, AAAA, CNAME, MX, NS, TXT records, DMARC policy, SPF record |
| WHOIS | `python-whois` against registrar WHOIS servers | Registrar, creation/expiry dates, domain age, privacy protection, registrant org/country |
| HTTP | `requests` library with redirect following | Redirect chain, page title, login form detection, security headers, server fingerprint, technologies |
| TLS | Python `ssl` module + `cryptography` library | Certificate issuer, SANs, validity period, self-signed detection, chain length, SHA-256 fingerprint |
| ASN | `dnspython` for IP resolution + `ip-api.com` | ASN number/org, country, city, CDN/cloud/hosting detection, reverse DNS |
| Intel | crt.sh + DNS blocklists (Spamhaus, SURBL, URIBL) + abuse.ch URLhaus | Certificate transparency logs, blocklist hits, malware distribution URLs, related subdomains |
| VirusTotal | VirusTotal API v3 (optional) | Vendor detection counts, per-vendor results, categories, popularity ranks, reputation score |

Each collector has a 30-second timeout and stores raw artifacts (response bodies, certificates, JSON dumps) to local storage or S3.

### Step 3 — Post-Processing

After collectors finish, four additional analyses run sequentially:

1. **Subdomain Enumeration** — Takes subdomains discovered by crt.sh, resolves each via DNS, groups by IP, and flags interesting ones (admin, login, api, staging, vpn, db, jenkins, etc.)

2. **Domain Screenshot** — Always captures a full-page screenshot of the investigated domain using headless Chromium (Playwright), with anti-bot evasion and JS redirect stabilization. Saved as an artifact.

3. **Domain Similarity Analysis** (when client domain provided) — Computes:
   - Levenshtein edit distance
   - 8 typosquatting techniques (omission, insertion, transposition, replacement, TLD swap, hyphenation, subdomain impersonation, combosquatting)
   - Homoglyph detection (Latin/Cyrillic confusables like `a`/`а`, `e`/`е`, multi-char like `rn`/`m`)
   - Visual similarity score (0–100)

4. **Visual Comparison** (when client domain provided) — Captures screenshots of both domains, compares via:
   - Perceptual hashing (aHash + dHash, Hamming distance)
   - RGB histogram correlation (Pearson coefficient)
   - Weighted composite: 60% perceptual hash + 40% histogram
   - Classification: visual clone (>=80%), partial clone (50-79%)

### Step 4 — Signal Generation

35+ investigative signals are automatically generated from the collected evidence. Signals are **clues, not conclusions** — they inform the analyst but do not determine the classification. See [Signal Generation](#signal-generation) for the full list.

### Step 5 — AI Analysis

The complete evidence bundle (collector outputs + signals + data gaps + external context) is sent to Claude with a strict analytical methodology. Claude follows a 5-step reasoning process:

1. Establish baseline plausibility — could a legitimate service operate this way?
2. Identify technical anomalies — what is technically inconsistent?
3. Attacker necessity test — would attacker-controlled infrastructure be required?
4. Hypothesis comparison — legitimate vs. malicious, which is more parsimonious?
5. Classification — apply definitions exactly

The analyst produces a structured report with: classification, confidence, risk score (0-100), findings mapped to MITRE ATT&CK, IOCs, recommended SOC action, and narrative sections.

### Step 6 — Persistence & Delivery

All evidence, reports, artifacts, signals, and IOCs are persisted to PostgreSQL. The frontend receives real-time progress via Server-Sent Events and displays the complete investigation across 7 tabbed views.

---

## Evidence Collectors

### DNS Collector

Queries public recursive resolvers using `dnspython`:

- **Record types:** A, AAAA, CNAME, MX (with priority), NS, TXT (all entries)
- **DMARC:** Fetches `_dmarc.{domain}` TXT record
- **SPF:** Identifies SPF records from TXT entries
- **Artifacts:** Full JSON dump of all records with TTL values

### WHOIS Collector

Queries WHOIS servers via `python-whois` (handles subdomains by extracting the registered domain with `tldextract`):

- **Registration details:** Registrar, creation/updated/expiry dates, domain age in days
- **Privacy detection:** Checks 12+ keywords (privacy, proxy, redacted, whoisguard, domains by proxy, etc.)
- **Registrant info:** Organization, country
- **Infrastructure:** Name servers, domain statuses (clientTransferProhibited, etc.)
- **Artifacts:** Raw WHOIS response text

### HTTP Collector

Probes the domain with `requests` (HTTPS first, HTTP fallback, 10-redirect limit):

- **Reachability:** Whether the domain serves content
- **Redirect chain:** Every hop with status code and headers
- **Client-side redirects:** Detects `<meta http-equiv="refresh">` and `window.location` / `document.location` JavaScript redirects
- **Page analysis:** Title (first 200 chars), content type, content length
- **Login form detection:** Finds `type="password"` input fields
- **Security headers:** CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- **Technology fingerprinting:** nginx, Apache, IIS, Cloudflare, LiteSpeed from Server/X-Powered-By headers
- **Brand impersonation detection:** Scans page body for 12 phishing phrases ("verify your account", "update your payment", "account suspended", "unusual activity", etc.)
- **Phishing kit detection:** 6 regex patterns for obfuscation/exfiltration:
  - `eval()` — JS obfuscation
  - `atob()` — Base64 decoding
  - `String.fromCharCode` — character encoding
  - `unescape()` — URL decoding obfuscation
  - `document.write()` — dynamic content injection
  - `api.telegram.org/bot` — Telegram-based credential exfiltration
- **External form detection:** Identifies `<form>` elements posting to domains other than the investigated one
- **External resource extraction:** Collects external domains referenced in `<script src>`, `<link href>`, `<img src>` (up to 20)
- **Favicon hash:** Fetches `/favicon.ico`, computes Shodan-compatible MurmurHash3 fingerprint for cross-referencing with Shodan's HTTP favicon database
- **Artifacts:** Response headers (JSON), HTML body sample (10KB cap)

### TLS Collector

Connects via Python's `ssl` module and parses the certificate with the `cryptography` library:

- **Certificate details:** Issuer, issuer organization, subject, SANs (Subject Alternative Names)
- **Validity:** Valid from/to dates, days remaining until expiry
- **Fingerprinting:** Serial number, SHA-256 hash (useful for pivoting)
- **Detection:** Self-signed certificates, wildcard certificates
- **Chain:** Certificate chain length
- **Artifacts:** DER-encoded certificate binary

### ASN / Hosting Collector

Resolves the domain to IP via `dnspython`, then queries `ip-api.com` (free, no API key):

- **Network info:** ASN number, ASN organization, ISP
- **Geolocation:** Country, city
- **Reverse DNS:** PTR record
- **Infrastructure classification:**
  - CDN detection (Cloudflare, Akamai, Fastly, CloudFront, etc.)
  - Cloud detection (AWS, Azure, GCP, DigitalOcean, Linode, etc.)
  - Hosting provider flag
- **Artifacts:** Raw ip-api.com JSON response

### Intel Collector

Aggregates threat intelligence from multiple free sources:

- **Certificate Transparency (crt.sh):** Queries `crt.sh/?q=%.{domain}&output=json` to find all certificates ever issued for the domain and its subdomains. Extracts related certificate entries and subdomain names.
- **DNS Blocklists:** Checks the domain against three major blocklists via DNS queries:
  - Spamhaus DBL (`dbl.spamhaus.org`)
  - SURBL (`multi.surbl.org`)
  - URIBL (`black.uribl.com`)
- **abuse.ch URLhaus:** Queries the URLhaus API (`urlhaus-api.abuse.ch/v1/host/`) for known malware distribution URLs associated with the domain
- **Artifacts:** Summary JSON with cert count, subdomain count, blocklist hit details

### VirusTotal Collector

Queries the VirusTotal API v3 (`/api/v3/domains/{domain}`). Optional — skipped if no API key is configured:

- **Detection stats:** Malicious, suspicious, harmless, undetected vendor counts
- **Vendor breakdown:** Per-vendor results (who flagged it and how)
- **Categorization:** Domain categories from multiple categorization engines
- **Popularity:** Alexa, Cisco Umbrella, and other ranking services
- **Passive DNS:** Historical DNS records from VT
- **Certificate info:** Issuer, subject from VT's perspective
- **Community reputation:** Numeric reputation score
- **Free tier limits:** 4 requests/minute, 500/day

### Domain Similarity Analyzer

Pure-Python algorithm (no external APIs) that measures how closely the investigated domain resembles the client's legitimate domain:

- **Levenshtein distance:** Character-level edit distance, normalized to 0.0-1.0
- **Typosquatting detection (8 techniques):**
  1. Character omission (`gogle.com` vs `google.com`)
  2. Character insertion (`googlle.com`)
  3. Adjacent transposition (`googel.com`)
  4. Character replacement (`goog1e.com`)
  5. TLD swap (`google.net` vs `google.com`)
  6. Hyphenation (`mail-google.com`)
  7. Subdomain impersonation (`google.attacker.com`)
  8. Combosquatting (`google-login.com`)
- **Homoglyph detection:**
  - Single-character: `o`/`0`, `l`/`1`, `i`/`1`, `s`/`5`, `b`/`6`, `g`/`9`
  - Latin/Cyrillic: `a`/`а`, `e`/`е`, `p`/`р`, `c`/`с`, `x`/`х`, `y`/`у`, `k`/`к`
  - Multi-character: `rn`/`m`, `cl`/`d`, `vv`/`w`, `nn`/`m`
- **Overall similarity score (0-100):** Composite of edit distance (40%), visual similarity (25%), techniques found (25%), homoglyphs (10%)
- **Outputs:** `is_potential_typosquat` (score >= 50 + techniques), `is_visual_lookalike` (visual similarity >= 0.7 + homoglyphs)

### Visual Comparison

Uses Playwright (headless Chromium) and Pillow for screenshot capture and image comparison:

- **Screenshot capture:**
  - Viewport: 1280x720
  - Tries HTTPS, falls back to HTTP
  - Waits for `domcontentloaded`, then polls for JS redirect stabilization (up to 15s)
  - Anti-bot measures: removes `navigator.webdriver`, spoofs plugins/languages
  - Captures full page (not just viewport)
- **Image comparison metrics:**
  - Perceptual hashing: Average hash (aHash) + Difference hash (dHash) combined via Hamming distance
  - Histogram similarity: Pearson correlation on RGB histograms
  - Overall: 60% perceptual hash + 40% histogram (weighted)
- **Classification thresholds:**
  - Visual clone: >= 80% similarity
  - Partial clone: 50-79% similarity
  - Distinct: < 50% similarity

### Subdomain Enumeration

Post-processing step using crt.sh results from the Intel collector:

- Deduplicates and sorts subdomains (interesting keywords prioritized)
- DNS-resolves each subdomain to A records (up to 100 subdomains)
- Groups resolved subdomains by IP address
- Flags "interesting" subdomains containing keywords: `admin`, `login`, `signin`, `auth`, `api`, `staging`, `dev`, `test`, `vpn`, `mail`, `portal`, `db`, `jenkins`, `internal`

---

## Signal Generation

Signals are investigative clues generated automatically from evidence. They inform the analyst but do not determine the classification on their own. Signals are grouped by category:

### Infrastructure Age
| Signal | Condition | Severity |
|--------|-----------|----------|
| Very young domain | Domain age < 7 days | HIGH |
| Young domain | Domain age 7-30 days | MEDIUM |

### Registration
| Signal | Condition | Severity |
|--------|-----------|----------|
| WHOIS privacy | Privacy protection enabled | INFO |

### Certificate
| Signal | Condition | Severity |
|--------|-----------|----------|
| Self-signed cert | Certificate is self-signed | MEDIUM |
| Certificate expiring | < 7 days until expiry | MEDIUM |
| Many SANs | > 20 Subject Alternative Names | INFO |
| Free certificate | Let's Encrypt / ZeroSSL / BuyPass | INFO |

### Content
| Signal | Condition | Severity |
|--------|-----------|----------|
| Login form detected | `type="password"` found on page | INFO |
| Phishing kit indicators | JS obfuscation or exfiltration patterns found | HIGH |
| Brand impersonation | Phishing phrases detected in page content | MEDIUM |
| Many external resources | > 5 external resource domains loaded | INFO |

### Behavior
| Signal | Condition | Severity |
|--------|-----------|----------|
| Long redirect chain | > 3 redirects before final page | MEDIUM |
| Cross-domain redirect | Final domain differs from initial | MEDIUM |

### Security Posture
| Signal | Condition | Severity |
|--------|-----------|----------|
| No HSTS | Missing Strict-Transport-Security header | LOW |
| No CSP | Missing Content-Security-Policy header | LOW |

### Email Security
| Signal | Condition | Severity |
|--------|-----------|----------|
| No DMARC | Missing DMARC record | LOW |
| No MX records | Domain has no mail exchangers | INFO |

### Infrastructure
| Signal | Condition | Severity |
|--------|-----------|----------|
| Dedicated hosting | On a hosting provider (not CDN/cloud) | INFO |
| Many subdomains | > 50 subdomains in crt.sh | INFO |
| Many live subdomains | > 20 resolved subdomains | INFO |
| Interesting subdomains | admin/login/db subdomains found | MEDIUM |

### Reputation
| Signal | Condition | Severity |
|--------|-----------|----------|
| Blocklisted | Listed in 1+ DNS blocklists | HIGH |
| VT malicious (high) | >= 5 VT vendors flag as malicious | HIGH |
| VT malicious (moderate) | 1-4 VT vendors flag as malicious | MEDIUM |
| VT suspicious | VT vendors flag as suspicious | MEDIUM |
| VT bad reputation | Community reputation < -5 | MEDIUM |

### Domain Similarity (when client domain provided)
| Signal | Condition | Severity |
|--------|-----------|----------|
| High domain similarity | Similarity score >= 80 | HIGH |
| Moderate domain similarity | Score 50-79 | MEDIUM |
| Typosquatting detected | Typosquatting techniques identified | HIGH |
| Homoglyph detected | Visual lookalike characters found | HIGH |
| Combined impersonation | Both typosquat AND visual lookalike | CRITICAL |

### Visual Comparison (when client domain provided)
| Signal | Condition | Severity |
|--------|-----------|----------|
| Visual clone | >= 80% visual similarity | CRITICAL |
| Partial visual clone | 50-79% similarity | HIGH |
| Combined visual + domain | Typosquat + visual clone together | CRITICAL |

---

## AI Analysis Engine

### Classification Definitions

The analyst applies strict definitions — classification is determined by **evidence**, not suspicion:

| Classification | Definition |
|---------------|------------|
| **Benign** | Domain behavior is fully explained by legitimate service operation |
| **Suspicious** | Unusual behavior present, but an attacker is NOT required to explain it |
| **Malicious** | Observed behavior REQUIRES attacker-controlled infrastructure |
| **Inconclusive** | Evidence is insufficient to determine classification |

### Core Analytical Constraints

1. Never invent or assume data not present in evidence
2. Never classify based on domain name alone or "gut feeling"
3. Never classify from a single indicator in isolation
4. Never treat reputation data as proof of maliciousness
5. Never treat missing evidence as evidence of maliciousness
6. Only assign "malicious" if attacker-controlled infrastructure is **required**
7. Return "inconclusive" if evidence is insufficient
8. Always compare legitimate vs. malicious explanations before classifying

### Report Output

The analyst produces a structured JSON report containing:

- **Classification** (benign / suspicious / malicious / inconclusive)
- **Confidence** (low / medium / high)
- **Risk score** (0-100) with rationale
- **Primary reasoning** — the analytical narrative
- **Hypothesis comparison** — legitimate vs. malicious explanation
- **Findings** — individual analyst findings with severity, evidence references, and MITRE ATT&CK technique mappings
- **IOCs** — indicators of compromise (IP, domain, URL, hash, email) with confidence levels
- **Recommended SOC action** (monitor / investigate / block / hunt)
- **Recommended steps** — specific next actions for the SOC team
- **Executive summary** — high-level overview for stakeholders
- **Technical narrative** — detailed analysis for analysts
- **Contradicting evidence** — evidence that argues against the classification

### External Intelligence Policy

- CTI (Cyber Threat Intelligence) **never** determines classification alone
- CTI that matches evidence increases confidence, not classification
- CTI that contradicts evidence is flagged as potentially outdated or misattributed
- Findings older than 90 days receive reduced weight

---

## MITRE ATT&CK Integration

Analyst findings are automatically enriched with MITRE ATT&CK technique mappings from a curated database of 25 techniques relevant to domain-based investigations:

### Mapped Techniques

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Resource Development | T1583.001 | Acquire Infrastructure: Domains |
| Resource Development | T1584.001 | Compromise Infrastructure: Domains |
| Resource Development | T1588.004 | Obtain Capabilities: Digital Certificates |
| Resource Development | T1608.001 | Stage Capabilities: Upload Malware |
| Resource Development | T1608.005 | Stage Capabilities: Link Target |
| Initial Access | T1566.002 | Phishing: Spearphishing Link |
| Initial Access | T1189 | Drive-by Compromise |
| Execution | T1204.001 | User Execution: Malicious Link |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name |
| Defense Evasion | T1036.011 | Masquerading: Break Process Trees |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Command & Control | T1102 | Web Service |
| Command & Control | T1090 | Proxy |
| Command & Control | T1090.004 | Proxy: Domain Fronting |
| Credential Access | T1557 | Adversary-in-the-Middle |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture |
| Collection | T1185 | Browser Session Hijacking |
| Reconnaissance | T1593.002 | Search Open Websites: Search Engines |
| Reconnaissance | T1596.003 | Search Open Technical Databases: Digital Certs |
| Reconnaissance | T1598 | Phishing for Information |

Each finding in the report includes a clickable link to the MITRE ATT&CK page. The Findings tab groups techniques by tactic to show ATT&CK coverage.

---

## Dashboard & Analytics

The dashboard at `/dashboard` provides an operational overview across all investigations:

- **Stat cards** — Total investigations, malicious count, suspicious count, concluded count
- **Classification pie chart** — Breakdown of concluded investigations by classification
- **Risk score histogram** — Distribution across 5 buckets (0-20, 21-40, 41-60, 61-80, 81-100)
- **Investigation timeline** — Stacked area chart of the last 30 days, grouped by classification
- **Top registrars** — Most common registrars among malicious/suspicious domains (horizontal bar chart)
- **Top hosting providers** — Most common ASN organizations among malicious/suspicious domains
- **Recent malicious** — Last 10 malicious investigations with risk scores, clickable to view details

Data is sourced from PostgreSQL aggregation queries, including JSONB field extraction for evidence-level stats (registrars, hosting providers).

---

## Batch Processing & Campaign Detection

### Bulk Investigation

Upload a CSV or TXT file containing up to 500 domains. Each domain is investigated in parallel via Celery:

- Optional batch metadata: name, client domain (applied to all), context
- Real-time progress bar showing completion percentage
- Per-domain status tracking (state, classification, risk score)

### Campaign Detection

After batch investigations complete, the platform can detect **campaigns** — groups of domains sharing infrastructure:

- **Shared IP addresses** — Domains resolving to the same IP
- **Shared TLS certificates** — Domains using the same certificate (by SHA-256)
- **Same ASN** — Domains hosted on the same autonomous system
- **Same registrar** — Domains registered through the same registrar
- **Same name servers** — Domains using the same DNS infrastructure

Campaign groups are displayed with shared infrastructure badges and domain classification overlays. Unclustered domains (with no shared infrastructure) are shown separately.

---

## Frontend

### Pages

| Page | Path | Description |
|------|------|-------------|
| Home | `/` | Domain submission form with optional client domain, URL, reference image, context |
| Dashboard | `/dashboard` | Analytics overview with charts and stats |
| All Cases | `/investigations` | Filterable investigation list (by state) |
| Investigation Detail | `/investigations/[id]` | Full investigation with 7 tabbed views |
| Batches | `/batches` | Batch upload and recent batch list |
| Batch Detail | `/batches/[id]` | Batch progress, investigation table, campaign detection |

### Investigation Detail Tabs

1. **Executive Summary** — Classification badge, risk score, reasoning, SOC action, hypothesis comparison
2. **Technical Evidence** — DNS records, TLS certificate, HTTP response, WHOIS data, hosting/ASN, content analysis (phishing indicators, brand impersonation, favicon hash, external resources), domain screenshot, visual comparison, subdomain enumeration, VirusTotal results, threat intelligence
3. **Findings** — Analyst findings with severity badges and MITRE ATT&CK mappings, technique coverage by tactic
4. **Indicators & Pivots** — IOCs (IP, domain, URL, hash, email) with confidence levels
5. **Signals & Gaps** — Investigative signals and identified data gaps with impact statements
6. **Infrastructure** — Pivot points (IPs, certs, ASN, registrar, nameservers) and related investigations sharing infrastructure
7. **Raw JSON** — Toggle between evidence, report, and investigation detail JSON views

### Real-Time Progress

During collection, the UI displays a collector timeline with live status indicators for each of the 8 stages (DNS, TLS, HTTP, WHOIS, ASN, Intel, VT, Analyst). Statuses update via SSE streaming.

### Export

Investigations can be exported as:
- **PDF** — formatted report with all sections
- **Markdown** — portable text format
- **JSON** — raw data for integration

---

## API Reference

### Investigations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/investigations` | Start a new investigation |
| GET | `/api/investigations` | List investigations (filter by state, limit, offset) |
| GET | `/api/investigations/{id}` | Get investigation metadata |
| GET | `/api/investigations/{id}/evidence` | Get full evidence JSON |
| GET | `/api/investigations/{id}/report` | Get analyst report |
| POST | `/api/investigations/{id}/enrich` | Add external intelligence (re-analysis optional) |
| GET | `/api/investigations/{id}/pivots` | Get infrastructure pivot points and related investigations |

### Real-Time Progress

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sse/subscribe/{id}` | SSE stream for investigation progress |

### Batches

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/batches` | Upload CSV/TXT for bulk investigation |
| GET | `/api/batches` | List all batches |
| GET | `/api/batches/{id}` | Get batch detail with investigations |
| GET | `/api/batches/{id}/campaigns` | Detect shared infrastructure campaigns |

### Artifacts & Reference Images

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/artifacts/{id}` | Download stored artifact (screenshots, certs, etc.) |
| POST | `/api/reference-images/{domain}` | Upload reference screenshot for client domain |
| HEAD | `/api/reference-images/{domain}` | Check if reference image exists |

### Analytics & Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | Aggregated dashboard statistics |
| GET | `/api/attack/techniques` | List all mapped MITRE ATT&CK techniques |
| GET | `/api/health` | Health check |

---

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- PostgreSQL 18
- Valkey 8 (Redis-compatible)
- An Anthropic API key

### Option 1: Docker Compose (Recommended)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY (required), VIRUSTOTAL_API_KEY (optional)

# 2. Start all services
docker-compose up -d

# 3. Run database migrations
docker-compose exec api alembic upgrade head

# 4. Open the UI
# http://localhost:3000
```

Note: PostgreSQL major upgrades (for example `16 -> 18`) require data migration.
If an old `pgdata` volume exists, either migrate with `pg_upgrade`/dump-restore
or use a fresh dev volume.

### Option 2: Manual Setup

```bash
# 1. Start infrastructure
docker-compose up -d postgres redis
# Or install PostgreSQL and Valkey natively

# 2. Configure environment
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and database URLs

# 3. Install backend dependencies
cd backend
pip install -r requirements.txt

# 4. Run database migrations
alembic upgrade head

# 5. Start FastAPI server
uvicorn app.main:app --reload --port 8000

# 6. Start Celery worker (separate terminal)
celery -A app.tasks.celery_app worker --loglevel=info --concurrency=4

# 7. Start frontend (separate terminal)
cd frontend
npm install
npm run dev
```

### Using the Makefile

```bash
make infra       # Start PostgreSQL + Valkey
make migrate     # Run database migrations
make api         # Start FastAPI with hot reload
make worker      # Start Celery worker
make doctor      # Runtime sanity diagnostics (API/Celery/Valkey/Postgres)
make test        # Run test suite
make investigate domain=example.com   # CLI investigation
make seed        # Seed test data
```

PowerShell alternative (if `make` is not installed):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\doctor.ps1
```

---

## Configuration

All configuration is via environment variables (`.env` file):

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | `sk-ant-...` |
| `DATABASE_URL` | Async PostgreSQL connection string | `postgresql+asyncpg://threatintel:threatintel@localhost:5432/threatintel` |
| `DATABASE_SYNC_URL` | Sync PostgreSQL connection string (for Celery/Alembic) | `postgresql://threatintel:threatintel@localhost:5432/threatintel` |
| `REDIS_URL` | Valkey connection string (Redis-compatible) | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend URL | `redis://localhost:6379/1` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | Claude model for analysis |
| `VIRUSTOTAL_API_KEY` | _(empty)_ | VirusTotal API key (collector skipped if empty) |
| `ARTIFACT_STORAGE` | `local` | Storage backend (`local` or `s3`) |
| `ARTIFACT_LOCAL_PATH` | `./artifacts` | Local artifact directory |
| `S3_BUCKET` | `threat-intel-artifacts` | S3 bucket for artifacts |
| `S3_ENDPOINT_URL` | _(empty)_ | S3 endpoint (for MinIO/compatible) |
| `APP_ENV` | `development` | Environment (`development` or `production`) |
| `APP_DEBUG` | `true` | Enable debug logging |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `MAX_ANALYST_ITERATIONS` | `3` | Maximum analyst re-analysis iterations |
| `COLLECTOR_TIMEOUT` | `30` | Collector timeout in seconds |
| `DEFAULT_COLLECTORS` | `dns,http,tls,whois,asn,intel,vt` | Enabled collectors |

---

## Project Structure

```
threat-intel/
├── backend/
│   ├── app/
│   │   ├── analyst/              # AI analysis engine
│   │   │   ├── attack_mapping.py #   MITRE ATT&CK technique database (25 techniques)
│   │   │   ├── orchestrator.py   #   Claude API client and response handling
│   │   │   ├── prompt_builder.py #   Evidence → prompt construction
│   │   │   ├── response_parser.py#   JSON extraction from Claude response
│   │   │   └── system_prompt.py  #   234-line analytical methodology prompt
│   │   ├── api/                  # FastAPI REST endpoints
│   │   │   ├── investigations.py #   CRUD + evidence + report endpoints
│   │   │   ├── sse.py            #   Server-Sent Events for progress
│   │   │   ├── batches.py        #   Bulk investigation + campaigns
│   │   │   ├── dashboard.py      #   Analytics aggregation queries
│   │   │   ├── attack.py         #   ATT&CK technique reference
│   │   │   ├── artifacts.py      #   Artifact download
│   │   │   ├── reference_images.py#  Client screenshot upload
│   │   │   ├── pivots.py         #   Infrastructure pivot queries
│   │   │   ├── enrichment.py     #   External intelligence ingestion
│   │   │   ├── export.py         #   PDF/Markdown/JSON export
│   │   │   └── router.py         #   Route aggregation
│   │   ├── collectors/           # Evidence gathering modules
│   │   │   ├── base.py           #   BaseCollector abstract class
│   │   │   ├── dns_collector.py  #   DNS records via dnspython
│   │   │   ├── whois_collector.py#   WHOIS via python-whois
│   │   │   ├── http_collector.py #   HTTP probe + content analysis
│   │   │   ├── tls_collector.py  #   TLS certificate parsing
│   │   │   ├── asn_collector.py  #   ASN/geo via ip-api.com
│   │   │   ├── intel_collector.py#   crt.sh + blocklists + URLhaus
│   │   │   ├── vt_collector.py   #   VirusTotal API v3
│   │   │   ├── domain_similarity.py# Typosquatting + homoglyph detection
│   │   │   ├── visual_comparison.py# Screenshot capture + image comparison
│   │   │   └── signals.py        #   35+ investigative signal generation
│   │   ├── db/                   # Database layer
│   │   │   ├── session.py        #   Async/sync engine + session factory
│   │   │   └── repository.py     #   Data access queries
│   │   ├── models/               # Data models
│   │   │   ├── database.py       #   SQLAlchemy ORM (7 tables)
│   │   │   └── schemas.py        #   Pydantic v2 schemas (evidence, report)
│   │   ├── services/             # Business logic
│   │   │   └── investigation_service.py
│   │   ├── storage/              # Artifact persistence
│   │   │   ├── base.py           #   Abstract storage interface
│   │   │   └── local.py          #   Local filesystem storage
│   │   ├── tasks/                # Celery async pipeline
│   │   │   ├── celery_app.py     #   Celery configuration
│   │   │   ├── investigation_task.py # Entry point: chord of collectors
│   │   │   └── analysis_task.py  #   Post-processing + AI analysis
│   │   ├── utils/                # Utilities
│   │   │   ├── domain_utils.py   #   Domain validation + extraction
│   │   │   └── hashing.py        #   SHA-256 + MurmurHash3 (Shodan compat)
│   │   ├── config.py             #   Pydantic Settings (env vars)
│   │   ├── dependencies.py       #   FastAPI dependency injection
│   │   └── main.py               #   Application factory
│   ├── alembic/                  # Database migrations
│   │   └── versions/
│   │       ├── 001_initial_schema.py
│   │       ├── 002_add_client_domain.py
│   │       └── 003_add_batches.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/                  # Next.js App Router pages
│   │   │   ├── page.tsx          #   Home — investigation input
│   │   │   ├── dashboard/        #   Dashboard — analytics charts
│   │   │   ├── investigations/   #   Investigation list + detail
│   │   │   └── batches/          #   Batch upload + detail
│   │   ├── components/
│   │   │   ├── layout/           #   Header with navigation
│   │   │   ├── shared/           #   Spinner, TabBar, Badge
│   │   │   ├── investigation/    #   Input, Progress, Enrichment, Classification
│   │   │   ├── report/           #   7 tab components (Summary, Evidence, etc.)
│   │   │   ├── batch/            #   Upload, Table, CampaignView
│   │   │   └── evidence/         #   EvidenceTable component
│   │   ├── lib/
│   │   │   ├── api.ts            #   API client + SSE + artifact URLs
│   │   │   ├── types.ts          #   TypeScript types (mirrors backend schemas)
│   │   │   └── constants.ts      #   Design tokens + classification colors
│   │   └── styles/
│   │       └── globals.css       #   CSS variables, dark theme, animations
│   ├── next.config.js            #   API proxy rewrites
│   └── package.json
├── docker/
│   ├── Dockerfile.api
│   ├── Dockerfile.worker         # Includes Playwright + Chromium
│   └── Dockerfile.frontend
├── docker-compose.yml
├── Makefile
├── .env.example
└── README.md
```

---

## External Services & Data Sources

| Service | Purpose | API Key Required | Rate Limits |
|---------|---------|:----------------:|-------------|
| **Anthropic Claude API** | AI-powered threat analysis | Yes | Model-dependent |
| **VirusTotal API v3** | Domain reputation and vendor detections | Optional | 4 req/min, 500/day (free tier) |
| **ip-api.com** | ASN, geolocation, ISP lookup | No | 45 req/min (free tier) |
| **crt.sh** | Certificate Transparency log search | No | Implicit rate limit |
| **Spamhaus DBL** | DNS blocklist | No | DNS query |
| **SURBL** | DNS blocklist | No | DNS query |
| **URIBL** | DNS blocklist | No | DNS query |
| **abuse.ch URLhaus** | Malware URL database | No | Free API |
| **Playwright / Chromium** | Headless browser screenshots | No | Local binary |

### Data Flow Summary

```
Domain Submission
    │
    ├─── DNS ──── Public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
    ├─── WHOIS ── Registrar WHOIS servers
    ├─── HTTP ─── Direct HTTPS/HTTP connection to domain
    ├─── TLS ──── Direct SSL/TLS handshake with domain
    ├─── ASN ──── ip-api.com (free JSON API)
    ├─── Intel ── crt.sh + Spamhaus/SURBL/URIBL + abuse.ch URLhaus
    └─── VT ───── VirusTotal API v3
         │
         ▼
    Evidence Bundle
         │
    ├─── Subdomain Enumeration (DNS resolution of crt.sh results)
    ├─── Screenshot Capture (Playwright headless Chromium)
    ├─── Domain Similarity (pure Python, Levenshtein + homoglyphs)
    └─── Visual Comparison (Playwright + Pillow image processing)
         │
         ▼
    Signal Generation (35+ automated investigative signals)
         │
         ▼
    Claude AI Analysis (5-step methodology + MITRE ATT&CK mapping)
         │
         ▼
    Structured Report
    (classification, risk score, findings, IOCs, recommendations)
```
