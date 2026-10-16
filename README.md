# Domain Threat Investigation Platform

Automated, evidence-based domain threat investigation platform powered by Claude AI. Collects intelligence from 10+ sources, detects phishing kits and brand impersonation, captures visual evidence, maps findings to MITRE ATT&CK, and produces analyst-grade reports — all from a single domain submission.

---

## Where values are born

The one invariant to hold before reading anything else here, because almost
every confused question about this codebase is a question asked of the wrong
layer:

| layer | what it holds | written by |
|---|---|---|
| `alert_body_investigation_runs.alert_body` | the source's own text, untouched | ingest |
| `alert_graph_entity` / `alert_graph_edge` | **exactly what extraction produced**, per run | `extract()`, via the materialisation sweep |
| the assembled graph | merges, folds, enrichment, ATT&CK naming, reused-infrastructure flags | `assemble()` / `graph_for_runs()`, **at read time** |
| the endpoint payload | case overlays — criticality, supersession, pivots, draw summary | `get_case_graph` |

**Storage records what was extracted. Everything derived happens on read and
is never stored.** So `alert_graph_entity` will never contain
`absorbed_parent`, a technique's `name`, its `tactic` or an enrichment
verdict, and a query looking for one there returns zero rows for ever — which
looks exactly like the feature being broken. Verified 2026-10-13: 0 stored
technique rows carry any of them, and 0 rows of any kind carry enrichment.

One caution when checking this yourself: attribute names are not unique across
node kinds. `attrs ? 'name'` matches a *service* node, where `name` is the
service's own name and is extraction output. Scope the check to the kind you
mean.

The same line answers the other direction. A change to extraction needs the
runs re-materialised before it appears; a change to assembly, naming or
enrichment appears on the next request with no backfill at all. The `refines`
edge needed a drain; the parent/child fold did not, and that followed from
this table rather than from a measurement.

**A new source is what tests this.** When CrowdStrike lands it brings new
extraction, and the invariant holds only if nothing CrowdStrike-derived is
computed at read time and nothing currently derived gets stored because it was
convenient during the integration. If that line stops being true, the next
wrong-layer question has no answer at all — which is worse than today, where
the answer existed as soon as somebody looked.

---

## Read these before changing anything

Sixteen rules that were learned expensively and are not obvious from the code:

- **[A rename is not a deployment](docs/deploy/schema-changes.md)** —
  `alembic upgrade head` changes the database for every container at once;
  rebuilding changes the code for one. Between the two, any container still
  running the old code fails every query touching the change, and nothing
  notices because each half is internally consistent. This stopped all alert
  analysis for 2h38m with no signal. Its sibling is in the same document: **an
  `.env` change is not a restart** — `env_file` is read when a container is
  created, so `restart` reuses the old environment and `up -d` often sees no
  config change and exits 0 having done nothing.
- **[Name the entry point you measured — and check the instrument can return the bad answer](docs/deploy/measuring.md)**
  — a timing or correctness claim states the call path it went through. A
  bound on the case graph was built, measured and re-run across eleven cases
  before anyone noticed its input could never reach its threshold: every
  number described a path no user was on.

  The same test applies to the instrument, not just to the thing measured.
  Before trusting a check, ask what it would show if the answer were bad. On
  2026-10-12 three checks in a row could not have failed: a `docker compose
  exec python` that re-imports from the bind mount and so reports the source
  rather than the running process; a file mtime, which moves on `touch` and
  not on content; and a timestamp accidentally compared against itself. Each
  returned "fine" because "not fine" was not among its possible outputs. The
  check that worked that day picked a signal whose two values distinguish the
  two code versions — a stored field present versus absent — and got it from
  the live process through the broker.
- **[A source that stops looks exactly like a source that is quiet](docs/problems/sources-that-stopped.md)**
  — every alarm here measured work in progress and none measured work that
  never arrived, so two sources worth 34% of all alerts went silent for 17 and
  23 days unnoticed. A new alarm needs to say which of the two it can tell
  apart.
- **State the stores an absence was sought in.** An absence claim has a
  scope the way a number has a population, and it should carry it. "The true
  exposure is unknown" was written about truncated IPv4-mapped addresses
  because none survived in `ioc_values` — while the alert bodies were
  retained one table over and still held 93 of the originals. *"Not found in
  `ioc_values`; bodies not checked"* would have been true and would have
  prompted the next step immediately.

  The same failure, larger, two steps later: 55.6% of alert bodies were
  reported as free text with no recoverable field, having only been tested
  against four shapes. Censused against nine, **99.9% are parseable** and the
  genuinely unclassified remainder is 10 bodies. Declaring something
  unknowable without naming where you looked turns an unsearched place into a
  known negative — which is the same move as reading an empty result as a
  clean one, one level up. Its sibling is
  [the grain rule](docs/deploy/measuring.md): a number states its
  population, an absence states its scope.

- **Proportions quoted as coverage have to sum.** Four body-format
  classifiers matched 44.4% of alert bodies between them, and that figure was
  reported as coverage — leaving 55.6% described as free text. But the four
  overlapped: they were counted as if they partitioned the corpus, and shares
  that don't sum to 100 aren't shares. The honest version needs an ordered
  classifier where first match wins, every body counted exactly once, and an
  explicit `unclassified` bucket carrying the remainder; run that way the
  answer was **99.9% parseable, 10 unclassified** — the opposite conclusion.
  Two tests before quoting a share: do the parts sum to the whole, and is
  there a named bucket for what matched nothing. A set of overlapping
  positives has no complement, so the number you take from it by subtraction
  is not measuring anything.

  **And the sum test is seductive, because passing it proves only that the
  partition is exhaustive.** It says nothing about whether anything landed in
  the right bucket. Ordering the classifiers made the shares sum, which was
  the defect being fixed, and it did nothing to make each classifier correct:
  a table that sums to 100% while assigning half its mass to the wrong shape
  passes the check completely. `json_keys_embedded` is the live example — it
  took 31.1% of the corpus on a quoted-word-before-a-colon match, and only
  7.0% of those bodies hold an object that parses. So exhaustiveness and
  correctness are separate claims needing separate evidence, and the second
  one is per-bucket work that no amount of arithmetic on the totals can
  stand in for.

- **When comparing two periods, state both lengths.** The specific form of
  compare-like-with-like that keeps recurring here: `alerts_at_close` counted
  at one window against a re-derivation at another, and a host reported at
  "21.1% of prior" from 194 alerts over 24 days against 41 over 18 — on equal
  windows it was 37%, a decline rather than a collapse. Two weeks apart, same
  shape, both caught only by someone re-reading their own figure.
- **The environment is part of what you are measuring.** A monitor is not done
  until it has run against live data, and a failure in a test environment is
  not a defect until it has been reproduced outside one. The two halves are
  one fact: a green test does not prove the thing works in production, and a
  red one does not prove it is broken.

  Both directions earned their place in a single week. *Forward:* the ingest
  alarm passed 21 tests, then on its first live run reported 2.5 days of
  silence for a source delivering 97 alerts in 12 hours, and cleared a 26-day
  outage on the strength of one alert. ThreatFox is the sharper case — every
  test that touched it supplied the feed's output itself, monkeypatching
  Cobalt Strike and Emotet hits, while no test ever called `perform_ip_lookup`
  and the real request 401'd on a wrong header name for 6,376 consecutive
  lookups. A suite can assert elaborate behaviour on data the system has never
  once retrieved. *Backward:* headless Chromium showed Esc failing to leave
  fullscreen and it was nearly filed as a bug — the headless shell owns no
  window for the browser to take the key, and both real paths work — and every
  component test reported "React is not defined" until the JSX transform was
  configured, which was the harness and not the components.

- **[Every ATT&CK mapping we show is an assertion](docs/problems/attack-corroboration.md)**
  — 42 of 32,574 technique entries are corroborated, and 38 of those 42 are on
  one test machine. Four confirmations exist in the whole production estate.
  Say "assertions" rather than "mappings" when describing what this platform
  produces.

- **An absence convention sits downstream of correctness.** `app/services/absence.py`
  makes a *missing* value legible; it cannot make a *wrong* one safe, and it
  offers no protection at all against a query that returns the right shape
  from the wrong row. `ip_lookups` is append-only history, the IP read had no
  `ORDER BY`, and a dict comprehension kept whichever row Postgres returned
  last — not the newest on 218 of 1,535 addresses. On two it inverted the very
  distinction the module exists for, showing a confident `0` where the check
  had failed and "the provider did not answer" where a real 0 was stored. It
  defeated the convention from inside the one module built to enforce it. If
  rows accumulate per subject, select `distinct on (subject) ... order by
  subject, stamp desc`, and ask what one row means before computing any
  percentage over the table.

- **[A feed answers about a host; a verdict is about an observable](docs/problems/the-intel-collector-was-dead-for-98-days.md)**
  — reached independently on two feeds a day apart, so it is a property of
  host-granular intelligence and not of either provider. ThreatFox's
  substring search returned 45 positive domains across seven months and 44
  were shared-provider apexes; URLhaus, asked about `github.com`, reports
  9,654 malicious URLs and 22,665 for `raw.githubusercontent.com`. Of the
  four hosts it listed among 259 that had received a benign verdict, **not
  one** carried a listing for the path this platform had investigated.
  Consuming either feed at host granularity in `and not hits` — a
  precondition for benign — would have taken the pipeline from
  under-escalating for seven months to escalating most of the estate on the
  day the credential landed. So the raw answer stays in the evidence, because
  "malware is hosted here" is real context, and the *decision* uses only what
  is about the observable itself: `app/services/threatfox_match_scope.py`,
  one module for both feeds. Recording what a source said and deciding what
  it means are two statements.

- **A precondition must require `checked and not listed`.** `not hits` is
  true both when a source answered "nothing" and when it never answered, and
  in a benign precondition the second unlocks the branch on no evidence at
  all. ThreatFox spent seven months there and the intel collector 98 days,
  and in **both** cases the platform had already recorded which it was —
  `feeds_skipped` carrying `threatfox (error: HTTPError)`, `meta.status =
  "failed"` on 2,198 consecutive runs — and nothing read it. The one source
  that did it right, Google Safe Browsing's `(checked and not listed)`, sat
  twelve lines away in the same function. Apply the rule where absence
  *lowers* risk toward benign, and not where it would raise risk toward a
  block: requiring a feed to have answered before the platform will decline
  to auto-block makes an outage cause blocks.

- **Write the test for the bad direction before the branch that could take
  it.** Not a habit — the practice. **Six** defects went inside their own
  fixes on 2026-10-12/13, and the three that were caught were caught this
  way: SURBL's refusal code `127.0.0.254` would have marked the whole estate
  listed the moment the intel collector stopped crashing;
  `about_observable` dropped matches for an unknown observable and unlocked
  benign; and the ThreatFox kill switch assigned `threatfox_status` to a bare
  local, so a *disabled* feed recorded nothing and would have read as "asked,
  nothing listed" — the exact defect being switched off.

  The reason it recurs is mechanical: fixing an absence bug puts you in a
  filtering mindset, and filtering is the operation that creates absences. So
  the fix's own logic is the highest-risk site for the defect it is fixing.
  Write the assertion against the direction that does damage, watch it fail,
  then write the branch. And pair it with a control that fails if the guard
  becomes too aggressive — a filter that rejects everything passes every
  dangerous-direction test and detects nothing.

- **[Recording a failure is not reading it](docs/problems/per-verdict-source-coverage.md)**
  — every multi-month outage found on 2026-10-13 was already written down, on
  every affected row, in a field built for the purpose: ThreatFox's 401 in
  `feeds_skipped`, the intel collector's 2,198 consecutive failures in
  `meta.status`, OTX at 70%, VirusTotal's rate limits, brave_osint's lapsed
  subscription at 42%. The defect was never the recording. Nothing consumed
  it, and no surface showed it to the person making the decision — so a
  verdict reached with nine of eighteen sources unavailable looked exactly
  like one reached with all of them. When adding a failure state, name the
  consumer and the surface in the same change, and **derive the expected set
  from the registry** rather than listing it: `otx` was missing from the
  check built to find dead sources while being 70% dead.

  **And the seam between two correct halves is where this keeps failing.**
  Four times in one week a check verified each side and not the join: `exec
  python` against the running server; the `/health` alias against the
  decorated route; the api/worker fingerprint against a frontend that is a
  built image; and the backend route against the client's own URL
  construction — the integrations page asked for `/api/api/integrations/...`
  because `request()` prefixes `BASE = "/api"` and the new call sites passed
  `/api/...` too. Each time both halves were right and the seam was wrong,
  and each time the verification had been done on the two halves separately.
  So name the join and test *that*: the URL the deployed bundle builds, not
  the endpoint called by hand; the route the consumer hits, not the one that
  looks canonical.

  **The fifth instance was inside the instrument built for the fourth.**
  `scripts/liveness.sh` read the api fingerprint with `docker compose exec api
  python` — a fresh interpreter that imports the files on disk — while its own
  comment forbids exactly that for the worker. With `./backend:/app` bind
  mounted and the api running **without `--reload`** (decided 2026-10-13),
  disk and process diverge the moment anybody edits backend code. Measured:
  the serving process was `c94ab098` over 260 files while the script printed
  `b018dd56` over 263 and called it `in sync`, and the api had been serving
  code **3h11m older** than the commit it was supposedly running. The
  integrations card rendering under "Other" was that staleness, not the key
  mismatch it looked like — the payload the page received genuinely had no
  `category`, so the component was right.

  Two corrections followed. The api fingerprint now comes from the serving
  process over HTTP. And the dirty-tree skew exemption added that same morning
  was **removed**, because its premise — "any edit moves the api's hash" — was
  only true of the misreading: with both values read from the running
  processes, an edit moves neither, verified by adding and removing a module
  and watching the api's value hold. A workaround built on an unverified
  premise outlived the bug it was masking by half a day.

  **The derivation discipline belongs wherever a hand-kept list exists, not
  only where one has already bitten.** The eighth was found at 19.1% of
  account nodes while nobody was looking for it, and an unenumerated set only
  grows — so they are now named in
  [docs/design/silent-registries.md](docs/design/silent-registries.md), the
  same way the tolerated test failures are. Derive the list from what it is a
  list of, or guard it with a test that fails when it is incomplete; a
  hand-kept list is fine only where omission fails loudly, which is why
  `APP_NAV_SECTIONS` stays as it is.

- **Verify an exemption's premise independently of the check it exempts.**
  An exemption added to quiet a false positive keeps quieting the *true* one
  after the false one is fixed — and nobody notices, because a quiet check
  looks the same either way.

  `scripts/liveness.sh` is the instance. A dirty-tree carve-out was added on
  the premise that "any edit moves the api's hash and not the worker's", so
  skew on a dirty tree was expected rather than actionable. That premise was
  true *only because the script was reading the api fingerprint from disk
  instead of from the serving process* — **the premise for the workaround was
  the bug**. Fix the reading and the exemption turns out to have been
  silencing nothing real: with both values taken from the running processes,
  an edit moves neither. It outlived its reason by half a day; it could as
  easily have been months.

  So the test is: could this premise be checked by something other than the
  check I am exempting? If not, it is an assumption wearing a measurement's
  clothes. Worked examples in this repo, audited 2026-10-14:

  | exemption | premise | independent? |
  |---|---|---|
  | `cef_header_service.NON_OBSERVABLE_FIELDS` | the CEF spec fixes field positions | **definitional** — strongest kind |
  | `_NO_ACCOUNT_FROM_EVENT = {"15"}` | Sysmon 15 leaks ADS bytes into `user`; 107 of 299,087 short account names come from it | **measured** |
  | `source_coverage.UNAVAILABLE = {FAILED}` | only a real failure is unavailability; the wider set cried wolf on 47–50% of verdicts | **measured** |
  | `label_value.NON_OBSERVABLE_LABELS` | these 17 labels never carry observables | **measured for 10, untested for 7** — now split in the source |
  | the liveness dirty-tree carve-out | "an edit moves the api's hash" | **circular — removed** |

  A premise that is merely plausible is still worth writing down, but it is
  labelled as untested rather than counted as covered: seven of those
  seventeen labels never occur in this corpus, so the measurement says
  nothing about them in either direction.

- **Name the other world that produces the same observation.**

  Four defects on 2026-10-14 had one shape, and it is not "an absence read as
  a value" — that covers some of them and inverts on others. The form that
  covers all four: **the verdict collapsed two states that produce identical
  observations, and the code chose one without establishing it could tell
  them apart.**

  | observation | world A | world B |
  |---|---|---|
  | empty result set | found nothing | asked nothing |
  | no config row | never configured | configuration vanished |
  | wrong output | wrong key | right key, in a process that never read it |
  | silence | broken | quiet |

  Note the directions disagree, which is why the narrower rule fails: `not
  hits` conflated **two absences** (nothing found, nothing asked); twelve
  minutes of silence read as an outage was an **absence read as an event**,
  the opposite of an event read as an absence. Only the collapse is common to
  all of them.

  **So the question to ask of any verdict is: name the other world that
  produces this same observation.** If you cannot name one, you have not
  looked yet. If you can, you need evidence that separates them — and if
  there is none, *the verdict has to say so*. That third option is the one
  this codebase keeps rediscovering: it is what the absence convention does
  for data (`never_observed` is not `0`), and what `continuity()` now does
  for time — Falcon declares no silence interval because a quiet estate and a
  broken Falcon look identical, so it reports the last success and refuses a
  verdict rather than inventing a threshold.

  **And a note on how this rule was got wrong first.** My initial version was
  "what would this look like if the thing had been working yesterday?" — which
  catches the two history-dependent cases and misses silence entirely, because
  silence has nothing to do with yesterday. A generalisation fitted to three of
  the four cases that produced it is the same mistake as a measurement fitted
  to its sample, and it is worth more care precisely when the rule seems good:
  the version that fits is the version nobody re-derives.

- **[A fitted graph can still be unreadable](docs/problems/graph-fit-density.md)**
  — `cy.fit()` scales to whichever dimension binds first, so a tall narrow
  layout renders at thumbnail scale. A property of fit-against-aspect, not of
  any one layout.

Open problems with the evidence behind them live in
[`docs/problems/`](docs/problems/); the incident notes live in
[`docs/incidents/`](docs/incidents/).

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
       | PostgreSQL   |                      |     Redis     |
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

**Stack:** FastAPI + Celery + PostgreSQL + Redis + Next.js + Playwright + Claude AI

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
- PostgreSQL 16
- Redis 7
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

### Option 2: Manual Setup

```bash
# 1. Start infrastructure
docker-compose up -d postgres redis
# Or install PostgreSQL and Redis natively

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
make infra       # Start PostgreSQL + Redis
make migrate     # Run database migrations
make api         # Start FastAPI with hot reload
make worker      # Start Celery worker
make test        # Run test suite
make investigate domain=example.com   # CLI investigation
make seed        # Seed test data
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
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result backend URL | `redis://localhost:6379/1` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_MODEL` | `gpt-5.6-luna` | Primary AI model |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Fallback AI model |
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
| `URLSCAN_ANALYSIS_TIMEOUT_SECONDS` | `75` | Maximum time to poll an accepted URLScan analysis |
| `DEFAULT_COLLECTORS` | `dns,http,tls,whois,asn,intel,vt` | Enabled collectors |

### ANY.RUN Residential Proxy

The Any.Run sandbox integration keeps API keys server-side only. Configure keys and proxy country choices in the backend environment:

| Variable | Description | Example |
|----------|-------------|---------|
| `ANYRUN_API_KEY` | Primary Any.Run API key used by the backend sandbox/lookup service | `...` |
| `ANYRUN_API_KEY_FALLBACK` | Optional second Any.Run API key for fallback submissions | `...` |
| `ANYRUN_PRIVACY_TYPE` | Any.Run privacy mode, when supported by the plan | `owner` |
| `ANYRUN_SANDBOX_OS` | Sandbox OS connector family | `windows` |
| `ANYRUN_URL_SANDBOX_ANALYSIS_TIMEOUT` | Any.Run URL task timeout option in seconds | `120` |
| `ANYRUN_URL_SANDBOX_MITM` | Whether to enable Any.Run HTTPS MITM for URL tasks | `true` |
| `ANYRUN_PROXY_COUNTRIES` | Comma-separated Residential Proxy geo choices exposed to the UI | `BE,US,GB,DE,FR` |

Residential Proxy submissions use the official Any.Run SDK/API option names:
`opt_network_residential_proxy=true` and `opt_network_residential_proxy_geo=<country>`.
Country values should be Any.Run-supported uppercase country codes such as `US`, `GB`, or `BE`; when Residential Proxy is enabled without a country, the backend sends `fastest`.
Availability depends on the Any.Run plan/API entitlement.

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

### Rule 17 — a migration runs later than it is written

**Any code that encodes a measured fact executes after the measurement that
justified it.** So it resolves against the data rather than asserting about it.

Migration 065's backfill said *"the six existing rows all carry
`'verification'`"* — a population measured hours earlier, and written into a
comment as justification. By the time it executed there were **26** rows,
twelve of them from a real person whose username resolves to a `users` row.
The classification was not merely stale; it recorded twelve real human actions
as unattributable, in the column built to make attribution possible.

The error is not the figure. It is the shape: a migration is written at one
moment and run at another, by definition, against whatever the table holds
*then*. The same applies to a backfill, a data fix, a one-off script, and any
constant derived from a census.

**The pattern, from migration 066:**

- **resolve, don't assert** — `UPDATE … FROM users WHERE u.username =
  t.actor_recorded`, so the answer comes from the data at execution time;
- **promote only** — a row already resolved stays resolved;
- **never demote** — and `downgrade()` is deliberately empty, because
  reversing it would assert an actor cannot be matched when the migration has
  just demonstrated it can. A false claim written by a rollback is still a
  false claim.

Re-runnable by construction, which is the test of it: if running it twice
changes anything the second time, it was asserting rather than resolving.

Related: rule 16 (name the other world), and the measurement rules — a
population is a measurement and carries a time, like any other.

### Rule 18 — a field you did not read is a field that does not exist

One line, beside its guard, which is the deliverable:
`app/services/investigation_step_render.py` **refuses** to render a template
slot whose field is absent from the payload. Absent is `check_failed` with the
key named, like every other absence here.

Distinct from rule 16's family. `queryName` and `data_domains` are real fields
that mean something else, and the remedy there is checking the producer.
`filename`, `selected_count` and `final_risk.verdict` **do not exist at all** —
no misleading source, no source: code written against an imagined interface.
What made it render plausibly every time was `.get()` returning `None` into a
slot that formats it, so the silence was the language's, not the data's.

And it is a guard rather than a rule because a rule was tried. The
pluralisation helper existed, was declared, had a test — and the first producer
written against it built the phrase with an f-string and shipped
"1 attachments". A rule is advice. The renderer is where it holds.

### Rule 19 — list the keys before writing a predicate against a payload

**Don't check carefully. List.** Before writing any predicate, filter, template
slot or presence test against a payload, enumerate that payload's keys —
`jsonb_object_keys`, `jsonb_each_text`, `sorted(d.keys())`, whatever the store
offers.

The reason is not diligence, it is that **care does not help.** A check written
against a guessed field *inherits the guess*, so no amount of rigour in the
predicate escapes it. That is not a hypothesis:

| # | the guess | what it did |
|---|---|---|
| 1 | `selected_count` (payload: `looked_up`) | rendered "0 worth checking" beside a step that asked six sources |
| 2 | `final_risk.verdict` (payload: `risk_level`) | rendered "no verdict" on a run with a verdict |
| 3 | `filename` (payload: `path`) | rendered "an unnamed file" for every file |
| 4 | `log_context.events` / `.logs` (payload has **neither**) | an emptiness check that reported "not empty" for all 2,833 rows — **inside the query written to catch #3** |

The fourth is the lesson. It was a *careful* check, written knowing about the
first three, and it inherited a new guess and failed silently. What broke the
loop was not a better predicate — it was running `jsonb_object_keys` and
reading the fourteen keys that are actually there.

One listing would have prevented all four, at a cost lower than any single one
of the checks that didn't. It is three seconds of query.

#### Enumerate until you reach scalars

"List the keys" is not the whole rule, because a listing can stop one level too
early and the stop is itself a guess. **Every stopping point above a scalar is
an assumption about the level below it** — which is exactly what this rule
exists to forbid. So descend: keys, then each value's *type*, then, for a
container, the shape of its elements, until what you are looking at is a
number, a string, a boolean or a null.

Three instances in one day, each one level deeper than the last:

| level | the stop | what it asserted | what was there |
|---|---|---|---|
| container vs value | `log_context` is present | "100% have log context" | the object was present on 2,833 of 2,833; 695 held no logs |
| value vs non-empty | the key exists and is not SQL `NULL` | "400/400 present" | `-> 'key' IS NOT NULL` is **true for a JSON `null`**; `jsonb_typeof(...)` is the question |
| dict keys vs element shape | `attack_assessment`'s keys listed, `techniques` among them | `listing(techniques)` would name techniques | `techniques` is a list of **objects**; it rendered raw dicts on the page |

The third is the one that shows the rule needs the clause. The section's keys
*were* enumerated, deliberately and under this rule — and the enumeration
stopped at the name `techniques` without asking what one element of it looks
like. `[type(x) for x in value[:3]]` is the same three seconds as the listing
above it.

#### Every predicate needs a positive control

Enumerating the keys tells you the field exists. It does not tell you that
your comparison can match anything. So **the same predicate, with a value
known to be present, must return non-zero** — and until it has, a zero is a
statement about the comparison rather than about the data.

This was already established for one API and then not applied to SQL. The
Falcon alert field control exists because the Alerts API answers an unknown
field name with HTTP 200 and zero rows, so a negative is meaningful only while
a positive control passes. That is not a Falcon practice. It is a predicate
practice, and the next instance was a hand-written SQL query with no control
at all: seven columns compared to a user's uuid, **0 in every one**, when the
answer in one of them was 5. Four of the seven hold a *name*; comparing them
to a uuid cannot match, and the uniform zero was the shape of the comparison.

**A uniform zero across heterogeneous code paths is itself the signal.** Seven
columns, written by seven different features, at different times, by different
people, agreeing perfectly — perfect agreement between things with nothing in
common is almost always a property of the comparison. Suspect the predicate
before believing the result. (Rule 20's instances are the same idea one layer
up: a declaration agreeing with itself.)

**Two concerns, and merging them produces the bug it was meant to fix.**

| the question | answered from | never from |
|---|---|---|
| does this field name mean anything to the API? | **`total`** — known-present ≥ 1, nonsense 0 | page contents |
| did I see what I am about to reason over? | returned count against `total`, plus a deterministic sort | the first page alone |

The first draft of this clause said a known-present value must return *"the
row you took it from"*. That merges the two, and **it fails on every correct
field whose hit set exceeds the limit** — which is the normal case:
`sha256:'<a real digest>'` returns 5 rows of `total: 771`, and the sampled row
is not among them. A control written that way condemns a field that
demonstrably works. `alerts_field_control` already had this right by passing
on `total > 0`, and the proposed "fix" would have broken it.

So the pass condition is `total > 0`, and the part still missing is the
**nonsense value**: a value that cannot exist must return `total: 0`. That is
the only check that catches a field name which is *accepted and ignored* —
one that returns rows for anything, passing a known-present check while every
negative from it is meaningless. No Falcon field behaves that way today
(`behaviors.sha256` with a real digest returns 0 of 0), which is a measured
property of the provider and not a thing to rely on for free.

#### The four axes, as a set

Assembled one axis at a time over a single day, each from a different live
defect, so they are written as a set rather than discovered again:

| # | question | answered by | the defect it caught |
|---|---|---|---|
| 1 | Does the field name mean anything? | `total ≥ 1` on a **known-present** value | `behaviors.sha256` — 200 with zero rows for every hash |
| 2 | Is the filter actually applied? | a **nonsense** value returns `total = 0` | the hazard a field accepted-and-ignored would pose |
| 3 | Did I see everything? | returned count against `total`, **with a sort** | `limit: 20` of 29, both confirmed records outside the page |
| 4 | Can it match the kind of value I will pass? | a reference value of **external provenance**, plus variance in the field's own distribution | `sha1` — forty zeros on 1,953 of 1,953 |

**Axis 4 is the one that is not a patch.** The control sampled its test value
*from the API's own response*, so it filtered the sentinel against itself and
got 1,953 rows. **It verified a round trip, not a capability.** A control whose
reference value is drawn from the system under test inherits that system's
defects.

Variance catches the degenerate case — one distinct value is trivially
satisfied — but the general fix is **provenance**: the reference value comes
from outside. Hash a file you hold, or take a digest from a public corpus, and
confirm the field matches a *real* value of that kind rather than its own
echo. That also catches what variance cannot: a field whose values are
plentiful and varied but drawn from a **different namespace** than the thing
you will pass it.

Rule 21 owns axis 3.

#### A discriminator must differ between the states it claims to separate

The general form, and it is cheap to check before trusting any check: **ask
what each candidate state would produce, and if two of them produce the same
observation, the check is not a discriminator for those two.**

An HTTP 404 was read as "this endpoint is gone, so there is no corroborating
resource". But `/incidents/queries/incidents/v1` returns a body *identical in
shape* to a deliberately nonsense path — a generic `"Not Found: Please provide
trace-id"` with no scope message. Unscoped, not-available-on-this-cloud, and
never-existed all produce the same bytes. So the 404 separates **none** of
them, and the honest kind is `check_failed`: not shown unavailable, merely not
reached.

This is the absence convention applied to a status code rather than a value,
and it is the same test that killed the nonsense-value question in one call:
name the candidate states, then find the observation that differs between
them. The 319 open alerts were left indeterminate by exactly this test — every
`epp` alert is closed and every `automated-lead` alert is open, so "written at
triage" and "a property of the product" produce identical observations here
and the cells that would separate them are empty.

And: **`ORDER BY created_at DESC LIMIT 1` without a unique tiebreaker returns
a different row each run.** Two consecutive reads of "the latest" gave
different payloads, and reading a shape from one row while templating against
another would have left no trace in the output. Add the primary key to every
such ordering.

See rule 18 for the guard that stops a guessed field *rendering*; this rule is
upstream of it and cheaper.

### Rule 20 — check the layer that acts, not the layer that answers

**A check is only evidence about the layer it interrogates.** Ask the component
that *answers conveniently* and you learn about that component; the work is
being done somewhere else, and that somewhere else is what the claim was about.

Three instances in two days, in three unrelated domains:

| # | the check asked | the work was done by | what the check missed |
|---|---|---|---|
| 1 | the **api** container, over HTTP | the **worker**, which runs the task | the worker was 4 commits behind; the api answered for itself and was read as answering for the deployment |
| 2 | the **fingerprint on disk**, by hashing files | the **socket**, serving an already-imported module | committed code was 404ing for three hours while disk and git agreed it was there |
| 3 | the **template registry**, which the author writes to | the **page**, which renders | eight templates the registry certified could not render at all; `Boolean(absence_kind)` discarded their sentences |

The shape, stated so the fourth one is recognisable: **the registry, the
manifest, the config, the repository and the disk are all declarations of
intent. The socket, the worker, the renderer and the query planner are what
act.** A declaration agreeing with itself is not a measurement. When the two
layers can disagree — and they can whenever one is loaded, cached, deployed,
projected or rendered from the other — the only check worth the name goes
through the acting layer.

It is cheap to get right and the fix is always the same: route the check
through the thing that does the work. `liveness.sh` fingerprints the worker
over its own socket *and* diffs serving-against-disk because of #1 and #2;
`presentation_of()` lives beside the renderer, with the page switching on its
output, because of #3.

**It is a reflex, not a fact you can learn once.** The fourth instance was
written *the same day as this rule*: a call counter patched onto
`httpx.Client.send`, reporting **0 Falcon calls** for work that plainly
happened, because `falcon_client` imports `requests`. The instrument was the
declaring layer and the provider was the acting one. Knowing the rule did not
help; asking "which layer am I actually touching?" before trusting the number
is the only thing that does.

**And the acting layer is sometimes *poorer*, not just different.** The fifth
instance inverts the first four. E1 in the escalation spec was drafted against
a corpus paged by hand from `/alerts/entities/alerts/v2` — 112 keys per
record, `status`, `resolution`, dispositions, everything. The acting layer,
`falcon.lookup`, reads the *queries* endpoint and returns dicts with **one
key, `id`**. Nothing was inconsistent; the product simply cannot do what my
hand-run query could.

So: **a predicate drafted against data you obtained by hand is a predicate
drafted against a capability the product does not have.** Investigating with
ad-hoc queries is right, and the shape they return is not evidence about what
the code path returns. Before building on a shape, get it from the function
the feature will call.

**And before any of that: establish that the component exists.** The same day,
from the other side, a diagnosis ran three paragraphs on "our collector
stalled — check its cursor, its last run, whether the worker was recreated".
There is no collector. One `grep` for a Falcon task settled what had been
built on top of an inferred component: Falcon is queried live, there is no
ingest path, no beat entry and no table. The hypothesis had *existence* fifth
in a list of behaviours, when existence is the only question whose answer
makes the other four meaningful.

Both failures are one rule in two directions — **reasoning about an
architecture nobody verified.** One assumed a *richer* layer than exists; the
other assumed a layer at all. So the order is fixed: does this component
exist, then what does it return, then how does it behave. A `grep` and a
`\dt` are cheaper than any paragraph written about an imagined one.

Three corollaries worth naming, because all three have bitten:

- **Presence in a registry is not reachability.** "Every declared kind has a
  template" passed throughout, while certifying eight that nothing could
  reach. A registry answers *is it declared*, never *does it run*.
- **A parse or aggregation that found nothing makes every assertion over it
  pass.** The `ast` walk that replaced a hand-kept list of eight kinds is the
  right correction — but an empty walk would have made every test over it
  succeed by asserting nothing, so it asserts its own non-emptiness first.
  Same family as a zero-shard aggregation read as agreement: the acting layer
  returned nothing and silence was scored as a pass. See
  `docs/problems/container-defaults-erase-absence.md` for the collection of
  these — an instrument whose absence reads as a value.
- **A test may pin a decision; it must not pin the decision's *reason*.** A
  refusal has an identity — *we do not ask Falcon about domains* — and a
  justification, which is a claim about the world. The test never measured the
  world, so pinning the justification makes it an authority on something it
  cannot see. One did: it asserted the literal sentence *"no alert field that
  holds a domain"*, which was measured **false** on 2026-10-16, and the test
  had been certifying it for weeks. It now pins the refusal's kind, its
  reading, and that the reason still says nothing was searched — plus a guard
  that the falsified sentence cannot return. This is the third kind of
  certified-wrong-thing after the registry that certified unreachable
  templates and the `all("None" in line)` check that passed on every input.

### Rule 21 — a bounded read without a deterministic order is a sample, not an answer

**Any `limit` without a `sort`, and without reading the available total, is a
claim about what you did not see.** Four instances, and the fourth was my own
control written to catch the second:

| # | the read | what it concluded | what was there |
|---|---|---|---|
| 1 | `ORDER BY created_at DESC LIMIT 1`, no tiebreaker | "the latest row" | a *different* row on consecutive runs; ties, no unique key |
| 2 | `limit: 20` on a hash's Falcon alerts | `true_positive` → **False** | 29 alerts, **2 confirmed**, both outside the page |
| 3 | `limit: 5` filtering on a sampled `dns_requests.domain_name` | "the field is ignored, the filter returns an arbitrary page" | `total: 6` — the source row was the sixth. **The field filters correctly.** |
| 4 | `limit: 5` on `sha256`, in the same run as #3 | would have condemned `sha256` too | `total: 771`; a field known to work, failing the same way |

#3 is the one worth keeping. It produced a confident, specific, wrong
diagnosis — *a non-filterable field returning an arbitrary page* — which would
have put a hole in the whole field-control framework, and it was wrong because
five rows of six were read without a sort and without the total. #4 is its
control: the same method condemns a field that demonstrably works.

**The total is free.** `meta.pagination.total` comes back in the *same
response* as the rows. The floor was always detectable and was simply not
read. So:

* `sort` deterministically, always, so the same read twice is the same answer;
* read the total, and when `total > len(rows)` the result is a `lower_bound`,
  never a negative;
* page until the population is covered when the question is "is there *any*".

An existence question is the dangerous one: "is there any confirmed detection"
is answered by the *population*, and a page cannot answer it unless the page
is the population. That is exactly how a hash an analyst had twice confirmed
came back as having no confirmed detections.

See rule 19's positive-control clause for the other half — the one that checks
a predicate can match at all, from `total`. This one checks that what you
*read* is everything, from the count against that same total. The two
questions share a response and must not share an assertion.

#### Put it in a signature, not a habit

Rules 19, 20 and 21 are habits, and **habits are being written faster than
they change.** Two instances in one session, both of them a *fix* inheriting
the habit rather than the lesson:

* the call counter fell to rule 20 **the day rule 20 was written**, and
* the paging control fell to rule 21 **while being written to catch rule 21.**

Documentation is not the mechanism for closing that gap. **Whatever can be
moved into a signature should be.** A paging helper that returns
`(rows, total, complete)` instead of a list means a caller *cannot not know*
it read a page — the same thing `search_all` → `_page` already does for
OpenSearch, which is why no OpenSearch read in this codebase has made this
mistake. A rule a caller has to remember is a rule that holds until the next
fix is written in a hurry.

### Rule 22 — a warrant states what it does not cover

A **warrant** is the sentence this platform attaches to an answer to say why
the answer can be trusted: *this field spans the full retention window, 2.6
million documents across 190 hosts.* Warrants are load-bearing for the whole
credibility story — the point of them is that a number without one is not
evidence.

**Which is why a warrant that can co-sign a wrong answer is worse than no
warrant at all.** On 2026-10-16 a tenant pin was set to a plausible wrong
value. The query returned zero documents, and the answer carried that coverage
warrant beside it. Every word of it was **true**, and none of it was about
whether the *filter* had selected anything. So the reader got a confident
negative with a coverage guarantee attached, and adding warrants
systematically raises confidence in exactly the cases that deserve less.

It is rule 20 at a seam nobody had looked at: **the warrant interrogated the
field, which answers about itself, and not the filter, which acts.**

So every warrant carries a scope clause, and if the warrant is rendered next
to a verdict, its boundary is rendered with it:

> This says the FIELD holds data across the window. It says nothing about
> whether this query's filters — the tenant pin included — selected the right
> documents. A zero here is only a negative if the pin resolved.

### Rule 23 — record what a read path returns before you change it

**Before touching a read path, record what it currently returns as counts.
After the change, diff.** Three lines, no new tooling, and it fits the
measurements-print-aggregates rule unchanged — counts and distributions, never
payloads.

This is the only control that has caught a **coverage regression**. The
Falcon paging helper was written to stop bounded reads being read as answers;
in writing it, `want=500` was clamped to one page, and the host panel silently
dropped from 500 detections to **200**. Nothing failed. No test broke. The
numbers were internally consistent, `complete: False` was correctly reported,
and the helper was being honest about a page that was now 300 rows shorter
than the day before. It was caught by comparing against a figure recorded
before the change and nothing else.

Every other control here catches a *bug*: a wrong value, an exception, a
failing assertion. A coverage reduction has none of those symptoms — the code
is correct, the output is well-formed, and only its *size* changed. That is
invisible to tests, to types and to review, and visible in a diff of two
numbers.

So: `{rows: 500, groups: 9, hosts: 2}` before, the same after, and look at
them side by side. The before-figure is also what makes the after-figure
interpretable at all.

### Rule 24 — resolve a corpus's subjects before analysing it

**Whose hosts, whose users, whose tenant.** Two queries, before the first
aggregate.

This rule is the cost of three reframings of one document in two days, each
produced by resolving an identifier that had been carried as a label:

| framing | what it rested on | what resolved it |
|---|---|---|
| "a customer's estate has gone quiet" | the file's location in `docs/outbound/` | — |
| "the untriaged queue is our service gap" | — | `assigned_to_name` → our own `users` table |
| "the estate and the analysts are both ours" | — | device `machine_domain` → `*.expertware.net`, 182 of 182 |

Nobody resolved an identifier until two days in. Every intervening conclusion
was sound reasoning over an unestablished subject, which is rule 20's
existence clause applied to the subject of a report rather than to a
component — and the audience is the part that goes wrong silently, because a
document inherits it from where the file was filed.

**The audience of a finding is something to measure, not something to
inherit.** So:

* names in a payload are resolved against `users` before they are described;
* hostnames are resolved against a domain or an asset inventory before an
  estate is characterised;
* a tenant id is resolved to an organisation before a document is addressed
  to one.

The same two queries also catch the thing rule 16's concentration check is
for: resolving 182 hostnames is what revealed that one of them was 70% of the
corpus.

### Rule 25 — a retraction has to be total

**A claim has copies, so correcting it means correcting all of them.** When a
rule or a reason changes, enumerate everywhere it lives — README, memory,
spec prose, test fixtures, code comments, commit history you can still
amend — and fix every copy, **because the uncorrected copy is the one that
gets cited.**

Two instances in one day, and they are the same shape:

| the retracted claim | the stale copy | how it would have resurfaced |
|---|---|---|
| "no Falcon alert field holds a domain" — measured false | a **test** asserting the literal sentence | the test certified the false reason for weeks, and would have blocked the correction |
| "a control must return the row you took the value from" — reproduces the bug it fixes | a **memory file** still carrying the merged formulation | it would have been recalled in a later session as current guidance |

The test case is the more dangerous of the two, because a stale assertion does
not merely sit there: it actively defends the retracted claim against the
correction. The memory case is the more insidious, because nothing in the
repository contradicts it and it comes back wearing the authority of a
considered note.

Hence the companion rule already in place: **a test may pin a decision, never
the decision's reason** (rule 20's third corollary). A reason with no copies
cannot go stale.

Practically, when something is retracted: `grep` the claim's distinctive
phrase across the repo and the memory directory, not just the file you were
editing. Two of today's three retractions had a copy somewhere else, and the
phrase was the thing that found it.
