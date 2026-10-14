# Backlog

Written down rather than carried in anyone's head. Each item has the
measurement that justifies it, so the next person does not re-derive it.

Opened 2026-10-14, at the close of the ThreatFox / intel-collector /
brand-rule pass.

---

## 1. Brand-rule replacement

**State:** signal disabled (`BRAND_REFERENCE_SIGNAL_ENABLED`, default off).
Nothing is scored on it. The replacement is not built.

**Why it is not just "fix the ownership test":** the test is inverted in its
*use*. `paypal-secure-login-update-account.xyz` contains "paypal", so the old
rule concluded PayPal owned it and skipped — while *"contains the brand word
and isn't the brand's"* is the detection worth having. The condition used to
exclude is the condition that should include.

**Order, decided on the measurements:**

1. **Rendered text or form action, not the raw body.** The only option
   needing no list at all, and it removes two-thirds of the signal outright:
   984 of 1,085 Google flags co-occur with a Google/gstatic external
   resource, i.e. they are `<script src>` hits.
2. **Split "mentions a brand" from "imitates a brand".** One field currently
   carries two claims and only one is a detection. Do this regardless of (1).
3. **Ownership from evidence already collected** — `hosting.asn_org` reads
   `Microsoft Corporation` for `live.com`; TLS SANs; WHOIS registrant — with
   a mandatory third state. Anything behind a CDN reads `Cloudflare`, so "no
   evidence of ownership" must mean **unknown**, never *not-owned*, or the
   same inversion returns wearing better evidence.

**Constraint:** it must not be a ninth hand-maintained list.
`test_brand_reference_signal.py` fails if a `BRAND_OWNERS` or
`OWNED_DOMAINS` list appears.

Evidence: `docs/problems/the-brand-rule-flags-the-brand.md`.

---

## 2. VirusTotal rate-limit clustering

**Measured:** 201 of 2,218 runs (9.1%) failed with "rate limit exceeded on
all configured keys". They occupy **20 of 431 active hours**, and 199 fall on
2026-09-15 and 2026-09-16 — the two busiest days in the 90-day window, at
2.2× and 2.8× the third-busiest. Whole hours are total losses: 21/21, 20/20,
18/18, 17/17, 15/15.

**Why it matters:** `vt_malicious >= 5` leads the escalation clause.
VirusTotal is the heaviest term in the ladder and the one most likely to be
absent when volume is highest, so anyone able to generate volume degrades the
platform's primary enrichment as a side effect.

**Cost measured:** 201 extra `suspicious / investigate` verdicts on the two
busiest days — analyst load, not missed detections, because
`observable_clean` requires `vt_found`.

**Open decisions, neither taken:**
- should the answer-rate denominator exclude collector failures? Today
  `virustotal` reads 100% answered with 203 collector-failed beside it;
- should a run that lost VirusTotal be re-queued rather than concluded? 201
  cases were decided on a partial evidence set and recorded as finished.

**Status:** dormant since 2026-09-17. Load-dependent, so it recurs at the
next burst and nothing fires during one.

Evidence: `docs/problems/virustotal-fails-when-volume-peaks.md`.

---

## 3. The Pydantic-default five

**Measured:** 198 distinct field names across 68 models default to an empty
container, which makes "found nothing" and "nobody looked" the same bytes
before the data reaches storage. **That list is not the work list** — most are
outputs where empty genuinely means none produced.

The criterion: *an emptiness that claims an external source answered, read
where absence grants leniency.* That gives **four**, after the ANY.RUN grain
split removed one:

| source | read as | the "was it asked" record | consumed? |
|---|---|---|---|
| phishtank | `not phishtank_positive` | in `feeds_checked`, 98.3% of rows | **no** |
| openphish | `not openphish_listed` | in `feeds_checked`, 98.3% | **no** |
| urlscan | `not urlscan_malicious` | `urlscan.meta.status`, 98.3% completed | **no** |
| http signals | `not high_conf_http` | `http.reachable` 84.1%, `meta.status` 97.9% | **no** |

For all four the flag **already exists and nothing reads it** — the same
finding as ThreatFox and the intel collector. The fix is consuming a field
that is already written, not new plumbing.

Pattern to apply: the Google Safe Browsing shape (`checked and not listed`),
or `None` plus a named `Absent`. **Do not** convert 198 defaults.

Evidence: `docs/problems/container-defaults-erase-absence.md`.

---

## 4. The change-detection limb for the answer-rate check

**Why:** an absolute floor cannot catch a decline. `intel_blocklists` went
21.5% → 0 and `threatfox` 11.7% → 0 without crossing any threshold, and
`otx` currently reads **23.3%** — a partial failure no floor will flag.

**What exists:** `source_answer_rate_service` now reports `never_answered`,
`never_asked`, `never_present` and `collectors_not_covered`. All four are
absolute.

**What is missing:** a comparison against the source's own recent history, so
a source halving is a finding even while it still answers. The shadow-first
rule applies — report before alarming, and take the threshold from a week of
the check's own output rather than picking one.

---

## 5. The three outbound documents

In `docs/outbound/`, each with a named owner and **no channel to send it**.
This platform has no outbound mechanism, so they need carrying by hand.

| document | to | ask |
|---|---|---|
| `grupobiopar-now-listed.md` | SOC analyst on duty | look at the domain again; and decide whether a concluded verdict reopens when a feed lists its subject afterwards |
| `technique-disagreements.md` | detection-content owners | 488 ATT&CK disagreements |
| `silent-endpoints.md` | Wazuh / endpoint-agent owners | which of Tier A are decommissioned and which are broken |

Closing the gap itself — an outbound channel — is the larger item behind
these three.

---

## 6. Phase 3: cross-case pivots

**Measured 2026-10-14** — `docs/design/phase-3-ioc-prevalence-recon.md`. The
ceiling is no longer unscoped, and the blocker is not the one it was thought
to be.

* `ioc_values` is a `text[]` **column** on `alert_body_investigation_runs`,
  per run. `UBIQUITY_HOST_LIMIT = 10` is at **host** grain for *within*-case
  linkage and does not answer the cross-case question.
* Case grain, deduped: **85.7% of indicators appear in exactly one case**;
  p95 = 3, **p99 = 17**, max = 778 (`expertware.net`). The head is a schema
  URL, a version string parsed as an IP, an all-zero hash and the client's
  own domain.
* **The blocker is the run→case link, not the index.** A GIN index is 1.4 MB
  and 215 ms and makes a selective pivot 180× faster. But runs carry no
  `case_key`, and the derived join **fans out 90.8% of runs** because 2,044
  spine rows have overlapping session windows — a pivot built on it would
  report case counts 2.3× too high.
* Threshold, from the distribution rather than chosen: **fewer than 17
  cases**, with the prevalence shown beside every pivot.

**The tail decomposes into three causes and only one is prevalence.** 15
values of 2,114 carry 23.8% of all case-pairs: tenant identity
(`expertware.net`, 782 cases), version-strings-as-addresses, schema URLs and
a degenerate hash. Extraction defects must be **quarantined at extraction**,
not hidden by a threshold — a threshold that hides them guarantees they are
never found. Tenant identity is a profile exclusion derived from
`clients.domain`/`aliases`, true for every tenant onboarded.

Removing them moves the threshold barely (p99 17 → 16) but the head
massively (max 778 → 85): the defects are few and huge, and percentiles are
insensitive to a handful of extremes.

**New defect found by the decomposition:** 96 stored values of the form
`::ffff:N` and **zero** full IPv4-mapped addresses — every one truncated at
the first dot (`::ffff:192.168.1.1` → `::ffff:192`). Tenth delimiter-boundary
instance, and a prevalence threshold would have cut all four silently.

**The structural half is done** —
`app/services/ioc_conformance_service.py` and
`docs/problems/stored-values-that-do-not-parse.md`. One check over the
corpus, replacing an indefinite series of discoveries: 103 nonconforming
values in `iocs` and 17 in `ioc_values`, including four classes nobody had
named (IPv6 stored as a domain, values carrying their own `cert_sha256:`
prefix, a TLS subject DN as a domain, an mDNS address as a hash).

**The semantic half needs field provenance, per format.** `6.0.4.27` is a
valid public IPv4 address and `http://schemas.microsoft.com/...` is a
well-formed URL — both conform structurally. But measured against the real
bodies, both are definitionally attributable:

* `6.0.4.27` — **97 of 97 bodies** have it in **CEF field 4**, which the
  format defines as Device Version;
* the schema URL — **391 of 392** inside an `xmlns=` attribute.

So the work is per-format field extraction (CEF by position, Windows Event
XML by `Data Name=`, JSON by key, label prose by label), not one heuristic.
A nearest-preceding-key rule was measured and **misattributes both** —
`detailEntry` and `errorNumber`, adjacent keys from other log lines — so it
must refuse rather than guess.

**The limit is much narrower than first written.** Censused properly — each
of 16,969 bodies classified once, most-specific shape first, so shares sum
to 100%:

| shape | share | | shape | share |
|---|---|---|---|---|
| `Label: value` single space | **43.5%** | | Windows Event XML | 1.7% |
| embedded JSON keys | 31.1% | | **CEF** | 1.5% |
| bare `key=value` | **15.9%** | | JSON object | 1.0% |
| `Label:  value` prose | 4.8% | | syslog 3164 / 5424 | 0.4% |
| | | | **unclassified** | **0.1% (10)** |

**99.9% of bodies have a parseable shape.** The earlier "55.6% free text"
was an artefact of overlapping counts plus only testing four patterns; the
remainder was label-value-single-space and bare `key=value`. Of the 10 that
remain, most are double-escaped JSON. So the outstanding work is **parsers
for nine shapes, not four** — a different and better problem than "the
majority is unreachable".

`app/services/cef_header_service.py` is the first, with the escaped-pipe
guard (eleventh delimiter instance, 0 of 257 bodies affected today, caught
before it was live).

Next: quarantine the extraction defects at entry (the same predicate, the
other consumer), add the tenant-identity exclusion,
resolve the overlapping-session question, then store the run→case link, then
the index.

---

## 7. Tenant scoping is exercised by nobody — before the second tenant

**Trigger condition, not a date: before a second real tenant is onboarded.**

All 28 users have `all_tenants = true` and `tenant_ids = []`. Tenant scoping
exists in the schema, has a service (`app/services/tenant_scope.py`), is
applied by every alert-run read and every integrations read — and no
principal is actually restricted by it.

Today that is harmless: there is one tenant, so an unfiltered query and a
filtered one return the same rows. **The day a second tenant exists, every
one of those 28 accounts can see it**, and nothing in the system will say so
because no test and no user exercises the restriction.

What closing it means: at least one real principal with
`all_tenants = false` and a non-empty `tenant_ids`, reading the product
through the UI. Until then the only thing standing between the design and a
cross-tenant read is
`backend/tests/unit/test_security/test_integration_isolation.py`, which
constructs a restricted principal precisely because nothing else does.

---

## 8. No credential in this system has an expiry check

**From the Spamhaus forensics, 2026-10-14.** The stored
`SPAMHAUS_SIA_TOKEN` is a JWT whose `exp` claim decodes to
**2026-05-12T11:23:24Z** — the same day the SIA step was committed. The
collector then failed on 2,198 consecutive runs for 98 days.

The expiry was **in the token, in the database, readable, and nothing read
it.** Same shape as `meta.status`, `feeds_skipped` and `sources_checked`: the
information was there and no consumer existed.

**Partly done, 2026-10-14.** `app/services/credential_expiry_service.py` is
the central register the Falcon integration reports its OAuth token expiry
to. What remains is every *other* credential this platform holds —
`.env`-based provider keys with no expiry visible, and the Spamhaus SIA token
itself, which is still expired.

**Natural home:** `source_answer_rate_service`, which already distinguishes
*never answered* from *never asked* from *never present*. An expired
credential is a fourth category and the one that is fixable before it bites —
a JWT's `exp` is readable without calling the provider, so this costs one
decode per configured credential and no requests.

Scope: every credential this platform holds that carries a decodable expiry.
Report, do not alarm, and do not log any part of a credential.

Evidence: the addendum in
`docs/problems/the-intel-collector-was-dead-for-98-days.md`.

---

## 9. Falcon ingest, and what it brings with it

Enrichment shipped 2026-10-14. Ingest did not, and deliberately:

* **`_create_alert_run` must be extracted** from
  `app/api/alert_investigations.py` into a service first. Five endpoints
  funnel through it, it is a private function in an API module, and a Celery
  poller would be a sixth caller importing from the API layer.
* **A Falcon field map**, where unmapped fields are quarantined as
  `no_field_map` and never inferred.
* **Falcon's MITRE attributions are a third technique namer** and must not
  quietly join `rule_only`.
* **The tenant does not reach an investigation yet** — see
  `docs/design/integrations.md`. `spawn_investigation` accepts it;
  `alert_body_investigation_service` never sees it.
* And **the Alerts API accepts unknown FQL field names silently** (measured:
  twelve fields including an invented one, all HTTP 200 with zero
  resources). A wrong field reads as "the EDR has nothing" for ever.

  **Standing defence, not a note:** for every third-party query field this
  platform relies on, assert once against the live tenant that the field
  *can* return a non-empty result. A field that has never returned anything
  is indistinguishable from a field that does not exist, and the difference
  is a detection nobody will ever see. One query per field, on configuration
  or on a schedule. The answer-rate registration is a backstop measured in
  weeks; this is the check measured in seconds.

---

## 10. The estate lookup: two standing absences

From the OpenSearch recon (`docs/design/phase-3-ioc-prevalence-recon.md`).
Both are **absences to report, not gaps to paper over**:

* **No proxy logs anywhere.** `data.proxy.url` and `data.http.url` are 0,
  and `data.url` comes from a single appliance. **The estate question cannot
  be answered at URL grain at all** — only domain (Sysmon DNS, 97.2% of
  hosts) and address (perimeter). A URL-grain lookup returns an absence
  naming this, never an empty result.
* **120-day retention**, oldest document 2026-06-16. Any case older returns
  **unknown**, never *no contact*. A backfill treating an aged-out window as
  clean reproduces the seven-month feed bug by a different mechanism.

And a design rule for the lookup itself: **`queryName` and `dstip` answer
different questions and must never be merged.** A host resolving a domain and
the perimeter seeing an address are distinct facts; the 2.07bn-to-2.6M
document ratio is the gravity well that makes them look like one. A perimeter
hit with no corresponding host query is interesting in its own right.

---

## Closed in this pass, recorded so they are not reopened

* **ThreatFox** — off. Measured benefit over seven months: **zero verdicts
  changed**; 25 of 25 knowable positives were already caught by other
  sources. Measured cost within two hours of the credential being restored:
  two `malicious/high/90/block` verdicts on Microsoft apexes. The query is a
  substring search, so granularity could not fix it.
* **The brand rule** — off, and the close is clean: **disabling cost zero
  detections** and fixed five false `malicious/82` verdicts
  (`googlebot.com`, `www.google.com/bot.html`,
  `www.apple.com/go/applebot`, a MITRE technique page, `otar.nl`). The
  control row is what makes the 833 a measurement rather than a number:
  **0 of 779 non-carriers moved.**
* **The intel collector** — 98 days dead from one unguarded credential call;
  guarded, with per-source `sources_checked`/`sources_skipped`.
* **Per-tenant integrations, enrichment** — tenant-keyed, five-state status
  derived rather than flagged, secrets encrypted and write-only with a
  rotation path, catalogue derived from the connectors, and CrowdStrike
  Falcon `verified_ok` against the live API. See
  `docs/design/integrations.md`.
* **Spamhaus** — not a credential problem. `login realm=intel` returns
  *"no subscriptions found"*; the ask is a **DQS** key, which also fixes the
  SURBL/DBL public-resolver refusals. An SIA subscription would only restore
  a field nothing reads.

## 11. `_ALIASES` reads one identity field where the corpus carries six

`alert_graph_extraction_service._ALIASES` maps `"User"` and nothing else from
the Windows identity labels. `Account Name`, `SAM Account Name`,
`Display Name`, `User Principal Name` and `Security ID` have no entry, so the
graph never reads them however well they parse. The **eighth** silent
registry: no error, the field is simply never read.

Measured: **4,805 account nodes (19.1% of 25,186)** sit on a body carrying an
unaliased identity label. Adding aliases would recover **554 substantive
values over 346 bodies** — 343 Security IDs, 106 account names, 105 account
domains (the other 91.5% of candidates are Windows' `-` placeholder and
recover nothing).

Not a parser change — a node-identity change. 343 of those are SIDs, and the
Account merge key is `account:sid:` when a SID is present, so adding the
alias would re-key nodes that currently fragment by username. That is a graph
re-materialisation with moving merge keys, so it needs its own before/after
measurement of which nodes merge, which split, and whether any analyst-facing
graph changes shape. Evidence:
[the-key-collapse-that-was-not-there.md](problems/the-key-collapse-that-was-not-there.md).
