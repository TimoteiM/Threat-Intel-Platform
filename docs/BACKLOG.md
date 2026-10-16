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

> **Two blockers, both to be settled before this is written, not during.**
> Each is cheap now and silent afterwards:
>
> * [15](#15-blocker-for-falcon-ingest-materialise_run-destroys-graphs-when-log_events-is-omitted)
>   — `materialise_run` replaces a run's rows, and omitting the optional
>   `log_events` turns a 307-entity graph into 3 while stamping it fresh. The
>   ingest pass materialises graphs for new runs and will be written against
>   the signature.
> * [12](#12-falcon-device_id--agent_id-as-merge-keys--decide-before-ingest-lands)
>   — `device_id` / `agent_id` are present on some host records and absent
>   from others, and a conditional merge key fragments identity rather than
>   consolidating it. Decide the resolution-table approach first.

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
registry: no error, the field is simply never read. **4,805 account nodes
(19.1% of 25,189)** sit on a body carrying an unaliased identity label.

### Do not implement it as an alias. The prediction says it makes things worse.

The merge count was named before building, because re-keying by SID collapses
identities that fragment by username and a falling node count reads as data
loss to anyone who did not predict it. **The count does not fall. It rises.**

| | distinct account merge keys |
|---|---|
| now | 756 |
| projected under the alias | **763** |
| predicted change | **+7, not a fall** |

Of the 24 rows the alias would re-key, the outcome is exactly even:

| outcome | rows | share |
|---|---|---|
| **SPLIT** — brand-new SID key, siblings stay on the username | 12 | 50.0% |
| MERGE — the SID key already exists | 12 | 50.0% |

The splits are the damage. `account:povgrp\did24` holds 7 rows; the alias
moves one of them to a SID key and leaves 6 behind, so one human becomes two
nodes. **Whether a row gets a SID key depends on whether that row's own body
happened to carry the SID, not on who the account is** — so a partial SID
source fragments identity rather than consolidating it. Partial coverage is
worse here than none.

### Two traps the prediction surfaced, both load-bearing

**1. Most recovered `Security ID` values are not principals.** Of the
candidates the alias would read: **234 are `S-1-0-0`** (NULL SID — Windows'
way of writing *no principal*, so absence spelled as a value) and **49 are
`S-1-5-18`** (LOCAL SYSTEM — a role true of every actor operating through the
machine). Only **24 are individual domain principals**. The first pass of this
prediction excluded only NULL and ANONYMOUS and still produced
`account:sid:s-1-5-18` absorbing five distinct human accounts — `povgrp\c0109`,
`c0112`, `c0307`, `c0401`, `did09` — which is a tautological discriminator
used as an identity. Any implementation needs the well-known set excluded as a
**precondition**, not a refinement: `S-1-0-0`, `S-1-1-0`, `S-1-5-7`,
`S-1-5-11`, `S-1-5-18/19/20`, `S-1-5-113/114`, `S-1-5-32-*`, `S-1-16-*`.

This also corrects a number in
[the-key-collapse-that-was-not-there.md](problems/the-key-collapse-that-was-not-there.md):
the "343 Security IDs recovered" offered as the reason to do this work was
itself absence-as-value. 234 of them are the NULL SID. The honest figure is
**24**.

**2. `Security ID` is section-scoped, so the label alone is ambiguous.**
**235 bodies carry more than one distinct SID.** A Windows 4720 has
`Subject: Security ID: <admin>` followed by `New Account: Security ID: <the
account created>`; first-occurrence-wins returns the actor, not the subject of
the event. The label needs the enclosing section (`Subject`, `New Account`,
`Target Account`) to mean anything — which is the same structure the
absorption bug exposed, where `An account was successfully logged on.
Subject` became a mega-label holding the whole section.

### What the work actually is

Not an alias. A **SID ↔ username resolution table**, so every row for a known
account keys the same way whether or not its own body carried the SID. That
removes the fragmentation rather than redistributing it, and it is the only
version where the node count moves in the direction a consolidation should.
The 24 individual principals are the seed data for it, not the deliverable.

## 12. Falcon device_id / agent_id as merge keys — decide before ingest lands

Carried forward from the SID re-keying prediction, because it is the same
shape and it is about to recur.

**"Partial coverage is worse than none" applies to any merge key drawn from a
field only some records carry.** Re-keying account nodes by SID was projected
to *raise* the distinct-node count from 756 to 763, because whether a row got
a SID key depended on whether that row's own body carried the SID rather than
on who the account was: 12 merges and 12 splits, one human becoming two nodes.

Falcon ingest brings `device_id` and `agent_id`, which will be present on some
host records and absent from others — Wazuh-sourced host nodes will have
neither. Keying hosts on them where present and on hostname where not
reproduces the fragmentation exactly: the same machine becomes two nodes
depending on which source saw it.

**Decide before ingest lands, not after:**

1. Either key hosts on a resolution table (`device_id` ↔ hostname, populated
   from whichever source has both) so every row for a known host keys the
   same way — or key on hostname alone and carry `device_id` as an attribute.
2. Do not add a conditional key. That is the version the prediction killed.
3. State the expected node-count change before running the backfill, per
   [README rule on predicting a remediation's direction](../README.md).
4. Check the well-known-value trap: `device_id` values like `00000000-...`
   or a shared image's duplicated agent id are the `S-1-5-18` of this
   dataset — a value true of many hosts, which merges unrelated machines.

Evidence for the shape:
[the-key-collapse-that-was-not-there.md](problems/the-key-collapse-that-was-not-there.md)
and [backlog 11](#11-_aliases-reads-one-identity-field-where-the-corpus-carries-six).

## 13. ~~`liveness.sh` does not check the frontend~~ — DONE

The frontend limb is in. Filed and then done the same day, because it was the
third deployment-liveness gap this week after the api process and env drift,
and the pieces already existed asking a person to run the comparison by hand.

`next.config.js` hashes `src/**/*.{ts,tsx,js,jsx,css}` at build time into
`NEXT_PUBLIC_BUILD_FINGERPRINT`; the layout renders it as
`<meta name="x-build-fingerprint">`; `BuildStampClient` logs bundle-vs-html to
the console and says "compare with /health for the API". An instrument that
tells you to do the check yourself is one check short, so `liveness.sh` now
recomputes the source fingerprint and compares it to the meta tag the running
container serves.

The reproduction is byte-exact, proved rather than assumed: before the rebuild
the script said `frontend STALE`, after it `fe 281e1b30 in sync`, and the
recomputed value equals the served one character for character.

Six states verified with a stubbed harness, because absence must not read as
agreement in any of them: match → in sync (exit 0); mismatch on a clean tree →
`frontend STALE` (exit 1, the three-hour 404); mismatch on a dirty tree →
reported but exit 0, since that red cannot be cleared mid-edit; no build stamp
→ reported, since a page served without one is an old build; frontend
unreachable → reported; `src` unreadable → reported.

The first two harnesses silently failed to inject their variables, so the
branch each change existed for went unexercised while the other rows passed.
The stub generator now asserts its own injection landed.

## 14. The 14 tolerated failures have no premises

`docs/testing/tolerated-failures.txt` enumerates them, which stopped the set
growing silently. It did not establish that any of them *should* be tolerated,
and "the same 14, name for name" is quoted on every sign-off as though it had.

Per the README rule on exemptions, each entry needs a premise verified
independently of the check that cites it. What is known so far:

* ~27 errors across the 14, **24** of them
  `AttributeError: module 'app' has no attribute 'collectors' | 'db' | 'tasks'`
  — monkeypatch target resolution, i.e. a harness fault.
* **That grouping is not the whole set, and the first entry checked disproved
  it.** `test_dns.py::TestDNSCollector::test_empty_evidence_on_failure` fails
  on `assert 'completed' == 'failed'`: the DNS collector reports *completed*
  for a run that produced no evidence. That is absence-read-as-value — a
  candidate **live defect** being tolerated as a broken test.

The work: one pass over the 14, each classified as harness fault (fix the
patch target) or product defect (fix or file with evidence), with the premise
written beside it. Expect the two assertion failures and `'error' in
{'enabled'...}` to be the interesting ones; the 24 AttributeErrors are likely
one shared fix.

Start with the DNS one, because a collector reporting success for an empty
result is the exact shape that let ThreatFox and the intel collector sit dead
for months.

## 15. BLOCKER for Falcon ingest: `materialise_run` destroys graphs when `log_events` is omitted

Settled by measurement rather than by reading the docstring, which turned out
to be accurate: **`materialise_run` REPLACES a run's rows.** Called twice over
run `4bd69f04` it produced 307 entities / 290 edges both times, and the
transaction was rolled back so live data was untouched.

That also clears the interrupted sweep from 2026-10-14: `materialise_graphs`
commits **once after the whole batch**, so killing it mid-sweep rolls the
entire transaction back. No loss, no duplication. (My original claim that the
interruption was harmless was right for the wrong reason — I cited the
per-run delete, which is necessary but not sufficient; the batch-wide
transaction is what actually makes it safe.)

**The defect the measurement found instead.** The same call without
`log_events` produced **3 entities / 2 edges for the same run** — a 99%
reduction, committed as a replacement:

| call | entities | edges |
|---|---|---|
| as the sweep makes it (`log_events=logs`) | 307 | 290 |
| omitting `log_events` | **3** | **2** |

Replace semantics plus an argument that is optional (`log_events: Any = None`,
defaulting to `()`) and carries 99% of the content means **any caller that
forgets it silently destroys the graph it was asked to refresh.** No error, no
warning, and the run is stamped `graph_materialised_at` either way — so
afterwards it reads as freshly materialised and genuinely sparse.

### This is a prerequisite of the Falcon ingest pass, not a "soon"

"One real caller" is a fact about today, not about the design. The next caller
is **the Falcon ingest pass**, which materialises graphs for newly arriving
alert runs — and it will be written against the signature, under time
pressure, by someone who has no reason to read this docstring. The destructive
path is the *shorter* call: omit one optional argument and a 307-entity graph
becomes three, stamped `graph_materialised_at` as though it were fresh.

So this is not scheduled after the ingest pass or alongside it. **It is done
before the ingest pass is written**, because afterwards the damage is silent,
committed, and indistinguishable from a sparse alert.

The fix, in the order of preference the platform's own conventions imply:

1. **Raise when the run has an `alert_log_context` row the caller did not
   pass.** This is the right shape because it keeps "nobody passed logs"
   distinguishable from "this run has none" — the absence distinction this
   whole platform is built on, and the one a default of `()` erases.
2. Make `log_events` a required keyword, so the omission cannot compile past
   review. Weaker than (1): it makes forgetting hard rather than detectable,
   and says nothing about a caller who passes an empty list.

Do (1). (2) is a reasonable addition, not a substitute.

Cross-reference: [backlog 12](#12-falcon-device_id--agent_id-as-merge-keys--decide-before-ingest-lands)
is the other thing the ingest pass must not be written without. Both are the
same category — a decision that is cheap now and silent later.

## 16. CLOSED as unexplained: an intermittent graph-collapse failure, 1 in 9

`test_graph_extraction.py::test_identical_leaves_collapse_into_one_counted_node`
failed once in the full suite and has not reproduced. **Not a product defect
as far as measured** — the test is pure in-memory with fixed inputs.

Direction, which narrows it: `assert 11 == 12` on `member_count`, with
`len(accounts) == 1` and `attrs["group"] is True` both passing. So collapse
happened and **one of twelve evidence rows never became an account node** —
too few by exactly one, not over-merging and not a merge-key split.

Ruled out by measurement, not inspection:

* Not caused by the changes in that session — `git diff` showed the two files
  temporarily edited for drift tests restored clean.
* Not the new test files — passes with all three running ahead of it.
* Not hash ordering **in isolation** — 0 failures in 40 seeds.
* Not wall-clock — the fixture's `NOW` is a fixed `datetime`.
* Not a settings leak — `COLLAPSE_AT` is a module constant and no other test
  references it, `_collapse_siblings`, or the assembly service.
* Not parallel-worker redistribution — `pytest-xdist` is not installed, there
  is no `-n` option, and no `addopts` anywhere in the repo.
* Not reproducible at `tests/unit/test_services/` scope — 4 seeds, and the one
  failure there is `test_url_lexical_ml_service`, a baseline entry.

**Also ruled out: an identity-hashed object in a set.** This was the strongest
hypothesis, because `id()`-based hashing is not controlled by
`PYTHONHASHSEED`, varies with allocation history (i.e. with what ran before),
and would therefore be order-dependent, seed-independent and intermittent —
exactly the observed shape. It does not hold here, established by reading
every set construction in both files rather than by assuming:

* Every set in the assembly and extraction path is a **set of strings** —
  `inbound: dict[str, set[str]]`, `inbound: set[str]`, `self.unread: set[str]`,
  the technique-id comprehensions, `MAPPED_DECODERS`, `_NOT_A_MACHINE`.
* Every use of them is order-independent: `len()`, membership, or wrapped in
  `sorted()` (`sorted(kinds)`, `sorted(model_only - set(rule_ids))`).
* `Witness`, `AssembledNode`, `AssembledEdge` and the extraction `Edge` are
  plain `@dataclass` — so `eq=True, frozen=False`, which sets `__hash__ =
  None`. They are **unhashable**, so one entering a set raises `TypeError`
  rather than reordering silently.
* `_collapse_siblings` groups on `(source, kind, node.kind, marker)`, a tuple
  of strings, in an insertion-ordered dict.

**Observed rate: 1 failure in 5 full runs** (an earlier note said 1 in 3,
which was the figure after three runs). Two of those five pinned
`PYTHONHASHSEED` to 1 and 2 and passed, so seed-pinning has not produced a
reproducer either.

**Also ruled out: an elapsed-time or work budget.** The hypothesis was that a
loaded box truncates the run — which would fit "too few by exactly one"
precisely. `NOW` being a fixed datetime pins the *data's* clock and says
nothing about the *execution* clock, so this needed checking separately.
Grepped both files for `monotonic`, `perf_counter`, `time()`, `timeout`,
`deadline`, `budget`, `elapsed`: **none present.** Every cap in the path is
evaluated against input size, not time — `MAX_NODES = 150` only sets an
`over_cap` flag on the output, `MAX_LOG_EVENTS = 400` counts inputs, and the
`[:200]`/`[:80]`/`[:72]` are deterministic string truncations. There is no
budget for load to truncate.

**Two of my own explanations also died, and both were speculation rather than
measurement:**

* "The failing run was the only one not launched into a quiet box" — asserted,
  and with no time budget in the code there is no mechanism by which load
  could change the result.
* "I edited source files during that run" — checked against timestamps and
  false. The failing run executed 12:56:44→12:59:56; the two edits were
  12:55:21 and 12:55:55, both before it started.

**Observed rate: 1 failure in 9 full runs.** Seeds 1, 2 and 3 all passed with
`PYTHONHASHSEED` pinned, and two concurrent full suites both passed.

**A note on that concurrency attempt, because it is the kind of result that
gets miscounted as evidence.** Two simultaneous suites finished in 191.73s and
193.04s against a ~192s solo baseline — i.e. the box has 8 cores and two
single-threaded pytest processes produced **no contention at all.** The run
proves nothing about load, and its own elapsed times are what say so. Treating
it as "load ruled out" would have been a false negative from an instrument
incapable of returning the positive, which is the defect class this project
tracks most often. Load was retested under 12 spinning CPU hogs on
the 8-core box (loadavg 10.2–12.8): the suite took **250.47s against the
~192s baseline**, a 30% slowdown, which is what says the contention was real
this time. Result: 14 failed, 2780 passed, collapse test passed. **Load is
eliminated.** A mid-flight correction was needed there too — the first
generators had a 480s deadline while `tests/unit/test_services/` runs in the
latter half, so the test in question would have executed after the load
lifted; longer-lived generators went in before the run reached it.

Bisection was deliberately **not** used and still should not be: it assumes
determinism, and at this rate a passing prefix eliminates nothing.

**CLOSED as unexplained**, with every variable controllable from here held
fixed and passing — input, data clock, execution clock, hash seed, test order,
test composition, parallelism, concurrent source edits. That is a worse
outcome than a diagnosis but a more honest one than a mechanism nobody has
demonstrated.

If it recurs, the next useful datum is **which of the twelve accounts went
missing** — that is in the assembled node list, not in the assertion, so
capture the node list and the quarantine list at the moment of failure. The
drop happens in extraction (one evidence row never became an account node),
not in collapse, so `b.quarantine` entries are the first place to look: a
quarantined account would explain the missing member and would name its own
reason.

**Proportionality, stated so reopening this is a decision rather than a
reflex.** This is an in-memory test with pinned inputs failing one run in nine
on a count assertion. **Whether it corresponds to anything in production is
unestablished** — a production drop would need a different mechanism than a
test whose inputs do not vary. It gets a line in this file, not an
investigation, unless it recurs with the node and quarantine lists captured.

Worth keeping because it is one of the two things that made the name-for-name
diff worth having: a count-only check would have read 15 as "the same
tolerated set, one bigger".

## 17. GATE: nothing ships to a second customer until these are closed

Two defects share one trigger condition, and both are invisible today for the
same reason: **there is exactly one tenant.** They are listed together because
they are not two pieces of work to schedule independently — they are one gate
on customer onboarding, and the day a second customer exists they both bite at
once, silently.

Measured, so the "one tenant" premise is not an assumption: the cluster holds
a single `manager.name` value, `wm-c00.siembiot.int`, carrying all
154,208,627 documents over 7 days.

> **This justification expires at onboarding, and it is load-bearing in more
> places than this entry.** "No other tenant's row was touched", "an unpinned
> query returns the same set as a pinned one", "the isolation defects are not
> live" — every one of those rests on that single `manager.name`
> measurement, taken 2026-10-14, and every one becomes false on the day a
> second manager ships documents to this cluster. It is a statement about
> today's data, not a property of the code.
>
> So the measurement is a **precondition of the gate, not evidence the gate
> can be skipped.** Re-run it before relying on any claim above:
>
>     terms agg on manager.name over the index pattern, 7 days
>
> More than one bucket means every "not currently a leak" in this file has
> expired, and the items below are live defects rather than scheduled work.

### 17a. Every user carries `all_tenants = true`

All 28 users have `all_tenants = true` and `tenant_ids = []`. Tenant scoping
is therefore exercised by **no real principal** — `TenantScope` is tested, and
nothing in production has ever been restricted by it. A scope that has never
restricted anybody is indistinguishable from one that does not work.

**Before the second customer:** at least one real principal restricted to one
tenant, and a check that fails if every user is unrestricted.

### 17b. A missing tenant pin silently drops the filter

`getattr(integration, "tenant_values", None) or []` in the estate adapter
turned a missing attribute into "no tenant filter" — an unpinned query, which
on a shared cluster is the isolation boundary gone. Found 2026-10-14 and fixed
to refuse; see the commit. **Absence-as-value inside a security boundary** is
the general form, and the whole class is invisible while one tenant exists
because unpinned and pinned return the same set.

**Before the second customer:** a test that asserts **no OpenSearch body is
ever sent without a `terms` filter on the tenant field.** Written against the
body-construction path rather than against a list of call sites, because that
is what catches the call sites that do not exist yet — enumerating the two
known ones (`alert_log_context_service` and `alert_log_selection`, which pin
on the same `tenant_field` / `tenant_values` idiom and have the same hole)
would pass on the day somebody adds a third.

Shape of the check: intercept at the lowest shared point every query goes
through — `OpenSearchClient._request`, since both the log-context queries and
the estate adapter reach the cluster through it — and assert that any
`_search` body carries a tenant `terms` clause in its `filter`. A query that
cannot name its tenant should raise there rather than be filtered out, for the
reason the estate adapter already refuses: an unpinned query on a shared
cluster is the isolation boundary gone, and refusing is the only behaviour that
stays correct when a second manager ships.

### And the live consequence today, which is a configuration absence

`OPENSEARCH_TENANT_VALUES` is **empty in the deployed environment**, so
`TenantIntegration.configured` is False and SIEM log enrichment has been off
since **2026-10-12 12:26:32** — zero `alert_log_context` rows since, across
1,601 alert runs. Full diagnosis, including why it is not a code regression
and not today's commits, in
[log-context-stopped-on-an-empty-env-var.md](problems/log-context-stopped-on-an-empty-env-var.md).

The fix is one line plus `docker compose up -d --force-recreate` (not
`restart` — `env_file` is read at container creation):

    OPENSEARCH_TENANT_VALUES=wm-c00.siembiot.int

**The same value unblocks the estate lookup**, which refuses for the same
reason. Left for a human because it recreates the api on a box carrying live
traffic.

## 18. Falcon's silence expectation is conditional, not a number

`continuity()` needs a declared `expected_interval_hours` before it will call
an integration stopped, and with none declared it makes no claim. The log
store declares 6h because it produces one `alert_log_context` row per
analysed alert. **Falcon must not declare one**, and the reason is worth
keeping rather than fixing with a plausible number:

Falcon enriches **on escalation, not on a clock.** A quiet estate produces no
Falcon queries, so any fixed interval would manufacture outages on exactly
the days when nothing is wrong — and `6h` would be a guess dressed as a
declaration, which is worse than the honest absence because it carries a
verdict.

**But name what "no claim" costs**, because that is the part an absence
convention is supposed to make explicit: **a Falcon outage is currently
indistinguishable from a quiet day.** The card shows its last success and no
verdict, and nothing will ever go red.

**The right expectation is conditional:** silent *since the last verdict that
should have queried it.* That is a different shape from a duration — it needs
the set of verdicts whose decision path includes a Falcon lookup, and then
the question is whether any of those produced a Falcon result. A verdict that
should have queried Falcon and has no Falcon evidence is the outage signal;
elapsed time is not.

So the work is:

1. Identify the verdicts whose path includes a Falcon enrichment — the
   `decision_engine` already records which sources were consulted, and
   `source_answer_rate_service` already derives the expected source set from
   the registry rather than a list.
2. Express the expectation as "N consecutive qualifying verdicts with no
   result" rather than "H hours of silence".
3. Generalise `continuity()` to accept a conditional expectation, since any
   on-demand integration has this shape and a clock-based one is the special
   case rather than the rule.

Until then Falcon's honest state is: last success reported, no silence
verdict, and this entry as the record of what that omits.

### A second expiry, on the warrant's scope

`verified_ok` now carries a warrant — `collector_output` (worker) or
`api_ping` (api) — because the two are different claims. The log store's
promotion rests on collection evidence being a **superset** of what the ping
proves, and that is true only because **there is currently no api-side
user-facing OpenSearch query**: the sole `search_all` caller is
`alert_log_context_service`, reached only from `alert_body_task` and
`alert_log_followup_task`, and the api's only contact with the cluster is
`ping()` in `GET /admin/opensearch-health`.

**That expires the moment the estate lookup gets an API route**, which is the
plan — `estate_lookup_service` already calls `_request` and has no consumer
yet. From then on the ping is the **sole witness** for the api path, neither
warrant subsumes the other, and a card showing only `collector_output` is
making a narrower claim than it appears to: the worker can be answering while
an analyst's on-demand estate lookup fails.

So when that route lands, the log store needs **two** direction states rather
than one — the collection path and the on-demand path are separate consumers
with separate failure modes, which is the same argument that already keeps
`enrichment` and `ingest` apart. Do not let one warrant stand in for both.

#### DONE, 2026-10-15 — the route landed and this was closed

`GET /api/email-investigations/{run_id}/estate-dns` is the api-side consumer.
`test_estate_lookup_consumers.py` fired on it, naming the file, and the
obligation was met rather than allowlisted:

| | `enrichment` | `on_demand` |
|---|---|---|
| consumer | worker, one `alert_log_context` row per analysed alert | an analyst's estate lookup, from the api |
| expected interval | 6h | **none declared** |
| admissible warrant | `collector_output` | `api_ping` |
| state today | promoted while output is inside 6h | `configured_unverified`, `last_success` = `never_observed` |

`on_demand` declares no interval for the same reason Falcon does not: an
analyst triggers it or nobody does, so elapsed silence is not evidence about
it. `ToolSpec.expectation_for` indexes through a declared default rather than
using `or`, because `.get(d) or 6` would turn that refusal back into 6 — the
absence-as-value shape, in the one place the absence is the point.

Collector output is now **inadmissible** for `on_demand`:
`_continuity_per_direction` passes `last_succeeded_at` only to the direction
whose warrant it actually is, so the api path cannot be promoted on the
worker's evidence. The overall badge is the worst direction.

Two things this does **not** do, both still open above: the conditional
expectation (items 1–3 of this entry) is still unbuilt, so `on_demand` has no
outage signal at all — only "never witnessed". And the guard that fired has
been replaced by its inverse, which asserts the obligation still holds; a
guard watching for an event that has already happened reads as coverage while
watching nothing.

## 19. `sandbox_analyses.requested_by` holds kinds in an actor column

The only existing attribution precedent, and it should not be followed:
`String(64)` holding a display name rather than a user reference. A rename
orphans it and two people with one display name are indistinguishable — the
problem `users.external_id` already solved for Entra by keying on the
immutable claim rather than the address.

**Measured, 68 rows, all populated, 5 distinct values:**

| value | rows | resolves to a `users` row |
|---|---|---|
| `auto-detonation` | 31 | **no — not an actor at all** |
| `timotei.moscaliuc` | 17 | yes |
| `upload` | 14 | **no — not an actor at all** |
| `Threat-Analyzer-Owner` | 5 | yes |
| `admin` | 1 | no |

**So the answer to "resolvable or permanently approximate" is neither, and
the real shape is more useful than either.** 45 of 68 rows are not degraded
names — they are **kinds stored in an actor column**: `auto-detonation` is an
automated trigger and `upload` is a channel. The four-worlds collapse this
platform spent 2026-10-14/15 closing is already live in this table's data.

Classified against the taxonomy in
[submitter-attribution.md](design/submitter-attribution.md):

* **45 rows exactly classifiable** → `automated_ingest`. No guessing, no loss.
* **22 rows resolvable to user ids today**, by exact match on
  username / display_name / email — and stored as
  **`provenance = reconstructed_from_name` with the resolution date**, never
  as if recorded at creation. Resolving a display name now is an inference
  about the past: a renamed-and-reused account or a once-shared display name
  resolves confidently and wrongly, and nothing would ever flag it. Marked as
  reconstructed it is a defensible inference that a later correction can find
  again; stored bare it is a fabrication with a confident face. The
  resolution still has to happen **now**, because it works only while nobody
  has been renamed.
* **1 row (`admin`) → `recorded_unresolvable`, not
  `predates_attribution`.** Those are different worlds.
  `predates_attribution` means the actor existed and was never written down;
  this actor **was** written down and the string does not resolve — a role
  name, a deleted account or a literal, with nothing to separate them. The
  distinction is operational: `recorded_unresolvable` tells a later auditor to
  go looking for other evidence (access logs, the row's timestamps, the
  artefact) instead of concluding none exists. Folding it into
  `predates_attribution` would close an avenue that is still open.

The work: migrate to `submitted_by_kind` + `submitted_by_user_id` as
specified for the five request types, resolve the 22 now while they still
resolve, and classify the rest. Doing this *with* the main change is cheaper
than after, because the resolution window is closing on its own.

## 20. Rename `entity_user` → `subject_account`

Split out of the attribution change deliberately: 45 readers, a dual-write
release and a human verification step for an external API contract is too
much to carry alongside a security-sensitive feature, and bundling them makes
the pair hard to revert.

**Why rename at all.** `entity_user` is documented as *"Who the alert is
about … written at ingest from the alert body"* — the account named in the
log, frequently the compromised one. Sitting beside *"who requested the
investigation"* it is a trap that would attribute an investigation to its
victim. A test that the submitter is never populated from it is necessary and
insufficient: the next person reaching for the obvious column needs the name
to stop them.

**Proposed name: `subject_account`.** It says whose account the alert is
*about*, in the vocabulary the graph layer already uses (`account` nodes,
`Subject` in the Windows event sections), and it cannot be misread as an
actor. It also matches migration 048's existing `target_subject_account`
language. Not `affected_user`, which asserts impact nobody has established.

### 45 readers, and one is an API contract

| surface | refs | note |
|---|---|---|
| `models/database.py` | 1 | the column |
| `services/alert_log_context_service.py` | 6 | `principal_of`, plus the documented `DOMAIN\user` domain-half defect |
| `services/alert_log_selection.py` | 3 | selector construction |
| `services/alert_correlation_service.py` | 4 | builds the **plural** `entity_users` |
| `services/alert_case_graph_service.py` | 2 | account nodes |
| `services/alert_case_narrative_service.py` | 2 | narrative text |
| `services/alert_case_linkage_service.py` | 1 | case linkage key |
| `services/alert_entity_profile_service.py` | 3 | profile and its coverage caveat |
| `services/alert_body_investigation_service.py` | 1 | writes it from log context |
| `tasks/alert_body_task.py` | 2 | payload and followup |
| `tasks/alert_log_followup_task.py` | 3 | re-collection |
| `api/alert_investigations.py` | 5 | **response payloads** |
| `api/detections.py` | 1 | distinct-user count |
| `frontend/src/lib/types.ts` | 3 | `entity_user`, `entity_users`, coverage comment |
| `frontend/.../CasesList.tsx` | 5 | renders `entity_users` |
| `frontend/.../cases/[caseKey]/page.tsx` | 3 | renders `entity_users` |
| migrations 021, 043, 048 | — | historic, left alone |

**The derived plural is the hard part.** `entity_users` is an *API field* in
case payloads consumed by the frontend. Renaming the column is a migration;
renaming the API field is a breaking change for an external consumer, and
this platform has at least one.

### Migration shape — the two-step form of "a rename is not a deployment"

1. Add `subject_account`, backfill from `entity_user`, dual-write. Reversible
   throughout.
2. Move all 45 backend references; the API emits **both** `entity_user` and
   `subject_account` for one release, so no consumer breaks on the same
   deploy as the schema change.
3. Move the frontend once the API emits both.
4. Drop the old column and the old API field in a **separate** migration,
   after a deliberate decision that no external consumer reads it.

Step 4 needs a human: nothing in this repository can establish what an
external caller reads. Until then the trap is reduced and not gone, which is
why the never-populate-from-`entity_user` test ships with the attribution
change and stays afterwards — belt to the rename's braces, not instead of it.

## 21. Recharts renders into a zero-size container on the email results view

Seen in the browser console during the 2026-10-15 end-to-end upload
verification:

    width(-1) and height(-1) of chart should be greater than 0

A chart is mounting into a container with no measured size — `-1` is
Recharts' sentinel for "the ResponsiveContainer measured nothing", which
happens when the parent has no resolved height at mount (a flex or grid child
with no explicit basis, a `display: none` tab, or a render before layout
settles).

Minor, and worth fixing because it is **in the feature just verified**: the
email investigation results view. A chart that renders at zero size is
invisible rather than broken, so nobody reports it — the same shape as the
fitted-graph problem already in `docs/problems/graph-fit-density.md`, where
`cy.fit()` scaled to whichever dimension bound first and produced a
thumbnail-scale render that was accurate and unreadable.

Fix shape: give the `ResponsiveContainer`'s parent an explicit height (or a
`min-height`), and if the chart lives in a tab, mount it only when the tab is
active rather than hiding it with CSS. Confirm by reloading the email results
view with the console open and seeing no warning.

## 22. RESOLVED TO FACTS: `svc-tools` is a dormant cross-host root trust

Not a local service account. **An unrestricted root trust from another host.**

`wheel` contains only `svc-tools`. The account is password-locked, has no
crontab, and `/etc/cron.d` holds only distro defaults — **nothing on this host
runs as it.** It has exactly one SSH key, commented `root@exptools002`, and
the key carries **no options**: `cut -d' ' -f3` returned the comment, which it
could only do with no `from=` or `command=` prefix.

So: **root on `exptools002` is root on `siem-mon`**, from any address the
firewall permits, with no forced command and no password. The escalation is
not theoretical — the journal records it working (below).

### Has it ever been used? No evidence of other use — in a log the key holder could have altered

**The window is the host's entire life**, which is what makes the answer
complete rather than a floor:

| source | window | what it covers |
|---|---|---|
| journald | **2026-07-07 11:09:53 → now** (first boot; 363MB, no gap) | `Accepted publickey`, logged regardless of whether a pty is allocated — so **non-interactive use too** |
| `wtmp` | 2026-07-07 11:09:53 → now (no rotated archives) | interactive sessions only |
| `auth.log` | 2026-09-13 → 2026-10-15 (~32 days) | too short to speak to August |

**`Accepted publickey for svc-tools` in the journal over the host's whole
life: 1. Failed attempts: 0.**

**Scope that claim to the instrument.** The session reached root at 11:04:12,
and **root can rewrite the journal.** Forward Secure Sealing is **not
enabled** (no FSS key — systemd's default), the journal files are
`root:systemd-journal`, and `journalctl --verify` returning PASS establishes
*structural integrity, not authenticity*: a rewritten file still passes.

So the finding is **"no evidence of use beyond this session"**, not "used
exactly once, ever". The practical conclusion is unchanged — nothing suggests
other use, and the channel looks abandoned — but the claim must not be
stronger than the thing that produced it.

    2026-08-07 11:03:41  useradd: new user svc-tools, added to 'wheel'
    2026-08-07 11:03:41  passwd: password for 'svc-tools' changed by 'root'
    2026-08-07 11:04:10  Accepted publickey from 10.45.0.91, ED25519
                         SHA256:8EwMOtynzh8LORTQAZ4xzFYzKcj+aV7YmL0q0DfrLrA
    2026-08-07 11:04:12  sudo: svc-tools : USER=root ; COMMAND=/usr/bin/su
    2026-08-07 11:04:12  su: session opened for user root(uid=0) by svc-tools
    2026-08-07 11:08:38  Disconnected

Created, authenticated 29 seconds later, **root within 2 seconds of logging
in**, gone after **4 minutes 28 seconds**, and never used again in the 69 days
since. Its observable activity as root was host provisioning: `apt` ran,
several `systemctl` reloads from `session-10.scope`, and a docker/containerd
restart at 11:05:43.

**That `sudo … USER=root` succeeding is the empirical proof the `wheel` rule
grants root** — `/etc/sudoers` is unreadable without root, so the journal is
the evidence rather than the config.

### `su` ends command-level attribution, by construction

The one command `sudo` logged was `/usr/bin/su`. **After 11:04:12 nothing
records individual commands**: `sudo` logs each invocation, but a root shell
obtained through `su` logs one line and then nothing. The `apt`, `systemctl`
and docker activity visible in those 4m28s is inferred from *side effects* —
service units starting, dockerd losing containerd — not from any record of
what was typed.

**So what was done in those 4 minutes is unrecoverable from this host, by
design rather than by accident.** That is a stronger reason than `relatime`
for why the `.sql` question can only be answered by whoever held the key: the
`atime` argument leaves a 24-hour blind spot, while `su` leaves no command
record at all. Both reasons hold; this is the larger one.

**So: a dormant full-root channel, not an active one.** Different problem from
an active one, and still a full-root channel.

### Does anything of ours depend on it? No.

| pattern | hits in repo, deploy scripts, compose, docs |
|---|---|
| `svc-tools` | 4 — **all in this backlog entry**, written 2026-10-15 |
| `exptools002` | **0** |
| `NOPASSWD` | **0** |
| `exptools` | 1 — `http://exptools.com.sg/…` in a phishing-URL training set, coincidental substring |

**Nothing of ours connects**, so scoping the key breaks none of our
automation. Whatever it exists for lives on `exptools002`.

### Remediation — removal is the default outcome, not restriction

**Nothing is applied. Nothing will be until someone claims the channel.**

The earlier version of this section proposed `from=` as step one, written
while the usage was unknown. **It is now known** — one provisioning session,
69 days ago, nothing of ours depending on it — and that changes the default.
A restriction preserves a channel that nothing appears to use, and
**an unowned access path does not become owned by being restricted.** If
nobody claims this within a week, it goes.

**Default: remove.** Reversible at every step, which is what makes removal
the cheap option rather than the drastic one.

1. `gpasswd -d svc-tools wheel` — drop the group membership.
2. Delete `/etc/sudoers.d/wheel` (keep a copy outside the box first; it has
   never been read by this investigation and its exact grant is still
   unestablished).
3. Disable the key — comment the line in
   `/home/svc-tools/.ssh/authorized_keys` rather than deleting it, so the
   fingerprint stays recoverable for whoever turns up asking.

Each is one line to undo. If something surfaces that needs the channel, it
reappears in minutes with a known-good configuration.

**Interim, if removal has to wait:** apply `from="10.45.0.91"` — free, breaks
nothing, and the address is already evidenced as the only one ever used. It is
**an interim measure, not the plan.**

**Restriction becomes the answer only if someone claims the channel and names
what it is for.** Then `from=` plus `command="…"` plus a sudoers rule listing
actual commands — and the single observed session ran `su`, `apt`, `systemctl`
and a docker restart, which as a command list is barely narrower than `ALL`,
so "claimed" has to mean a stated purpose rather than a shrug.

### The security boundary has moved

`exptools002` is now the security boundary of this platform, and nothing done
on `siem-mon` is stronger than it. Who has root on `exptools002` is the
question that bounds everything else — including the TLS work, the CORS fix
and the tenancy gate, none of which constrain an account that is root on
demand.


## 23. BLOCKED ON A CUSTOMER FACT: `EMAIL_OWN_MTA_IDENTITIES` is empty

The estate DNS panel's sentence — "first resolved *before this email*" — needs
an arrival time our own infrastructure wrote. The resolver is built and tested
(`app/services/email_anchor.py`, 17 tests) and runs at parse time for both
`.eml` and `.msg`. The setting it reads is empty, so every run resolves
`check_failed` and **no before/after sentence renders at all**. Hits and named
absences still render; only the comparison is withheld.

**What is needed:** the mail hosts or domains that receive this customer's
mail, comma-separated — e.g.
`ourcorp-com.mail.protection.outlook.com,mail.ourcorp.example`. Suffix
matching is on a dot boundary, so the registered domain is usually enough.

**Why it cannot be defaulted.** The value decides which `Received` headers are
trusted to date a message. A wrong or over-broad entry trusts a chain we do
not own, and the failure is silent and in the dangerous direction: an attacker
who can get a header past the filter can backdate the message, which makes
their own domain read as "ordinary infrastructure". Empty is the honest state
and it fails visibly.

**Not a backfill.** `email_investigation_runs` has no raw-email column and
does not retain the Received chain — one of the 38 completed runs contains the
string "received" anywhere in its stored result. Setting this fixes runs from
then on; the existing ones stay `check_failed` permanently.

See `docs/problems/a-first-seen-that-is-really-a-collection-start.md`.

## 24. BLOCKED ON ITEM 17: free-form OpenSearch querying

**Not scoped, deliberately.** A query box over this log store is cross-tenant
exposure by construction, and the gate is item 17's tenancy test rather than a
design document.

### Why it is blocked rather than hard

The store holds **2.57 billion** documents in the busiest week alone. Every
account in this deployment currently carries `all_tenants = true`, because
there has only ever been one customer — see item 17 and
`one-tenant-hides-the-isolation-bugs`. And the tenant pin has been dropped
before: `OpenSearchEstateClient.count_and_hosts` read `tenant_values`, an
attribute that does not exist on `TenantIntegration`, and
`getattr(..., None) or []` turned the missing attribute into *no tenant
filter*, so the query ran across every tenant's documents. It was caught by a
host count disagreeing with the recon — 109 against 5 — and by no test.

A feature whose whole purpose is to let a caller shape a query body is the
worst possible place to re-learn that lesson.

### The precondition

**No OpenSearch request body leaves this platform without a tenant `terms`
filter, enforced server-side, and the filter is not expressible by the
caller.** Not a review rule — a test that constructs a body through every path
that reaches the cluster and fails if the pin is absent or caller-supplied.
That is item 17's work and it is worth doing whether or not this feature is
ever built, because the estate lookup, the log context and the Falcon panel all
already send bodies.

### What ships with it, if it is ever designed

Three things, not negotiable separately:

1. **A hard timeout and a result cap**, server-side. A retention-wide `min`
   over `data.dstip` (2.07bn docs) already timed out during the 2026-10-15
   verification, so this is a measured risk and not a hypothetical one.
2. **Every query recorded with its submitter.** That is the attribution spec
   (`docs/design/submitter-attribution.md`), so the two ship together — a query
   log with no actor is an audit trail that cannot answer the only question it
   will ever be asked.
3. **A written answer to "why is this not OpenSearch Dashboards?"** Dashboards
   exists, it is the tool for this, and it already has row-level security as a
   product feature. Rebuilding a worse version of it inside this platform needs
   a reason beyond convenience.

### The feature that is probably actually wanted

If the real need is *pivoting from an indicator in an investigation into its
logs* — "show me the DNS events behind this estate hit" — then say so, because
that is a different and much better feature: bounded by an indicator that is
already on screen, bounded by the tenant of the run it belongs to, no
caller-supplied query body, and no new exposure surface. It is also most of
`/alert-investigations/{run_id}/logs/context`, already built, pointed at a
different anchor.

Specified separately: `docs/design/on-demand-indicator-lookup.md` covers the
multi-source indicator lookup, which is adjacent and not blocked on this.

## 25. Two schema authorities: `create_all` at startup, and Alembic

**Filed 2026-10-15, not for today.**

`app/main.py` runs `Base.metadata.create_all` on startup. `alembic/versions/`
also creates tables. **Whichever runs first wins and the other must cope**, so
every new-table migration has to be written idempotent — 062 and 063 are, 064
was not, and this is what that cost:

The api restarted before migration 064 ran. `create_all` created
`indicator_lookups`, the migration then died on `DuplicateTable`, and
`alembic_version` stayed at **063 with the table present**. The schema was
ahead of the recorded version, and nothing reported it. The table worked — six
rows were written through it — which is exactly why nobody would have noticed.

**So Alembic's version is currently a partial record rather than the record.**
It describes the migrations that happened to run, not the live schema. Any
reasoning that starts "the database is at revision N, therefore…" is unsound
while that is true, and `docs/deploy/schema-changes.md` — which exists because
a rename cost 2h 38m of stopped analysis — assumes the version means something.

### The work

**One authority, with the other removed rather than worked around.** Removing
`create_all` is the likelier direction: migrations can express a rename,
`create_all` cannot, and the failure that doc records was a rename. But that
makes `alembic upgrade head` a hard precondition for startup rather than a
convenience, which changes the deploy sequence and the first-boot story — so it
is a decision, not a tidy-up.

**And a test that the head actually describes the live schema.** Compare
`Base.metadata` against the live database and fail on any difference: a table
or column present in one and not the other. Without it, "we are at 064" stays
an assertion about which scripts ran rather than about what exists — and the
test is what makes the chosen authority real instead of nominal.

Related: `docs/deploy/schema-changes.md`, and the idempotency note in
`alembic/versions/064_indicator_lookups.py`.

---

## `Threat-Analyzer-Owner` — deactivated 2026-10-16

A platform placeholder holding the **highest role in the product**, with one
login ever, at creation. Closed by deactivation rather than by giving it an
email address: an account nobody uses should not hold `owner`, and
deactivation is reversible in one statement where handing it an identity is
not.

**What was found, before anything was changed.** `last_login_at` is the
login path's own declaration, so it was not the evidence — every column that
records a user *acting* was checked instead, each against its own type
(README rule 20):

| column | type | rows for this account |
|---|---|---|
| `alert_case_spine.closed_by` | varchar | 0 |
| `api_keys.created_by` | varchar | 0 |
| `case_read_set.requested_by` | varchar | 0 |
| `email_investigation_runs.actor_user_id` | uuid | 0 |
| `indicator_lookups.actor_user_id` | uuid | 0 |
| `investigation_records.actor_user_id` | uuid | 0 |
| `sandbox_analyses.requested_by` | varchar | **5** |

The five are all on **2026-09-23, 07:42 → 14:33** — the day the account was
created, within eight hours of its single login at 06:33. Nothing in the 23
days since, anywhere.

The type column is load-bearing and nearly cost the finding: four of those
seven columns hold a **name**, not an id. The first pass compared all seven to
the account's uuid and returned 0 across the board, including for
`sandbox_analyses.requested_by` where the answer is 5 — a predicate written
without checking the column's type, which is README rule 19 one layer out of
the payload.

Also checked, and empty: no `api_keys` row created by it (all four are
`bootstrap`/`admin`, role `ingest`), no `integration_audit` entry (only
`timotei.moscaliuc` and `e2e-admin` appear), and no reference to the name
anywhere in the source — `security/bootstrap.py` creates `admin` or
`BOOTSTRAP_ADMIN_USERNAME`, so nothing recreates this account on start.

**Why deactivation bites immediately.** `middleware/auth._identify_user`
re-reads `active` on **every request**, so this is not a change that waits for
the next login — any live session for the account stops working at once. The
session TTL is 12 hours in any case, so the token issued on 2026-09-23 expired
23 days ago.

**Why it was a hand-written statement.** `auth.update_user` refuses to
deactivate or demote an owner, for everyone including another owner, and the
refusal names the escape hatch itself: *"Change the role in the database if
this is genuinely required."* So the API could not do it, by design. The
last-administrator guard's premise was verified manually before the change:
`timotei.moscaliuc` (owner) and `viorel.horga` (admin) both remain active, so
the platform is not left unmanageable.

```sql
-- what was run
UPDATE users SET active = false WHERE username = 'Threat-Analyzer-Owner';
-- to reverse it
UPDATE users SET active = true  WHERE username = 'Threat-Analyzer-Owner';
```

The row keeps `role = 'owner'` and its five `sandbox_analyses` rows still
resolve to it, so the attribution work above is unaffected: deactivating an
account does not rewrite what it did.

---

## 26 — there is no application path to disable an owner

`auth.update_user` refuses to deactivate **or** demote an owner, for everyone
including another owner and the owner themselves, and the refusal is
unconditional. For a security platform, the missing case is the ordinary one:
**an owner who leaves the company, or an owner credential that is
compromised.** The documented remedy today is a hand-written `UPDATE` against
`users`, which means the offboarding path for the highest-privileged account
in the product is "edit the database".

Deactivating `Threat-Analyzer-Owner` on 2026-10-16 required exactly that.

## 27 — the owner refusal names the database as the way around it

The 409 detail reads:

> An owner account cannot be {action}. This is deliberate and applies to
> everyone, including other owners. **Change the role in the database if this
> is genuinely required.**

An error message should not tell the caller where the control isn't. The
sentence is useful to an operator reading the source and harmful in an HTTP
response, which is the one place it currently appears. Move the guidance into
the docstring (it is already there) and leave the response saying only that
the operation is refused and who can authorise an alternative.

## 28 — the owner guard refuses unconditionally, so it is not enforcing its own purpose

`_refuse_if_owner` exists to stop an administrator taking the platform's
administration away from its owner — that is, to stop a tenant being orphaned
and left unmanageable. But it does not check whether that would happen. It
refuses always, which means:

* the case it protects against and the case it blocks needlessly are treated
  identically, and
* the actual check — *are there other active administrators?* — was performed
  **by hand, in the transaction, as a count** when the account was
  deactivated:

```sql
SELECT count(*) FROM users
 WHERE role IN ('owner','admin') AND active IS TRUE
   AND username <> 'Threat-Analyzer-Owner';   -- returned 2
```

That count belongs inside `update_user`. `_refuse_if_last_admin` already
performs the same shape of query for administrators; extending it to own the
owner case turns an unconditional refusal into a **condition**, which makes
items 26 and 28 the same fix: an owner may be deactivated exactly when another
active administrator remains, and the API can then do it. Item 27 falls out
too — the refusal no longer needs to point at the database, because there is
no longer a case where the database is the only route.

## 29 — no user-administration action is audited anywhere

Creating a user, changing a role, deactivating an account and resetting a
password all go through `auth.py`, and **none of them writes an audit row.**
The only audit table is `integration_audit`, which is scoped to integration
configuration (`tool`, `action`, `actor`, `actor_role`, `detail`) and is
written only by `integrations.py` and `integration_credential_service.py`.

So a privileged account state change leaves no trace in the system that holds
the account. That is
[a-failed-ingest-leaves-no-trace](problems/a-failed-ingest-leaves-no-trace.md)
applied to authorisation rather than ingest: the event happened, the state
changed, and nothing in the platform records that it did or who did it.

**The deactivation of `Threat-Analyzer-Owner` wrote no audit row**, and no
audit row was written for it deliberately either: the one audit table is for
integrations, and putting a user event in it would make that table mean two
things. **So the only record of that action is the backlog entry above and the
commit that carries it**, which is stated here rather than left to be
discovered — and it is the clearest possible argument for the item.

### The cost has already landed, which is the argument

Closing `Threat-Analyzer-Owner` took the better part of an hour. Almost none
of that was the decision — the decision was one `UPDATE`. It went on
*reconstructing* what an audit row would have recorded in one line: who
created this account, when, under what authority, and for what purpose.
Nothing recorded any of it, so the question had to be answered by inference
across seven tables, and the inference was **wrong on the first pass** (see
[false-exculpation](problems/false-exculpation.md) — a uniform zero from an
ill-typed comparison).

**That hour is what this table costs every time.** Not hypothetically: it is
the measured price of the one privileged-account question anyone has asked of
this platform so far, and the answer was still only "nothing has used it in 23
days", never "here is who granted it owner and why".

### The customer-facing version

An MSSP platform holding 154M documents across a tenant boundary will be
audited, and the questions are predictable:

* **Who holds `owner` on this platform, and when was it granted?** Today:
  unanswerable retrospectively. `users` has `created_at` for the row, and
  nothing for the *role*. An account promoted to owner last week is
  indistinguishable from one created as owner in September.
* **Who deactivated this account, and when?** Unanswerable. There is no record
  that any deactivation occurred, including the one performed today.
* **Who reset this analyst's password?** Unanswerable.

These compound with items 26–28: a role change may be **both unrecorded and
only possible at the database**, so the one class of change most likely to be
asked about is the one with the least trace. An operator editing `users`
directly leaves nothing but shell history on a box, and that is the documented
path.

The fix is a `user_audit` table, or a generalisation of `integration_audit`
with an explicit subject, written by the four paths above and by nothing else.

## 30 — Falcon can answer the domain question, narrowly, and is not asked

`ROUTING[DOMAIN]["falcon"]` refuses. **Its stated reason has now been wrong
twice, in opposite directions**, and the second correction removes the
refusal's basis rather than replacing it:

| date | reason given | verdict |
|---|---|---|
| 2026-10-15 | "Falcon has no alert field that holds a domain" | **false** — `dns_requests[].domain_name` exists |
| 2026-10-16 | "the field exists but cannot be filtered on" | **false** — and it was our own measurement at fault |

The first was a sampling error: the probe ran over 200 alerts that were all
`product: epp`, and `dns_requests` is carried by the `automated-lead*` family
(29% of open alerts against 3% of closed).

The second was a bounded read without a sort — README rule 21. The control
filtered on a sampled `domain_name`, read 5 rows, did not find the alert the
value came from, and concluded the field was ignored. `total` was **6**: the
source row was the sixth. Re-run with the total read and nonsense values
added, the field **filters correctly**:

| probe | rows | total | source row present |
|---|---|---|---|
| `dns_requests.domain_name:'<sampled value>'` | 5 (limit) | **6** | **yes** |
| three nonsense domains | 0 | 0 | — |
| `sha256:'<sampled value>'` (control) | 5 (limit) | 771 | no — *same page-boundary trap* |
| `behaviors.sha256` (dead field, control) | 0 | 0 | — |

**Measured capability**: `dns_requests` is non-empty on **138 of 2,047 alerts
(6.7%)** and holds **280 distinct domains**.

So there is no measured reason left to refuse, and what remains is a decision
nobody has taken: **what a negative from this field means.** A nil answer is
*"not one of 280 domains that appeared in the DNS context of an alert"* — not
*"Falcon has no opinion on this domain"*. The intelligence endpoints that
would answer the broad question are 403 to this credential.

The routing entry is therefore `cost_not_established` rather than
`no_field_map` — there is somewhere to look and the cost of a wrong reading
has not been established — and it says so in its own reason, because **a
refusal whose stated reason has been falsified is held by inertia until a new
one is written down.**

To close this: decide the negative's wording, add the field to the standing
control, and switch the entry to `ASK` with the 6.7% / 280-domain bound stated
in the section the analyst reads. This and item 33 are one investigation —
same field, same control — and should resolve together.

## 31 — `falcon.lookup` returns alert *ids*, not alert records

**DONE 2026-10-16**, inside item 32's helper — `hydrate_alerts` is a step of `paged_alerts`, so the two cannot come apart again. Verified live: the control hash returns 29 records of 91 keys each, `detections_total: 29`, `detections_complete: true`, and E1 evaluates **True** where it was False.

`falcon.lookup(observable_type="hash")` populates `detections` from
`/alerts/queries/alerts/v2`, which returns **composite ids**. Nothing fetches
the entities, so each element is a dict with exactly one key, `id`:

```python
found = falcon.lookup(observable=<sha256>, observable_type="hash", …)
found["detections"]          # 20 items
sorted(found["detections"][0].keys())   # ['id']
```

Consequences:

* `detection_count` in the indicator-lookup response is a **count of alert
  ids**. It is a usable count and nothing more — no status, no resolution, no
  disposition, no timestamp.
* **Any predicate over those records is unimplementable**, which is what
  blocks E1 in
  [indicator-lookup-escalation](design/indicator-lookup-escalation.md).
* `lookup_host` **does** fetch the entities — 91 keys per record, `status` and
  `resolution` present — so **the shipped Falcon host panel is unaffected**.
  This is the two-implementations divergence with `lookup` as the stale half.

**Fix, measured:** one `POST /alerts/entities/alerts/v2` with the ids — **1
HTTP call** — and the code to copy is already in `lookup_host`.

## 32 — one Falcon paging helper, as the only way to page

**DONE 2026-10-16.** `Page(rows, total, complete, reason)` plus `paged`, `hydrate_alerts` and `paged_alerts`. `lookup`, `lookup_host` and `alert_retention_floor` all go through it; `verify()` deliberately does not, and says why in place — it reads a status *code* rather than rows, and the helper raises on exactly the statuses it exists to report.

The helper then produced a regression of its own, which is the entry worth keeping: `want=500` clamped the per-request limit to the page size and stopped after one page, cutting the host panel from 500 detections to **200**. A coverage reduction introduced by the fix for a coverage bug, caught only by comparing against a measurement taken before the change. `want=N` now means N records across as many pages as that takes, with a test asserting the request sizes are `[200, 200, 100]`.

`lookup` asks `/alerts/queries/alerts/v2` for `{"limit": 20}` with **no
`sort`**. For sha256 `7600ffe12da441fe…` the population holds **29 alerts
including 2 `resolution: true_positive`**, and the 20 returned contained
**neither**:

```
over the 20 the lookup fetches:  any(resolution == 'true_positive') -> False
over all 29:                     any(resolution == 'true_positive') -> True
```

False — on the hash chosen *because* it has two confirmed detections. The gate
would tell an analyst Falcon has nothing confirmed on a file an analyst
confirmed twice.

**This is not to be fixed locally, and that is the point of the item.** The
same defect was then committed a second time *inside the control written to
catch it* (item 30: 5 rows of `total: 6`, concluding a working field was
ignored). A rule that is broken by the fix for its own first instance is not
going to be held by documentation.

So: **one paging helper, and it is the only way this codebase pages Falcon.**

```python
def paged(path, params, *, headers, base_url, want="all") -> Page
# Page = (rows, total, complete)
```

* It always sends a deterministic `sort`.
* It always reads `meta.pagination.total`.
* It returns `complete: bool`, so **a caller cannot not know** whether it
  holds the population or a page. A list return type lets the caller forget;
  a 3-tuple does not.
* `want="all"` pages to the end; `want=N` stops and reports `complete=False`.

This is exactly what `search_all` → `_page` already does for OpenSearch, and
it is why **no OpenSearch read in this codebase has made this mistake** while
the Falcon paths have made it three times. The lesson is that the signature
carried it, not the discipline.

Then every existing Falcon call site moves onto it — `lookup`,
`lookup_host`, `alerts_field_control`, `alert_retention_floor` — and a
negative over `complete=False` becomes a `lower_bound` rather than a
negative, mechanically.

**This closes rule 21 for Falcon and unblocks E1 in the same change**, because
item 31's entity fetch belongs inside the same helper: `paged` returns ids,
and the alerts variant hydrates them. Do this one first.

## 33 — add the nonsense-value check to `alerts_field_control`

**DONE 2026-10-16, with all four axes rather than only the nonsense check.**
Verified live: `sha1` is now refused *by the control itself* — "carries exactly
ONE distinct value across the 25 most recent alerts, so filtering on it proves
only that the API echoes its own sentinel" — while `sha256` (18 distinct),
`md5` (14) and `device.hostname` (5) still pass, each with a nonsense value
returning nothing. `behaviors.sha256` still fails at axis 1.

`reference` is optional and a pass without one says so in its own reason, so
axis 4b is never implied when it was not checked. Eight new tests in the
dangerous direction, including the sha1 case end to end and an
accepted-and-ignored field. The test fake also had to be corrected: it
honoured the field *name* and ignored the *value*, so it modelled an API that
ignores its own filters — a fake more permissive than the provider certifies
behaviour the provider does not have, which is the same error as the control
it was testing.

**`alerts_field_control` is already correct and must not be changed except to
add one call.** It passes on `total > 0` and never requires the sampled row to
be inside the page — which is exactly right, and is why it survived while two
hand-written controls did not. A proposed "fix" requiring the source row in
the page would have **broken every correct field whose hit set exceeds the
limit**: `sha256` returns 5 rows of `total: 771`.

The two concerns it keeps apart, and which must stay apart:

| question | answered from |
|---|---|
| does this field name mean anything to the API? | `total` — known-present ≥ 1, nonsense 0 |
| did I see what I am about to reason over? | returned count against `total`, plus a sort — item 32 |

The one gap: it never checks that **a value which cannot exist returns
nothing.** The framework's premise is that an unrecognised field name answers
200 with zero resources — measured, and still true (`behaviors.sha256` with a
real digest returns 0 of 0) — but that is a property of this provider rather
than a guarantee. The failure it cannot survive is a field *accepted and
ignored*, returning rows for anything: such a field passes the known-present
check while every negative from it is meaningless.

One extra call, cached with the pass as the control already caches, failing
closed through the existing `FalconFieldUnverified`. README rule 19 carries
the practice; this item is the code.

## 34 — six alerts no operator can see, and we render them identically

`show_in_ui` is `False` on **6 of 2,047** alerts. They are not duplicates of
anything visible: **every aggregate group containing a hidden record is
entirely hidden** (0 visible members in each), so these are whole detections
absent from the operator's view rather than suppressed copies.

| # | product | status | resolution | severity | name | created |
|---|---|---|---|---|---|---|
| 1 | automated-lead-context | new | — | — | `PollingKeylogg…` | 2026-09-29 |
| 2 | automated-lead | new | — | — | `EXP-BBTN473 at…` | 2026-09-29 |
| 3 | automated-lead-context | new | — | — | `UmppcBypassSus…` | 2026-09-30 |
| 4 | automated-lead-context | new | — | — | `MaliciousModul…` | 2026-09-29 |
| 5 | epp | closed | false_positive | **High** | `ObfScript` | 2026-07-25 |
| 6 | epp | closed | false_positive | **High** | `ObfScript` | 2026-07-25 |

Records 5 and 6 are `scenario: evade_detection`, tactic Execution, technique
Command and Scripting Interpreter, and were closed by an account that is **not
in this platform's `users` table**. Records 1–4 are untriaged leads, so
"hidden because dismissed" cannot explain them.

**What is not established:** whether the console surfaces these somewhere else
— CrowdStrike groups detections into incidents, and `/incidents/*` is
unreachable to this credential (README rule 19's discriminator clause: the 404
separates none of the candidate states). So "no operator can see these" is the
honest reading of `show_in_ui` and not a proven claim about every console
view.

**The product question, which is the actionable half.** We render all 2,047
identically. For a platform whose purpose is to surface what the console does
not, six operator-invisible records are the thesis in miniature — and
rendering them with no provenance means the first analyst who compares our
page against their queue finds a mismatch and stops trusting both.

So those six need **provenance on the page**: not "hidden", which we cannot
substantiate, but *"not shown in the vendor console"* stated as a fact about
where the record came from. That is the absence convention's instinct applied
to a **presence** — a record we have and they do not is as much a provenance
claim as a value we lack.

Related: `show_in_ui` is also why `/alerts/queries/alerts/v1` returns 2,041
where v2 returns 2,047, and why a console count must be compared against the
v1 population (see `docs/falcon-alert-volume-drop-internal.md`).

## 35 — there is no boundary where vendor absence becomes a kind

**Checked, and it is the worse answer: each caller meets the raw payload.**
`cape_normalizer` is the only vendor normaliser in the codebase and it shapes
data rather than distinguishing absence from a sentinel. For Falcon, callers
read `record.get("status")`, `record.get("pattern_disposition_description")`
and `r.get("seconds_to_resolved")` directly.

The honest-absence convention protects code that goes *through* it. **Every
vendor payload arrives with absence already encoded as a value**, and nothing
converts it. Enumerated over this tenant's 2,047 alerts:

Every row carries its denominator, because a sentinel on 134 of 140 records
carrying the field is a **dead field** and on 134 of 1,900 it is ordinary
sparsity:

| field | the sentinel | sentinel / carrying the key | reading |
|---|---|---|---|
| **`sha1`** | **forty zeros** | **1,953 / 1,953 — 100%, one distinct value** | **dead field** |
| `seconds_to_triaged` | `0` | 2,016 / 2,047 — 98.5% | **effectively dead: 31 real points** |
| `ioc_context` | `{}` | 1,786 / 1,993 — 89.6% | mostly absent |
| `associated_files` | `[]` | 134 / 203 — 66.0% | mostly absent, and sparse to begin with |
| `seconds_to_resolved` | `0` where never resolved | 319 / 2,047 — 15.6% | **exactly the open stage** |
| `aggregate_id` | `""` | 41 / 2,047 — 2.0% | ordinary sparsity |

### ⚠️ `seconds_to_triaged` is a KPI landmine, labelled now rather than later

**Zero on 2,016 of 2,047 — thirty-one real data points in the whole
population.** Anyone who computes *mean time to triage* from this field gets a
number indistinguishable from instant triage: **the most flattering possible
result, manufactured entirely out of absence**, on a metric that will end up
on a slide.

It is written here rather than left to whoever computes it, because the
failure mode is that it looks like a success and therefore gets no scrutiny.
`seconds_to_resolved` is the usable field — median 977 s over closed records,
619 s with the test laptop held out — and even that needed its grain fixed: a
median over the whole population carried the 319 never-resolved zeros and came
out at 584 s.

### ⛔ The boundary must NOT convert sentinels by shape

**JARM's leading zeros mean no TLS handshake was completed. That is a
measurement. `sha1`'s forty zeros are an absence. The two are
indistinguishable by pattern and opposite in meaning.**

A rule like *"all-zeros becomes absence"* is the obvious implementation of
today's lesson, it is what anyone applying it mechanically would write, and it
would **silently destroy a real Hybrid Analysis finding** — turning "we
completed no TLS handshake with this host" into "we do not know whether we
did".

So the conversion is **per field, against the vendor's documented meaning for
that field**, and a field the boundary has no rule for arrives **`unmapped`**
rather than being guessed at in either direction. Guessing toward absence
destroys measurements; guessing toward value is the defect we started with.
Unmapped is the only safe default, and it is also the one that makes the gap
visible.

### Three classes wearing one label, and the boundary treats them differently

| class | fields | what it means | conversion |
|---|---|---|---|
| **Dead** | `sha1` 1,953/1,953, `seconds_to_triaged` 2,016/2,047 | no information at any time | **absence, unconditionally** |
| **State-recoverable** | `seconds_to_resolved` 319/2,047, matching the open stage *exactly* | a badly-typed **state** field — zero means *open* | **recover it, losslessly.** Not a landmine: `0` → `state: open`, and the field keeps its meaning for the other 1,728 |
| **Sparse** | `ioc_context` 1,786/1,993, `associated_files` 134/203 | real fields, mostly empty | leave as a value, and **whatever consumes it must expect nothing as the normal case** — `associated_files` has content in **69 records of 2,047** |

The middle row is the one that was mislabelled first: `seconds_to_resolved`
was called a landmine alongside `seconds_to_triaged`, and it is not. Its zeros
land exactly on the 319 open records, so the conversion is a type fix rather
than a discard.

### A second vendor, already in our stored evidence

Found while sweeping for sha1 damage: **JARM TLS fingerprints** from Hybrid
Analysis, 62-character strings whose leading zeros are JARM's convention for
*no handshake data*. Present at
`hybrid_analysis.items[].raw_summary.behavior_details.connections[].tlsFingerprint.jarm`
on 357 sampled rows of `evidence.evidence_json` and 302 of
`collector_results.evidence_json`. So this is not a Falcon problem; it is
every vendor, and the boundary is the only place to deal with it once.

**The `sha1` one was live and shipped.** `ALERT_HASH_FIELDS` mapped a
40-character digest to `sha1`, so every SHA-1 indicator lookup filtered on a
real digest against a field whose only value is a sentinel, and returned a
clean zero. **And the field control passed**: it samples a value the API
returned — the zeros — filters on it, gets 1,953 rows, and concludes the field
filters. It does. It can never match. Fixed by removing 40 from the map and
giving it a measured reason that names SHA-256 and MD5 as the routes that
work.

`seconds_to_resolved = 0` is the same class and cost a published figure: a
median over the whole population carried 319 never-resolved zeros and came out
at 584 s where the closed-record median is 977 s.

Two items:

1. **A vendor boundary per integration, and it only works if it is the ONLY
   way a payload enters.** One function per vendor taking a raw record and
   returning one whose absences are kinds — but the **output type has to make
   raw access impossible**: accessors returning *a value or an absence*, never
   the underlying dict. If callers can still reach `record["sha1"]`, they
   will, and we are back to a registry that declares correctly while the
   consumer goes around it — which is exactly what happened to `Page.complete`
   for a day.

   This is the **third application of the same move**, and two of the three
   have already held where a documented rule did not:

   | type | removes the option of | held? |
   |---|---|---|
   | `Page(rows, total, complete, reason)` | reading a page as a population | yes — and the regression it then caught was found by rule 23, not by the type |
   | `Concentrated(value, …, held_out, …)` | reporting a pooled rate without its dominant term | new |
   | the vendor record | meeting a raw payload | **this item** |

   Treat it as the house approach rather than three coincidences: a rule a
   caller must remember is held until the next hurried fix; a return type is
   held by the compiler.
2. **The field control needs axes 2 and 4** (item 33): a sampled value from a
   field with **one distinct value** satisfies a known-present control
   trivially, and more fundamentally a reference value drawn from the system
   under test verifies a round trip rather than a capability. See README rule
   19's four axes.

3. **`cape_normalizer` is in scope, not done.** It shapes data; it does not
   name absence. That is the layer-that-answers error one more time — a
   normaliser that answers about the *shape* of a payload while the question
   is whether a field's value means anything — and the sandbox path is already
   load-bearing for email investigations, so it is not a future concern.

## 36 — extend the production/test classification to Falcon devices

`asset_criticality.environment` holds **two** classified rows, both
`windows-test-device`, and **0 of 2,047 Falcon alerts have a classified
host**. `EXP-22MY264` — 70.4% of the corpus, 1,323 alerts named
`TestingActivity` — does not match `seed_host_environment`'s `_TEST_TOKEN`
regex, because it is named like an ordinary laptop.

Signals available without inventing any:

* `machine_domain = dev.expertware.net` — 10 devices;
* the detection `name` (`TestingActivity` on 1,323 alerts), as a
  behaviour-based proposal in the shape `propose_from_behaviour` already uses;
* the existing name regex, for hosts named honestly.

Proposals, not confirmations — the existing propose/confirm split stays.
**This blocks E1**: see "E1 will escalate on test activity as currently
written" in [indicator-lookup-escalation](design/indicator-lookup-escalation.md).
