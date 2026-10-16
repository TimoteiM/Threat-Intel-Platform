# Slice 3 — the escalation rule on the on-demand indicator lookup

**Status: specification. Nothing here is built.** Two defects in the code it
would be built on were found by the positive control in §5 and must be fixed
first; they are backlog 31 and 32.

Slice 3 of the investigation record. The shape is settled and not reopened:

* A **clean** lookup stays a fan-out — the per-source answers it already
  renders, no second page, nothing further paid for.
* A **suspicious or malicious** lookup opens an investigation record, and the
  lookup page gains **one line** linking to it.

What follows is the two things that shape leaves open — what counts as
escalation, and what runs once it does — plus the control that demonstrates
the gate opens at all.

---

## 1. The corpus every rate below is measured over

One population, named once, because every figure in this document has it as
its denominator:

**All 2,047 Falcon alerts for tenant `c00`**, created 2026-07-20 → 2026-10-15,
read from `/alerts/entities/alerts/v2` on 2026-10-16. `meta.pagination.total`
is 2,047 and 2,047 were fetched, so this is the **population, not a sample** —
checked, because a page read as a population is how a rate gets an unstated
denominator.

Within it, 223 distinct `sha256` values. **Where a rate is per-hash the
denominator is 223, and where it is per-record the denominator is 2,047.** They
differ by more than a factor of two for the same predicate, and the per-hash
one is the rate a *lookup* escalates at, because a lookup asks about one hash
and escalates if **any** of its records satisfies the predicate.

### The field coverage that matters is coverage within the open stage

`severity_name` is populated on 1,728 of 1,728 closed alerts and 0 of 319 open
ones. That correlation is too clean to be a field with gaps, and the reading
cannot be settled with this data:

| cell | rows | `severity_name` | dates |
|---|---|---|---|
| `product: epp` + open | **0** | — | cell empty |
| `product: epp` + closed | 1,728 | 100% | 2026-07-23 → 10-15 |
| `product: automated-lead*` + open | 319 | 0% | 2026-07-20 → 10-08 |
| `product: automated-lead*` + closed | **0** | — | cell empty |

**Both off-diagonal cells are empty, so status and product are perfectly
confounded in this estate: every `epp` alert is closed and every
`automated-lead*` alert is new.** The test that would separate "written at
triage" from "a property of the product's schema" cannot be run here.

What the table *does* settle is the third reading: **it is not a schema change
by date.** Both families span July to October — July `automated-lead` alerts
lack the field and July `epp` alerts have it — so the field does not track
time. Of the two surviving readings, either implies the same thing for this
spec, which is why it is not a blocker: **no field's coverage measured over
the pooled 2,047 transfers to the stage a predicate runs in.** Measured within
the 319 open alerts specifically:

| field | open | closed |
|---|---|---|
| `status` | 100% | 100% |
| `device` | 100% | 100% |
| `lead_id` | 100% | 2% |
| `sha256` | **83%** | 100% |
| `md5` / `sha1` | 79% / 74% | 99% / 99% |
| `pattern_disposition_description` | **66%** | 100% |
| `dns_requests` / `network_accesses` | 29% / 30% | 3% / 3% |
| `resolution` | **0%** | 100% |
| `severity_name` / `severity` / `confidence` | **0%** | 100% |
| `priority_value` / `tags` / `assigned_to_*` | **0%** | 99–100% |
| `is_closed` | 17% | **0%** |

Three consequences, each of which would have been a wrong predicate:

* **`resolution` is a closed-stage field (0% open).** So E1's two clauses are
  *disjoint by construction*: `resolution == 'true_positive'` can only fire on
  closed records and `status == 'new'` only on open ones. They are not two
  tests of one thing; they are one test per lifecycle stage.
* **`severity_name` cannot rank what the gate keeps.** Populated for the 1,728
  discarded, absent for all 319 kept.
* **`is_closed` is not the closed indicator.** It is absent on 100% of closed
  records and present on 17% of open ones — the opposite of its name. `status`
  is the field.
* **17% of open alerts carry no `sha256` at all**, so a hash lookup can never
  reach them.

---

## 2. The predicates, stated literally

Over the record `D` as returned by the Falcon detection fetch, and the estate
section `E`. The distinct values of every field read are counted below, from
the population — **not the values I expected to find**, which is how `ignored`
and the absence of `false_positive`-as-a-status were missed on the first pass.

```
status      2 distinct:  closed 1728   new 319
resolution  4 distinct:  false_positive 1345   true_positive 378
                         <absent> 319          ignored 5
```

`false_positive` and `reopened_closed` **never appear as a `status`** in this
estate — they are `resolution` values. `CLOSED_STATUSES` in
`falcon_host_panel_service` lists them as statuses; that is harmless but it is
not measured here, and the predicate below does not depend on it.

**`resolution: ignored` — 5 rows — is handled explicitly, as dismissed.** An
enum member handled by omission is a bug with a date on it, so: `ignored`
means a human saw the alert and chose to take no action on it, which is a
judgement in the same family as `false_positive` and not an absence of one. It
therefore does **not** satisfy E1. The distinction from `<absent>` (319 rows)
is the whole reason to say so: absent means *nobody has looked yet*, and that
is the clause E1 drops to a reported fact below. All 5 `ignored` rows are
`closed` and all 5 carry a prevention disposition — the EDR blocked it and
someone decided it needed nothing further, which is the clearest possible case
for "dismissed".

### E1 — Falcon has evidence a human either confirmed or has not yet seen

```python
e1_confirmed = any(str(d.get("resolution")) == "true_positive" for d in detections)
e1_untriaged = any(str(d.get("status")) == "new"               for d in detections)
E1 = e1_confirmed            # opens the record
```

| predicate | per record (2,047) | per distinct hash (223) |
|---|---|---|
| `status == 'new'` | 319 — 15.6% | **127 — 57.0%** |
| `resolution == 'true_positive'` | 378 — 18.5% | **10 — 4.5%** |
| either (the first draft of E1) | 697 — 34.0% | **134 — 60.1%** |
| any record at all (the naive predicate) | 2,047 — 100% | 223 — 100% |

**So the first draft of E1 opens a record on 60% of the hashes Falcon knows,
and that is not a gate.** `resolution == 'true_positive'` alone is 10 of 223 —
4.5% — and that is the clause that carries evidence: a human looked and
confirmed it.

#### 4.5% of what — because the two readings differ by an order of magnitude

**4.5% is per hash Falcon has already seen.** It is *not* the rate at which a
lookup escalates, and 4.5% is the number people will remember, so:

> escalation rate per lookup = 4.5% × P(the hash an analyst types is one of
> the 223 Falcon has seen)

The lookup's real population is hashes an analyst types — from an email
attachment, a report, a customer question — and the overwhelming majority have
never appeared in this tenant's 2,047 alerts. That second factor is **not
measured**: `indicator_lookups` holds 27 rows, which is the same 27 that make
`RECENT_DAYS` unmeasurable. Until it is, the honest statement is *"4.5% of the
hashes Falcon already knows, which is a small fraction of the hashes anyone
looks up"* — and the per-lookup rate is `cost_not_established`, not a number
divided out and presented as one.

E2's denominator is the same shape: **12 of the 223 Falcon-known hashes** had
executed in the estate at a 7-day window (5.4%), which is again *given that
Falcon knows the hash*, and the estate may well have executed hashes Falcon
has never alerted on.

The reason this section exists is the sampling error that produced the first
draft: a base rate quoted from **the 600 most recent alerts**, where recency in
this estate is dominated by the untriaged `automated-lead` family. That sample
gave 1 true positive; the population gives 378. **The selection was correlated
with the thing being measured**, which is why §1 names the population and
checks `meta.pagination.total` against the fetch.

`status == 'new'` is dropped from the opening condition and kept as a
*reported fact* on the Falcon step. It means "sitting in an untriaged queue",
and in this estate all 319 such records belong to the `automated-lead*`
family, whose newest record is **2026-10-08** — a frozen backlog nobody has
worked for eight days, which is the subject of
`docs/outbound/falcon-alert-volume-drop.md`. "Nobody has triaged this yet" is
not evidence about the indicator.

A clause I tried and am recording as useless rather than including: `status ==
'new' AND the EDR acted` (disposition containing prevent / block / quarantine
/ kill). Its measured contribution is **zero additional hashes** — the EDR
acted on **0 of 319** open records; every one is `Detection, standard
detection.` (209) or absent (110). Prevention dispositions exist on 311
records in the population and all of them are closed. A clause that cannot
fire is not a safeguard, it is decoration.

**Cost: 1 additional call** — see §6, the lookup does not currently fetch the
fields this predicate reads.

**Verdict contributed: `malicious`.**

### E2 — the estate executed it

```python
E2 = (E.get("host_hashes") or {}).get("observed") is True
```

`estate_lookup_service.hash_lookup` answers on **Sysmon event 1, Process
Create, only** — what ran, not what was loaded into another process (event 7)
or seen on disk (event 29). `documents` and `host_count` are the scale and
belong in the step's sentence, never in the predicate.

`observed: False` is a negative **only when it is an answer.** The same
section carries a named absence instead whenever the question was not asked:
`unparsed` for a non-digest length, `cost_not_established` past the 30-day
measured ceiling, `check_failed` when the search did not complete. None of
those is `observed: False`, and none escalates *or* reads as clean.

Fire rate: of the 10 true-positive hashes, the estate had executed **3**
(5 docs / 2 hosts, 153 docs / 8 hosts, 2,007 docs / 106 hosts). A per-hash
rate over all 223 is not stated because it would cost 223 wildcard queries and
has not been measured.

**Cost: zero additional calls.**

**Verdict contributed: `suspicious`.**

### E3 — the estate's contact with it is new

**Cannot be written as stated. Ships disabled.** As given — "a first-seen after
the reference time" — it fails twice over:

1. `_estate()` passes **no** `reference_time`, by design: an on-demand lookup
   has no email, so there is no anchor our own infrastructure wrote, and
   `lookup()` refuses an unnamed one. Without it `first_seen` and
   `relative_to_reference` are never computed at all.
2. Naming the lookup's own request time as the anchor makes the comparison
   **vacuous**: `first_seen` is always in the past and the request is now, so
   the condition is false by construction. A condition that can never fire is
   worse than a missing one.

So: what was the value for? On the email surface this means *the estate's
contact began after the mail arrived* — the mail plausibly caused it. On demand
there is no triggering event, and the half that survives is **recency**:

```python
E3 = (isinstance(first_seen, str)                       # a timestamp, not an absence
      and relative_to_reference != AT_OBSERVATION_FLOOR # not floor-bounded
      and (now - parse(first_seen)).days <= RECENT_DAYS)
```

The floor clause is what stops this being the `aka.ms` bug again: a
`first_seen` sitting at the collection floor means *collection started then*,
not *contact started then*, and that is how a Microsoft telemetry endpoint read
as a new contact on 2026-10-02. Floor-bounded is `lower_bound` — it neither
escalates nor reads as old.

Two prerequisites:

* **`want_first_seen` on the estate lookup.** The first-seen query is
  independent of the before/after comparison and is today gated behind a
  `reference_time` it does not need. Passing a fake anchor to trigger it would
  be a lie in the field whose entire purpose is to prevent that lie.
* **`RECENT_DAYS` is unset and must be measured, not chosen** — from the
  `first_seen` distribution over indicators actually looked up on demand.
  `indicator_lookups` holds **27 rows**, which is not a distribution.

**The trigger, so the deferral is not permanent:** E3 is reviewed when
`indicator_lookups` reaches **250 rows**, which at the current rate is the
first number that gives a usable distribution rather than an anecdote. The
check belongs on the same footing as the other standing numbers — a row in
`scripts/liveness.sh`'s report, so the threshold announces itself instead of
waiting to be remembered. A disabled constant with no trigger is a permanent
decision disguised as a deferred one.

**Cost when enabled: 2 OpenSearch queries per hit** — `first_last_seen` and
`observation_floor`, both over the full 120-day retention, because a 7-day
window cannot answer "months" and its edge would read as a first-seen. Timed
for the hash field (24h 83 ms, 7d 161 ms, 30d 422 ms, 120d 1.7 s warm / 4.3 s
cold); **not timed for the DNS and perimeter fields**, so
`cost_not_established` there until it is.

**Verdict contributed: `suspicious`.**

---

## 3. The verdict, and the state the shape collapses

| verdict | when | opens a record? |
|---|---|---|
| `malicious` | E1 | yes |
| `suspicious` | E2 or E3 | yes |
| `clean` | nothing fired **and** every source that could be asked answered | no |

**`unknown` is not in that table on purpose.** A lookup where a source returned
`check_failed` is not clean — but it is also not a verdict about the
indicator. "We could not check" is a statement about *this platform*, and
rendering it in the verdict strip makes an analyst read our failure as a
property of the hash.

So it renders as **degraded coverage, above the verdict**, in the shape the
investigation chain already uses for `incomplete`: a band that says which
source could not answer and why, with the verdict beneath it reading `clean`
or the honest alternative over the sources that *did* answer. The verdict
field never takes the value `unknown`.

And **an unknown lookup records which source failed**, as a list of source
names with their absence kinds, so a re-run is comparable with it rather than
becoming an unrelated second row. Without that, two lookups of the same
indicator a day apart are two anecdotes; with it, the second one can say *the
estate answered this time and Falcon still cannot*.

A source that is `out_of_scope` or `no_field_map` for this kind of indicator —
Falcon on a domain, the estate on a URL — does **not** degrade coverage.
Nothing was asked because nothing could be, that reason is already on the
page, and treating a structural non-question as a failed one would make every
domain lookup permanently inconclusive.

---

## 4. The cost is a design constraint, not a tuning knob

**This is the largest finding in the document and it was first written as a
footnote.** S1 is per host, so the host-count distribution decides the design
— and the distribution is bimodal with nothing in the middle.

Measured 2026-10-16: every one of the 223 Falcon-known hashes asked of the
estate at a 7-day window, 223 queries in 10.5 s, 43 ms median, **zero
absences**. 12 of 223 had executed here.

| statistic | over the 12 executed hashes |
|---|---|
| min | 1 host |
| **p50** | **4 hosts** |
| p90 | 113 hosts |
| **p95** | **113 hosts** |
| max | 115 hosts |
| mean | 31.5 (the mean is meaningless here — see the buckets) |

| hosts | hashes |
|---|---|
| 1 | 2 |
| 2–5 | 5 |
| 6–20 | 2 |
| 21–100 | **0** |
| 100+ | **3** |

Nine of twelve are ≤20 hosts; three are >100; **nothing is in between.** The
three are almost certainly estate-wide signed binaries. So the design is not
"pick a cap and tune it" — it is "the common case is cheap and the tail is
catastrophic, and they are separated by a gap".

Per-host cost, measured on 3 real hosts: **median 5 Falcon calls and 1.44 s**
(14 calls / 4.96 s for the host that hits its 500-row detection cap). The
worst case is **projected, not run** — running 575 calls against the
customer's tenant to prove it would cause the exact harm being described:

| case | hosts | Falcon calls | wall clock |
|---|---|---|---|
| p50 | 4 | ~20 | ~6 s |
| p95 | 113 | ~565 | **~162 s** |
| max | 115 | ~575 | **~165 s (2.8 min)** |

### The benchmark the projections were missing

Latency means nothing against taste; it means something against what a triage
actually costs. Measured on the same tenant's closed alerts,
`seconds_to_resolved` for the analysts doing the work: **median 584 s**, p95
7.3 hours.

| case | lookup wall clock | share of a median triage |
|---|---|---|
| p50 — 4 hosts | ~6 s | **1%** |
| p95 — 113 hosts | ~162 s | **28%** |

So the cheap path costs an analyst one percent of the time they already spend
on one alert, and the expensive path costs more than a quarter of it — for a
host list that, at that prevalence, tells them almost nothing (see the
baseline below). **The bimodal design is validated against what humans spend,
not against a preference**, and the 584 s is the number to re-measure against
if the estate's triage pattern changes.

A second fact from the same source, which belongs in whatever this feature
eventually becomes: the four analysts who produced 1,447 of those closures
work in the customer's Falcon console, and **one of them has never logged into
this platform.** Every judgement in this document about what should escalate
and what an analyst wants first is a guess they could settle in half an hour.

### Three problems, not one

1. **The synchronous design is already broken, for the tail rather than the
   extreme.** ~165 s sequential does not complete inside any request timeout
   this platform runs, and it is reached by 3 of the 12 executed hashes — 25%
   of the cases where E2 fires, not a freak. One analyst pressing one button.
2. **Blast radius: the lookup shares a credential and a rate budget with the
   shipped alert panel.** There is one `tenant_integrations` row for
   `c00`/`falcon`, so an unbounded analyst-triggered fan-out of ~575 calls
   degrades or stalls the alert panel for everyone, and the panel is the thing
   on the alert page that analysts depend on. An on-demand feature cannot be
   allowed to exhaust the budget of a background one that is already shipped.
3. **A bound is a design decision because the absence convention forbids a
   silent truncation.** Whichever of these is chosen —
   * cap the hosts (cheap, and the bimodal gap makes ~20 a natural line),
   * make host enrichment lazy, one host at a time on the analyst's click,
   * or run the fan-out asynchronously with the record filling in,

   the record must say **`n of m hosts examined` under a named kind**
   (`lower_bound` for a cap, `cost_not_established` for hosts deliberately not
   asked). "Examined 20 hosts" where 115 ran it is the floor-as-fact shape
   this platform keeps finding.

### The expensive case and the uninformative case are the same case

The bimodality is not a cost curiosity, it is a statement about *what those
three hashes are.*

**The denominator, measured rather than inferred:** `observation_floor` on the
hash field enumerates **170 hosts** that executed any hashed process in the
7-day window (181 over 30 days; Falcon's device inventory holds 182). So the
three expensive hashes are on **113, 113 and 115 of 170 — about two-thirds of
the active host set.**

That figure was first written here as "98% of the estate", by dividing 113 by
115 — which is *another hash's host count*, not a denominator.

**And "two-thirds is high" needed a baseline, because without one it is an
inference wearing a measurement's clothes.** So: 173 distinct hashes sampled
from the same 7-day window **in lexicographic key order** — deliberately
uncorrelated with prevalence, since ordering by document count would select
ubiquitous hashes by construction and then discover they are ubiquitous.

| baseline prevalence, 173 ordinary hashes | |
|---|---|
| p50 | **1 host** |
| p90 | 14 hosts |
| p95 | 35 hosts |
| max | 134 hosts |
| on exactly 1 host | 96 (55%) |
| on ≤ 5 hosts | 142 (82%) |
| on ≥ 113 hosts | **4 (2.3%)** |

**The median hash in this estate runs on one host, 82% run on five or fewer,
and only 2.3% reach 113.** So a hash on 113 of 170 sits in the top ~2% of the
prevalence distribution, and "this is an installed component — a signed
binary, an agent DLL, a runtime library" is a reading of a measured extreme
rather than a guess. The claim is kept, with its baseline attached.

(That query returned 0 documents across 360 clean shards on the first
attempt, and was controlled before being believed: the cause was a guessed
tenant pin value — `C00-Indexer`, the cluster's name, where the configured pin
is `manager.name = wm-c00.siembiot.int`.)

Which means **knowing which 113 of 170 hosts hold such a file tells an analyst
very little.** The host list is the product of S1 and S2, and for exactly the
cases that cost ~565 calls it carries almost no information. The 1-host and
2-to-5-host cases are **7 of the 12** and are the ones where a host list
changes what somebody does — and they cost 5 to 25 calls.

So the distribution hands over the design: **cheap where it matters, expensive
where it does not.**

### The design

**Get prevalence cheaply, state it, and enrich per host on demand.**

1. The hash question already returns `host_count` and `hosts` for one
   OpenSearch query (43 ms median, measured over all 223). That is prevalence,
   already paid for.
2. The estate step states it as a fact rather than a host list: *"ran on 113
   of the 170 hosts that executed anything in this window"* — which is the
   finding for a ubiquitous file, and more useful than 113 enrichments would
   be. The denominator travels with the number, because "113 hosts" alone
   invites exactly the division that produced a wrong "98%" in the first
   draft of this section.
3. S1 and S2 then run **per host, on the analyst's click**, so the record says
   `2 of 113 hosts examined` because 2 is what somebody asked for. The `n of
   m` sentence is honest by construction rather than by remembering to add a
   caveat, and the blast radius is one host's five calls.

The cap and async variants both still owe an answer to "how many hosts is
enough", and the measured answer is that there is no such number — the
distribution has no middle to put a threshold in.

### The guardrail: prevalence modulates the enrichment, never the gate

This is the week's recurring failure mode and it would land squarely in the
one feature whose purpose is not to have a false-negative path.

**Prevalence is an input to how much enrichment to pay for. It is never an
input to E1, E2 or the verdict.** A file on 113 of 170 hosts *with a
`true_positive` disposition* is the mass-compromise case — a trojanised
installed component, a poisoned update, a living-off-the-land binary being
abused estate-wide — and it is the single most serious thing this lookup could
ever surface. If high prevalence ever suppresses escalation, the gate has a
hole in it shaped exactly like the worst case.

So, explicitly:

* `host_count` does not appear in any escalation predicate.
* Prevalence may change **what is fetched** (lazily rather than eagerly) and
  **what is said** ("113 of 170 hosts"), and nothing else.
* It may never change **whether a record opens**, and the test for that is a
  fixture with `host_count: 113` of 170 and a `true_positive` resolution,
  asserting the record opens — written **before** the enrichment code, since a
  dangerous-direction test written afterwards is a test of what was built.

---

## 5. The follow-up steps, and that they only run after the record opens

The record opens with the lookup's own results as its first steps — the
fan-out is the evidence that triggered the escalation, so the chain would
otherwise be missing its own premise. Ordinals 1..n are the sources already
asked, at zero additional cost. Then, and only then:

| # | step | measured cost | gated on |
|---|---|---|---|
| S1 | Falcon host panel per host in `host_hashes.hosts` | **5 Falcon calls / 1.44 s per host** (median of 3) | E2 fired, and §4's bound |
| S2 | the estate's log window around the earliest execution per host | 1 OpenSearch query per host | E2 fired |
| S3 | external reputation on the indicator | 1 call per source, **paid credits** | any condition fired |
| S4 | the summary | **1 model call** | the record exists |

S1's bound is §4, which is a design section rather than a note because the
distribution has no middle: p50 is 4 hosts and p95 is 113.

Carried from slices 1 and 2 rather than restated as new: every step records
its cost so the chain shows what escalation bought; a step that could not be
asked is recorded as *No claim* with its reason and never dropped; and S4 sees
the recorded steps, never the raw responses, with `unverified_entities` and
`unverified_numerals` shipping in the same change as the first summary.

---

## 6. The positive control — and the two defects it found

`aka.ms` firing nothing is a negative control, and a negative control alone
cannot distinguish a working gate from an unreachable one. So the gate was run
against an indicator chosen to satisfy it: **sha256 `7600ffe12da441fe…`**,
which the population says has 29 alerts including **2 `resolution:
true_positive`**, and which the estate has executed on 2 hosts.

**The record it opens, measured:**

```
step 1        the gate — why this record exists
steps 2-3     the fan-out: Falcon, the estate          0 extra calls
steps 4-5     S1 Falcon host panel, per host (2)       13 Falcon calls
steps 6-7     S2 estate log window, per host (2)        2 OpenSearch queries
step 8        S3 external reputation                    1 call per source
step 9        S4 the summary                            1 model call

TOTAL          9 steps, 1 model call
               15 follow-up calls + 1 per external source
               1 extra call for the predicate itself (see below)
```

Both S1 steps render a real negative: each host's device resolves in Falcon
and has **0 detections** in the window, which is a measured negative rather
than an absence — the path was controlled against `EXP-22MY264`, which returns
500 (its cap) with 91 keys per record.

The control also broke two things, which is why it was worth running.

### Defect 1 — `falcon.lookup` returns ids, so E1 cannot be evaluated at all

`falcon.lookup(observable_type="hash")` returns `detections` as **20 dicts with
exactly one key: `id`.** It calls `/alerts/queries/alerts/v2`, which returns
composite ids, and nothing fetches the entities. **Every field E1 reads —
`status`, `resolution`, `pattern_disposition_description` — is absent from the
producer the predicate would read.**

E1 was drafted against a corpus paged by hand from the *detail* endpoint. That
is README rule 20 at the seam: the shape was enumerated from the layer that
answered a question I asked directly, not from the layer that would actually
hand the predicate its input. Rule 19's depth clause caught it only because
the control forced the element's keys to be printed.

`lookup_host` does fetch the entities — 91 keys per record, `status` and
`resolution` present — so **the shipped Falcon host panel is unaffected**, and
this is the two-implementations divergence again, with `lookup` as the stale
one. The fix is one call, measured: POST `/alerts/entities/alerts/v2` with the
(≤20) ids, **1 HTTP call**, and the code already exists in `lookup_host`.
→ **backlog 31.**

### Defect 2 — the detection set is capped at 20, unsorted, so a negative E1 is a floor

With the entity fetch bolted on, the predicate was evaluated for real and
returned:

```
status values present:      {'closed': 11, 'new': 9}
resolution values present:  {'false_positive': 11, '<absent>': 9}
E1  any(resolution == 'true_positive')  ->  False   (0 of 20)
```

**False — on the hash chosen because it has two true positives.** `lookup`
asks for `"limit": 20` with **no `sort`**, the hash has 29 alerts, and neither
of the two confirmed records was in the 20 that came back. The gate would have
reported no Falcon evidence on a hash an analyst had twice confirmed: false
exculpation, in the predicate itself, found by the first control run against
it.

The truncation is **detectable for free** — the same response carries
`meta.pagination.total` (29 here, against a limit of 20). So a negative E1
over a truncated detection set is `lower_bound`, not a negative, and the
correct behaviour is to page until the population is covered or to record the
floor. → **backlog 32.**

The gate still opened, via E2, which is what the control was for: the record
exists, the steps are real, the follow-ups were paid and counted. But E1 is
not buildable until 31 and 32 are closed, and the single most important number
in this document is that **the first positive control run against the
predicate produced a false negative.**

---

## 7. What this still does not decide

* `RECENT_DAYS` — gated on `indicator_lookups` reaching 250 rows (§2, E3).
* The DNS and perimeter timing for `first_last_seen` — unmeasured, so
  `cost_not_established` on those fields rather than a guessed bound.
* Whether a *prevented* Falcon detection should carry a different verdict.
  `pattern_disposition_description` contains "Prevention", "Blocked",
  "Quarantine" or "Kill" on **359 of 2,047, and all 359 are `closed`** —
  `false_positive` 313, `true_positive` 41, `ignored` 5. So under E1 a
  prevented detection escalates only via the 41, and the 313 do not. That is
  probably right, a blocked execution being a working control rather than an
  incident, but it is a consequence of the clause rather than a decision
  anyone took. Note also that the 41 are a *superset* relationship worth
  checking before the bound in §4 is designed: prevented-and-confirmed is the
  highest-value evidence Falcon holds here, and it is 2% of the population.
* Which of §4's three bounding designs to build. The measurement says the
  distribution has no middle; it does not say which design the team wants.
