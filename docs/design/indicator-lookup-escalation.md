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

**Cost: 1 additional call** — see §5, the lookup does not currently fetch the
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

## 4. The follow-up steps, and that they only run after the record opens

The record opens with the lookup's own results as its first steps — the
fan-out is the evidence that triggered the escalation, so the chain would
otherwise be missing its own premise. Ordinals 1..n are the sources already
asked, at zero additional cost. Then, and only then:

| # | step | measured cost | gated on |
|---|---|---|---|
| S1 | Falcon host panel per host in `host_hashes.hosts` | **6.5 Falcon calls per host** (13 for 2 hosts, counted) | E2 fired |
| S2 | the estate's log window around the earliest execution per host | 1 OpenSearch query per host | E2 fired |
| S3 | external reputation on the indicator | 1 call per source, **paid credits** | any condition fired |
| S4 | the summary | **1 model call** | the record exists |

**S1's per-host cost makes the cap mandatory, with a number rather than a
worry.** The third true-positive hash the estate had executed ran on **106
hosts** — at 6.5 calls per host that is ~690 Falcon calls for one lookup. The
cap is a `lower_bound` on the step, stated in its sentence; it is not a silent
truncation. A sensible first cap is the hosts holding the earliest executions,
and the step says how many were not asked.

Carried from slices 1 and 2 rather than restated as new: every step records
its cost so the chain shows what escalation bought; a step that could not be
asked is recorded as *No claim* with its reason and never dropped; and S4 sees
the recorded steps, never the raw responses, with `unverified_entities` and
`unverified_numerals` shipping in the same change as the first summary.

---

## 5. The positive control — and the two defects it found

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

## 6. What this still does not decide

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
  checking before the cap in §4 is designed: prevented-and-confirmed is the
  highest-value evidence Falcon holds here, and it is 2% of the population.
* Whether E2's host cap should be the earliest executions or the most recent.
  The 106-host case is the one to decide it against.
