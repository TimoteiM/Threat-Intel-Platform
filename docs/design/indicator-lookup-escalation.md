# Slice 3 — the escalation rule on the on-demand indicator lookup

**Status: specification. Nothing here is built.**

Slice 3 of the investigation record. Slices 1 and 2 gave the email pipeline and
the alert pipeline a recorded chain of claims; this one decides *when an
on-demand lookup becomes an investigation at all*.

The shape is settled and is not reopened here:

* A **clean** lookup stays a fan-out. It renders the per-source answers it
  already renders, it never grows a second page, and it pays for nothing
  further.
* A **suspicious or malicious** lookup opens an investigation record. The
  lookup page gains **one line**, linking to it.

Everything below is the two things that shape leaves open: what counts as
escalation, and what runs once it does.

---

## 1. Escalation is a predicate over the lookup's own results

Not a model's opinion, and not a score. The lookup has already asked every
source it can ask; the predicate reads what came back. That makes it
auditable, free, and identical on every re-run of the same lookup.

It reads the real result shape — `app/api/indicator_lookup.py` builds
`sources.falcon.answer` and `sources.estate`, and the keys below were
enumerated from live records rather than inferred from the code that consumes
them (README rule 19, including the depth clause: the element shape of a list
is part of the listing).

### E1 — Falcon has an *open* detection on the hash

```
any(record for record in sources.falcon.answer.detections
    if status_of(record) not in CLOSED_STATUSES)
  or any(record.resolution == "true_positive" for record in ...)
```

**`detections` being non-empty is not escalation, and this is the measurement
that settles it.** The 600 most recent Falcon alerts in this estate, read from
`/alerts/entities/alerts/v2` on 2026-10-16 and spanning
2026-09-19 → 2026-10-15 by `created_timestamp`:

| `status` | `resolution` | records |
|---|---|---|
| `closed` | `false_positive` | **566** |
| `closed` | `true_positive` | 1 |
| `new` | *(none)* | 33 |

94% of the estate's recent detections were closed as false positives **by the
customer's own analysts**. A predicate of "Falcon returned a row" would open an
investigation record on evidence the customer has already judged and
dismissed, which is a worse failure than staying quiet: it spends the record on
the one population we know is noise.

Three element-level traps in the same records, each of which would have been a
silent wrong answer:

* **`is_closed` is not the closed indicator.** It is `None` on 593 of 600 and
  `True` on 7. `status` is the field; a predicate on `is_closed` would treat
  all 566 closed records as open.
* **`severity_name` cannot rank the open ones.** It is `None` on exactly the 33
  `new` records, and `Informational` on 545 of the 567 closed. Severity is
  populated for the population we discard and absent for the one we keep.
* **A closed `true_positive` must still escalate.** One record in 600. The EDR
  detected it and an analyst *confirmed* it — that is the strongest evidence in
  the whole source, and a naive "open only" predicate drops it.

`CLOSED_STATUSES` already exists in `falcon_host_panel_service` as
`{closed, reopened_closed, false_positive}` and is reused rather than
re-declared. Only `closed` and `new` appear in this sample, so the other two
are carried on the panel's authority, not on a measurement here.

**Cost: zero additional calls.** The detections are already in hand when the
predicate runs.

**Verdict contributed: `malicious`.** An open detection, or a confirmed one, is
the EDR saying this executed and was judged bad.

### E2 — the estate executed it

```
sources.estate.host_hashes.observed is True
```

`estate_lookup_service.hash_lookup` answers on Sysmon **event 1 (Process
Create) only** — what ran, not what was loaded into another process (event 7)
or merely seen on disk (event 29). `observed` is the trigger; `documents` and
`host_count` are the scale and belong in the record's text, not in the
predicate.

**`observed: False` is only a negative when it is an answer.** The same section
carries a named absence instead whenever the question was not asked —
`unparsed` for a non-digest length, `cost_not_established` beyond the 30-day
measured ceiling, `check_failed` when the search did not complete. None of
those is `observed: False`, and none of them escalates *or* reads as clean.

**Cost: zero additional calls.**

**Verdict contributed: `suspicious`.** Execution in the estate is not a
judgement about the file; it is a statement that the question now has a host
attached to it.

### E3 — the estate's contact with it is new

**This condition cannot be written as stated, and the substitute needs a
measurement before it is built.**

As stated — "a first-seen after the reference time" — it is not expressible
here, for two independent reasons:

1. `_estate()` in the lookup route passes **no** `reference_time`, by design:
   an on-demand lookup has no email, so there is no anchor our own
   infrastructure wrote, and `estate_lookup_service.lookup` refuses an unnamed
   one. Without it, `first_seen` and `relative_to_reference` are never
   computed — the first-seen query is only paid for on a hit *when a reference
   time exists*.
2. Even if the lookup's own request time were named as the anchor, the
   comparison is **vacuous**: `first_seen` is always in the past and the
   request time is now, so "first seen after the reference" is false by
   construction. It would be a condition that can never fire, which is worse
   than a missing one.

So: **ask what the value was for.** On the email surface this condition means
*the estate's contact with this indicator began after the mail arrived* — the
mail plausibly caused it. On demand there is no triggering event to be after,
and the thing worth keeping is the other half: **the contact is recent.**

The on-demand form, therefore:

```
first_seen is a timestamp (not an absence)
  and first_seen is not AT_OBSERVATION_FLOOR
  and (now - first_seen) <= RECENT_DAYS
```

The floor clause is the one that stops this being the `aka.ms` bug again.
`observation_floor()` is per host on the same predicate, and a `first_seen`
sitting at the floor means *collection started then*, not *contact started
then* — which is exactly how a Microsoft telemetry endpoint read as a new
contact on 2026-10-02. A floor-bounded first-seen is `lower_bound`, and it
neither escalates nor reads as old.

Two things this needs before it can be built:

* **`want_first_seen` on the estate lookup.** The first-seen query is
  independent of the before/after comparison, and today it is gated behind a
  `reference_time` it does not need. Passing a fake anchor to trigger a query
  would be a lie in a field whose whole purpose is to stop that class of lie.
* **`RECENT_DAYS` is unset and must be measured, not chosen.** A threshold
  picked from intuition decides how often this fires. The measurement is the
  distribution of `first_seen` over the indicators actually looked up on
  demand — and `indicator_lookups` currently holds 27 rows, which is not a
  distribution. **So E3 ships disabled, as `cost_not_established`, until there
  are enough lookups to measure it against.** E1 and E2 do not depend on it.

**Cost when enabled: 2 OpenSearch queries per hit** — `first_last_seen` and
`observation_floor`, both over the full 120-day retention rather than the
lookup's window, because a 7-day window cannot answer "months" and its edge
would read as a first-seen. Timed for the hash path (24h 83 ms, 7d 161 ms, 30d
422 ms, 120d 1.7 s warm / 4.3 s cold); **not timed for the DNS and perimeter
fields**, so for those it is `cost_not_established` until it is.

**Verdict contributed: `suspicious`.**

### What does not escalate, and the case that matters

`aka.ms` is the test. It is resolved by hundreds of hosts, it has a `first_seen`
pinned at the collection floor, it has no Falcon detection, and it is not a
hash so E1 and E2 cannot fire at all. **Nothing fires, the record never opens,
and the follow-up steps in §2 are never paid for.** That is the entire purpose
of the gate, and any change to the predicate is checked against this case
first.

### The third verdict the shape collapses

"A clean lookup stays a fan-out" has a hole in it: a lookup where a source
*could not answer* is not clean.

| verdict | when | opens a record? |
|---|---|---|
| `malicious` | E1 | yes |
| `suspicious` | E2 or E3 | yes |
| `clean` | no condition fired **and** every source that could be asked answered | no |
| `unknown` | no condition fired and at least one source returned `check_failed` | **no** — but it must not say *clean* |

`unknown` opens no record, because there is nothing to investigate — but it
cannot render as the clean case. A Falcon field control that failed, or an
estate search that did not complete, is the absence-read-as-value shape that
false exculpation is made of. The page states which source could not answer.

A source that is `out_of_scope` or `no_field_map` for this kind of indicator —
Falcon on a domain, the estate on a URL — does **not** make a lookup
`unknown`. Nothing was asked because nothing could be, that reason is already
on the page, and treating a structural non-question as a failed one would make
every domain lookup permanently inconclusive.

---

## 2. The follow-up steps, and that they only run after the record opens

The gate is the product. These steps exist because an escalated indicator
deserves them, and the reason they are listed separately from §1 is that
**none of them may run while the predicate is being evaluated.**

The record opens with the lookup's own results as its first steps — the
fan-out is the evidence that triggered the escalation, so the chain would be
missing its own premise otherwise. Ordinals 1..n are the sources already
asked, at zero additional cost. Then, and only then:

| # | step | cost | gated on |
|---|---|---|---|
| S1 | Falcon host panel for each host the estate named in `host_hashes.hosts` | 2 Falcon calls per host (device query + alerts) | E2 fired, so there are hosts |
| S2 | The estate's log window around the earliest execution on each host | 1 OpenSearch query per host | E2 fired |
| S3 | External reputation on the indicator (VirusTotal and the other configured sources) | 1 external call per source, **paid credits** | any condition fired |
| S4 | The summary | **1 model call**, at the end, over the recorded steps only | the record exists |

Four constraints on those, carried from slices 1 and 2 rather than restated as
new:

* **Every step is recorded with its cost**, so the chain shows what the
  escalation bought. A step that was not asked is recorded as *No claim* with
  its reason, never dropped.
* **S1 and S2 are per host and must be bounded.** `host_hashes.hosts` can be
  long — the hash question returns every host that ran the image. A cap is a
  `lower_bound` on the step, stated in its sentence, not a silent truncation.
* **S4 sees the recorded steps, never the raw responses.** One model call, at
  the end, for the summary only, with `unverified_entities` and
  `unverified_numerals` computed in the same change that introduces it — the
  spec condition from slice 1, not a follow-up.
* **S3 is the only step that spends money per run.** It is listed last among
  the paid steps on purpose: if the enumerated conditions turn out to fire more
  often than expected, S3 is the one to put behind a second gate, and the
  record's own cost counters are what will say so.

---

## 3. What this does not decide

* `RECENT_DAYS` for E3 — needs the first-seen distribution over real on-demand
  lookups, and there are 13.
* The DNS and perimeter timing for `first_last_seen` — unmeasured, so
  `cost_not_established` on those fields rather than a guessed bound.
* Whether a *prevented* Falcon detection should carry a different verdict from
  one that was merely detected. `pattern_disposition_description` contains
  "Prevention", "Blocked" or "Quarantine" on **22 of the 600 — and all 22 are
  `closed`.** So as E1 is written, a prevented detection never escalates
  unless its resolution is `true_positive`: the EDR stopped the file, an
  analyst closed the alert, and the lookup will report an open-detection count
  of zero. That may well be right — a blocked execution is a *working* control,
  not an incident — but it is a consequence of the open-only clause rather than
  a decision anyone made, and it should be decided on the first real case.
