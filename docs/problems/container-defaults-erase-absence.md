# A container default erases absence before storage

Found 2026-10-13, by asking why an instrument built to tell absence from zero
reported a number that was true and meant nothing.

## The defect

```python
class IntelEvidence(BaseModel):
    blocklist_hits: list[IntelHit] = []
```

An `IntelEvidence` is serialised with `blocklist_hits: []` whether four
sources were asked and found nothing, or the collector raised before any of
them ran. The two are the same bytes in the database. No downstream check can
recover the distinction, because it was destroyed one layer below storage —
which is why `source_answer_rate_service` could report `intel_blocklists` at
"0% of 2,286" while the truth was 2,198 consecutive collector failures.

This is not a collector bug. It is a schema property, and it is general.

## The scale, and why the sweep is not the work list

Mechanically: **198 distinct field names across 68 models** default to an
empty container, 245 field definitions in total. 132 of those names are read
somewhere in a decision path.

That list is not actionable, and treating it as one would be the mistake. Most
of the 198 are either *outputs* (`findings`, `key_evidence`,
`recommended_steps`, `evidence_refs` — things this platform writes, where an
empty list genuinely means "none produced") or *detail fields* whose
emptiness no branch reads as a claim.

The criterion that matters is narrow:

> **A container default is dangerous when its emptiness is a claim about
> whether an external source answered, and it is read where absence grants
> leniency.**

Applying that to the four expressions in `decision_engine` where absence
lowers risk — `observable_clean`, `anyrun_label_contradicted`,
`authoritative_clean`, `reputation_available` — gives a list of five, not 198 — and the grain split below removes one of
those five, leaving four.

## The actual list

Measured over 2,221 evidence rows, 90 days to 2026-10-13.

| source | read as | is the "was it asked" record present? | consulted? |
|---|---|---|---|
| Google Safe Browsing | `gsb_checked and not gsb_listed` | yes | **yes** — the pattern everything else should copy |
| ThreatFox | `threatfox_checked and not tf_matches` | yes, `feeds_checked` | **yes**, as of today |
| intel blocklists | `intel_checked and not intel_hits` | built today, `sources_checked` | **yes**, as of today |
| **phishtank** | `not phishtank_positive` | **yes** — in `feeds_checked` on 98.3% of rows | **no** |
| **openphish** | `not openphish_listed` | **yes** — in `feeds_checked` on 98.3% of rows | **no** |
| **urlscan** | `not urlscan_malicious` | yes — `urlscan.meta.status`, completed on 98.3% | **no** |
| **http signals** | `not high_conf_http` | yes — `http.reachable` true on 84.1%, `meta.status` completed on 97.9% | **no** |
| ANY.RUN / hybrid | `anyrun_verdict not in {malicious, suspicious}` | yes — `meta.status`, which also emits `skipped` | **no, deliberately** — see the split below |

So for four of them the flag already exists and nothing reads it — the same
finding for the third and fourth time in two days. The fix is not new
plumbing; it is consuming a field that is already written.

The ANY.RUN row needed its grain split before it could be filed, and the
split moves it off this list almost entirely. "54.8% have no completed
sandbox" lumps three states that mean different things:

| state | rows | share |
|---|---|---|
| completed | 1,005 | 45.2% |
| **attempted and failed** | **2** | **0.1%** |
| never attempted (`meta.status = "skipped"`) | 1,214 | 54.7% |
| not applicable to the observable type | 0 | 0.0% |

So the absence-as-value exposure on the dominant dynamic signal is **2 rows**,
not 1,214 — and both of those are
`IntegrityError: UniqueViolation`, a database defect rather than a provider
failure. The 54.7% were never attempted *by policy*: `hybrid_analysis` is in
`OPT_IN_COLLECTORS` and is not part of the default selection. That is a
selection fact, not a hidden failure, and the collector records it explicitly
as `meta.status = "skipped"` — a fourth state the asked/answered question
needs and that none of the other sources emit.

What remains true is narrower and belongs with per-verdict coverage rather
than here: `anyrun_not_flagged` reads "skipped" identically to "ran and found
nothing", so 54.7% of verdicts were reached with no dynamic analysis and the
page does not say so. Not an absence erased by a default — an absence
recorded accurately and never surfaced.

## A fifth, found on the way

`otx` was missing from the answer-rate check's `SOURCES` registry entirely,
and it is **70.5% dead**: `feeds_skipped` carries `otx (error: HTTPError)` on
1,567 of 2,221 rows plus 112 `ReadTimeout`s. The check built to find sources
that stopped answering did not cover one that had — the eighth instance of a
hand-maintained list swallowing an entry with no error. Now added.

OTX is read only in the positive direction (`if otx.get("found")`), so its
silence costs detections rather than producing wrong benign verdicts. That is
the better of the two failure modes and still 90 days of a source nobody knew
was gone.

## The pattern to apply

Two forms, in order of preference:

1. **The value and a sibling flag**, the Google Safe Browsing shape:
   `{"checked": true, "listed": false}`. Consumed as
   `checked and not listed`. Use this when a collector naturally knows
   whether it asked.
2. **`None` plus a named absence**, the `app/services/absence.py` shape: the
   field is `None` and a companion carries `Absent(kind, reason)`. Use this
   when the answer itself is a scalar, where there is no empty-container
   ambiguity to exploit.

What not to do is change 198 defaults to `None`. Most of them are read with
`or []` immediately, so the change would be invisible where it is harmless
and would need a consumer audit everywhere it is not — a large diff whose
risk is concentrated exactly where the current behaviour is already correct.

## The rule

**An absence convention protects only the fields that call it.** The
convention has existed for weeks. The three places that most needed it — the
enrichment payload, the clean precondition, and the instrument built to tell
absence from zero — each expressed "nobody asked" as an empty collection, and
a type cannot defend a field that never constructs it. Check the *default*,
not just the consumer: a schema default is a claim, made once, about every
row ever written.

---

## Worked example, 2026-10-15: a default that erased a security boundary

Same shape, higher stakes, and this one had a comment asserting the opposite.

```python
# alert_log_context_service.build_query
    # A `filter`, not a `should`: this one is not negotiable against the entity
    # match. A query that can return another tenant's logs if the entity clause
    # happens to match is not pinned at all.
    if tenant_field and tenant_values:
        filters.append({"terms": {tenant_field: list(tenant_values)}})
```

Both parameters are declared `= None`. So when either is empty the clause is
simply not added, the function returns a perfectly valid query, and that query
reads **every tenant's logs**. The defect is the two lines of prose directly
above it: they state the requirement correctly and completely, and then the
`if` makes it conditional. **Anyone reading this believed the comment.** It is
the most carefully explained version of the bug it describes.

The caller completes the circuit with the same shape one level up:

```python
tenant_field = str(getattr(settings, "opensearch_tenant_field", "") or "")
tenant_values = list(getattr(settings, "opensearch_tenant_value_list", []) or [])
```

`or ""` and `or []` convert "this deployment has no pin configured" into "pass
nothing", which `build_query` then reads as "no pin wanted". Three independent
places where an absence becomes a value, cooperating.

Verified rather than reasoned: calling `build_query` with no tenant arguments
returns a body with **one** filter clause — the time range — and no tenant
terms. It does not raise and does not return `None`.

### Why it belongs in this document rather than its own

It is not a schema default, but it is the same claim made the same way: *the
absence of a value is indistinguishable from a decision not to filter.* The
`IntelEvidence` version lost a distinction in a report. This version loses
tenant isolation. The lesson generalises in the direction of severity, not
away from it.

### What distinguishes it from the version that was already fixed

`OpenSearchEstateClient` reaches the same cluster and refuses:

```python
if not tenant_field or not tenant_values:
    raise RuntimeError(
        "this tenant has no log-store tenant pin ... so the query is "
        "refused rather than run unpinned")
```

Two paths to one cluster, written months apart, one raising and one silently
proceeding — which is why the fix is not "add the clause in the second place".
It is to move the refusal **below both**, into the client, so that a third path
written next year cannot be written wrong. See
`docs/design/opensearch-tenant-pin.md`.

### The reading rule this adds

A comment that states an invariant is evidence about intent, never about
behaviour. **Where a comment asserts something is "not negotiable",
"always" or "unconditional", read the next line expecting a conditional** —
that pairing is where the strongest claims and the weakest enforcement collect,
because the author wrote the prose while believing the code already said it.


---

## The vocabulary of refusal needs the same accuracy as the answers

A third instance, 2026-10-15, and it is not a default at all — it is a
*reason*. Which is the point: the convention has spent its effort on making
absences distinguishable from zeros, and comparatively none on whether the
absence chosen is the **true** one.

The indicator lookup refused hashes against the estate as `out_of_scope`:

> "The estate's log store holds DNS queries and perimeter traffic. No field in
> it carries a file hash, so this is an absence of capability and not an
> absence of the file."

Confidently worded, correctly typed, and false. `data.win.eventdata.hashes`
carries **2,626,536 documents across 190 hosts**, spanning the full 120-day
retention. The field was there the whole time. What was actually unknown was
the *query cost*, because the value is a composite
`MD5=…,SHA256=…,IMPHASH=…` string needing a leading wildcard.

### Why this is worse than a wrong answer

**`out_of_scope` is an absence that is wrong toward permanence.** Its meaning
is "there is nowhere to look", and its effect on a reader is *never ask this
again*. A wrong `check_failed` invites a retry. A wrong `never_observed`
invites a wider window. A wrong `out_of_scope` **deletes a capability from
everyone who reads it**, including the person who wrote it, six months later.

And it propagates into tests. `test_hashes_go_to_falcon_and_not_to_the_estate`
asserted the refusal, so the false premise acquired a guard defending it —
which is how a wrong absence becomes permanent rather than merely wrong.

### The fix, and the general rule

A new kind, `cost_not_established`: *there is somewhere to look and nobody has
measured what asking costs.* It invites the measurement rather than closing
the question, and it carries the figures so a reader can judge. Measuring took
four queries and found 7 days at 161 ms — so the honest outcome was not a
better refusal but **a bounded answer**, which is the second lesson: a refusal
built on a false premise had been standing in for a feature.

**The rule: an absence is a claim, so classify it as carefully as a number.**
Before writing one, ask which way it is wrong if it is wrong. Prefer the kind
that invites the next question over the kind that forecloses it, unless
foreclosure is actually established — and "I have not looked" is never
established.

A short vocabulary check, by what each one tells the next reader to do:

| kind | tells the reader |
|---|---|
| `check_failed` | try again |
| `never_observed` | widen the window, or accept a real negative |
| `too_little_history` | wait |
| `cost_not_established` | **measure it** |
| `no_field_map` | look elsewhere |
| `out_of_scope` | **stop asking** |

The last one is the only one that costs something permanent, and it was the
one reached for without evidence.

### A footnote worth more than the finding

Measuring the cost then exposed a second defect that the refusal had been
hiding: the wildcard was **case-sensitive**. Sysmon stores digests uppercase;
`detect()` lowercases every hash, and lowercase is what every tool and every
analyst pastes. Same needle, same window: uppercase 9,636 hits, lowercase
**0**. Every hash lookup would have returned a confident nothing.

That defect was unreachable while the capability was refused. **Clearing a
false refusal exposes code that has never run** — the same shape as clearing a
long-standing test failure, one layer out.
