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
`authoritative_clean`, `reputation_available` — gives a list of five, not 198.

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
| ANY.RUN / hybrid | `anyrun_verdict not in {malicious, suspicious}` | yes — `meta.status`, completed on only **45.2%** | **no, deliberately** |

So for four of them the flag already exists and nothing reads it — the same
finding for the third and fourth time in two days. The fix is not new
plumbing; it is consuming a field that is already written.

The ANY.RUN row is a documented decision, not an oversight: requiring
`anyrun == "clean"` once meant a sandbox that never ran blocked every benign
verdict. Worth keeping — but the scale of it belongs on record. **54.8% of
runs have no completed sandbox**, and all of them read as not-flagged.

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
