# False exculpation

**The name for the failure, so it stops being filed as a bug.**

A false positive wastes an analyst's time. A false negative loses a detection.
**False exculpation** is narrower and worse than either: the platform asked a
security tool about an indicator, the tool had something, and we told the
analyst it had nothing. The analyst then de-escalates with our assurance
behind them.

It is worse than silence for three reasons:

1. **It is acted on.** "The EDR has nothing on this host" closes a ticket.
   "The EDR could not be reached" does not.
2. **It is invisible.** Nothing fails. There is no error, no gap, no 0% source
   in a coverage report — just a clean negative that looks like diligence.
3. **It is durable.** The stored result is now evidence. A later reviewer
   reading the case sees that the EDR was consulted and found nothing.

Every absence kind in `app/services/absence.py` exists to prevent this one
thing. `never_observed` is not `0`; `check_failed` is not clean; `no_field_map`
is not "nothing found". The convention is the defence and the naming is the
point of it.

## The instance: Falcon's alert field map

Introduced `c31c089`, 2026-10-14 07:58. Found and fixed 2026-10-15.

```python
ALERT_FILTER_FIELDS = {          # every entry invented
    "domain": "behaviors.domain",
    "url":    "behaviors.domain",
    "ip":     "behaviors.ioc_value",
    "hash":   "behaviors.sha256",
}
```

The Falcon alert record has no `behaviors` key — 0 of 200 sampled alerts
carried one. And the Alerts API answers an unknown field name with **HTTP 200
and zero resources**, so each of those filters returned a clean negative. The
same hash returns **17 rows** under its real name `sha256` and **0** under
`behaviors.sha256`.

So the mechanism was complete: ask a real question, get a syntactically valid
empty answer, store it as "the EDR has nothing", and show it to an analyst.

What makes it an instance rather than a typo is that **the vendor cannot catch
it and neither can a test against a fixture.** A fixture returns what the
fixture author believed the field was called. Only a value the API itself
produced can test a field name, which is why the fix is a standing control
rather than a corrected constant.

## The damage: measured, and zero

Two independent counts, because "it was only a day" is a claim about exposure
and not about damage.

**How many investigations ran through it?** None.

| store searched | result |
|---|---|
| `evidence` rows carrying a `falcon` block | **0** of 2,608 |
| `evidence` rows mentioning `behaviors.sha256` | 0 |
| `evidence` rows mentioning "falcon" anywhere | 61 — all incidental: OpenCTI label lists, an OTX pulse describing "Falcon Sandbox", and alert text naming `CSFalconService.exe` |
| `alert_body_investigation_runs` mentioning "falcon" | 18 — all alert text about `CSFalconService.exe` |
| `email_investigation_runs` mentioning "falcon" | 0 |

The collector was registered but never ran in an investigation that stored
evidence. The broken map was therefore never consulted.

**Would it have mattered if it had?** No — and this is the half that lets
everyone stop worrying, because it does not depend on the collector's call
history.

Every attachment hash the platform has ever stored was re-queried against the
corrected field:

| | |
|---|---|
| attachment records across every email run | 98 |
| distinct email runs carrying attachments | 26 |
| distinct `sha256` | 42 |
| distinct `md5` | 42 |
| **(field, hash) pairs re-queried** | **84** |
| query errors | 0 |
| **hits in Falcon** | **0** |

Both field controls passed before the sweep ran — `sha256` and `md5` each
returned rows for a value read back from a real alert — so the zero is a
measurement and not another empty 200.

**Conclusion: no analyst was ever told the EDR had nothing when it had
something.** The defect was real, the exposure was about 27 hours, and the
sweep is clean.

## What the sweep does not cover

Stated because a clean result is only as wide as its question.

- It asks whether Falcon has an alert matching those hashes **now**. Falcon
  alerts are historical records, so a detection at the time would still be
  present — but Falcon's own alert retention bounds this, and that retention
  has not been measured.
- It covers hashes the platform **stored**. An attachment parsed and not
  stored, or a hash submitted interactively and never persisted, is outside
  it.
- It covers hashes only. The `domain`, `url` and `ip` entries in that map were
  equally broken, but there is no field in the Falcon alert record for any of
  them, so there is nothing to re-query — those kinds now return
  `no_field_map` and always should have.

## How it is prevented, not just fixed

A corrected constant would be the same defect waiting on the next vendor
rename. The fix has three parts:

1. **`alert_filter_field()`** dispatches hashes by digest length — 64 →
   `sha256`, 40 → `sha1`, 32 → `md5`. Filtering an MD5 against `sha256` is the
   same silent zero one level down.
2. **`ALERT_UNMAPPABLE_KINDS`** records *why* domain, URL and IP cannot be
   asked, so the absence is read rather than rediscovered — and the collector
   puts `no_field_map` **on the detections field** instead of returning `[]`.
3. **`alerts_field_control()`** is a standing control, not a one-off probe: it
   reads a value back from a real alert at the field about to be used and
   requires the filter to find it. It runs before any Falcon negative is
   reported, caches only passes, expires hourly, and treats an estate with no
   alerts as `too_little_history` rather than a pass — because a control that
   cannot run has not run.

The Alerts API's refusal to validate field names is a permanent property of
the provider. So the control is permanent too.

## Related

- `docs/problems/a-field-name-is-not-a-question.md` — the generalisation, with
  `data_domains` and `queryName` as its two worked examples.
- `docs/design/falcon-panel.md` — what Falcon can and cannot answer.
- README rule 16: name the other world that produces the same observation.
  Here: "the EDR has no detection" and "the API is ignoring my field name"
  produce byte-identical responses.

---

## The convention only protects code that goes through it

**2026-10-16.** Checking whether anything still authenticates as
`Threat-Analyzer-Owner` meant counting its rows in every column that records a
user acting. Seven columns, **0 in every one**, and the conclusion — nothing
uses this account — was right. It was right by luck. Four of those seven
columns hold a **name**, not a uuid, and comparing them to the account's id
cannot match anything. The real answer in one of them was 5.

The relief is the dangerous part. The conclusion survived, so there was
nothing to notice, and a measurement that cannot find a positive had been read
as a measured negative. That is this document's subject exactly: *we asked,
the tool had something, we said it had nothing.* Only this time the tool was
our own database.

**The platform already has the right kind, and it was not used.** Four columns
that cannot be compared to a uuid are not `0` — they are `cannot_join`, which
is the kind the Falcon coverage work introduced for devices with no hostname,
precisely so that an unjoinable row never renders as an absent one. Nothing
forced it here, because:

> **the honest-absence convention only applies to code that goes through it,
> and investigative queries are where we routinely step outside it.**

`absence.absent(...)` is reached by services, tasks and routes. An ad-hoc
`SELECT count(*)` in a throwaway script has no `absence` import, no kind, no
reason field and no reviewer — it returns an integer, and an integer cannot
say "this comparison was ill-typed". Every protection this platform has built
against absence-read-as-value lives on the far side of a boundary that
investigation work steps over by design, and the investigative queries are
*also* the ones whose answers get written into documents as findings.

Three things that follow, all cheap:

1. **Type the column before comparing it.** `information_schema.columns` is
   one query. Four of seven being varchar was visible before any count was
   taken.
2. **Positive control on every predicate** — README rule 19. A count of a
   value known to be present must come back non-zero, or the zero means
   nothing.
3. **An ill-typed comparison is `cannot_join`, not zero**, even in a scratch
   script. Writing "0 (cannot join: column is varchar, compared to a uuid)" in
   the output costs one line and is the difference between a finding and a
   false negative that happened to agree with the truth.

---

## The sha1 sentinel, and its damage count — 2026-10-16

`ALERT_HASH_FIELDS` mapped a 40-character digest to Falcon's `sha1`. That
field is present on **1,953 of this tenant's 2,047 alerts and carries exactly
one distinct value: forty zeros.** So every SHA-1 indicator lookup filtered a
real digest against a constant and returned a clean zero.

**The field control passed**, which is why this needed its own axis rather
than a patch: the control samples a value the API itself returned — the
zeros — filters on it, gets 1,953 rows, and certifies that the field filters.
It does. It cannot match a real digest. See README rule 19's fourth axis.

### Which path established it

"The field is a sentinel" and "we read it from a path that does not populate
it" are two conclusions with one observation, and neither 73 nor 91 keys was
the schema earlier the same day. Three independent paths, and a control:

| path | result |
|---|---|
| `entities/alerts/v2` via `paged_alerts` | 1,953 carry `sha1`, **1 distinct**, all zeros |
| `queries/alerts/v2` filtering `sha1:'00…0'` | **total = 1,953** — Falcon's own index holds the zeros |
| `entities/alerts/v2` hit directly, no helper | 37 of 50 carry it, 1 distinct, all zeros |
| **control: `sha256` on the same 50 records** | 44 present, **30 distinct** — the path does not flatten hashes |

Settled: the field is a sentinel, not a read-path artefact.

### The damage count — nil, and established rather than assumed

The field-map sweep of 2026-10-12 is the precedent, so the same sweep ran:

| question | answer |
|---|---|
| SHA-1 lookups ever performed on the affected path | **0** of 27 `indicator_lookups` — 8 domain, 4 hostname, 5 ip, 2 url, 1 unparsed, 6 sha256, 1 md5 |
| stored records carrying a Falcon `detections_field` | **0**, across 13 json columns and ~40,000 rows |
| stored verdicts derived from a sentinel comparison | **none** — nothing to re-run or mark |

So no analyst was ever told "the EDR has nothing" on the back of this. The
defect was live and shipped, and it had not yet been exercised.

**One finding from the sweep, and it is a second vendor's sentinel.** Searching
stored evidence for forty zeros returned 370 + 757 + 581 rows, which looked
like damage. Extracting the actual values at their JSON paths showed **none of
them is a forty-zero value**: they are 62-character **JARM TLS fingerprints**
from Hybrid Analysis, whose leading zeros are JARM's own convention for *no
handshake data* — absence encoded as a value, in a second vendor, already
stored in our evidence. `LIKE '%0…0%'` matched a substring of a longer string,
which is the sweep's own version of the trap it was looking for, and the fix
was to extract values rather than grep the serialisation. See backlog 35.
