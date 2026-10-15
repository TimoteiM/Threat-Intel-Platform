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
