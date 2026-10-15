# A first-seen that was really a collection start

**Status:** fixed in the service, 2026-10-15. One input still missing — see
"What is still owed".

**Constraint, not an observation:** on this estate a `first_seen` from
`data.win.eventdata.queryName` cannot reach further back than **2026-10-02**,
whatever the retention window says. Any sentence built on one must say so.

## The claim that was wrong

On 2026-10-15 the estate DNS lookup reported, for email run 113:

> `aka.ms` — First resolved 1 week before this email (2026-10-02 11:49 UTC) —
> consistent with ordinary infrastructure rather than with this message.

Every number in it was right. The conclusion was not. I had checked the
aggregation was complete (`timed_out: false`, 360 of 360 shards, 0 failed) and
that the field had 4,467,459 documents back to 2026-06-17, and concluded the
October date was the domain's history rather than the field's.

The challenge that broke it needed no query: `aka.ms` is Microsoft
infrastructure resolving on 46 hosts, so it should be present from the
retention floor. A date four months inside the window does not fit.

## What the measurement showed

Weekly histogram, all documents carrying `queryName`, tenant-pinned, full
retention:

| week of | docs | hosts | distinct names |
|---|---|---|---|
| 2026-06-15 | 64 | 47 | 49 |
| 2026-07-13 | 178 | 82 | 87 |
| 2026-08-31 | 85 | 60 | 64 |
| 2026-09-21 | 134 | 79 | 70 |
| **2026-09-28** | **642,806** | 156 | 4,513 |
| 2026-10-05 | 2,569,588 | 174 | 14,576 |
| 2026-10-12 | 1,256,298 | 168 | 9,839 |

A step of roughly 5,000×, and `aka.ms` has **0** documents before Oct 1
against 3,464 after — on a complete aggregation, so this is the step branch
and not an index-coverage one.

The two periods are not even the same event:

| period | rule | eventID | meaning | docs |
|---|---|---|---|---|
| Jun 01 – Sep 27 | 61109 | 1014 | DNS resolution **timed out** | 1,966 |
| Sep 29 – now | 103700… | 22 | Sysmon **DnsQuery** | 4,468,578 |

Before 2026-10-02 there were **2** event-22 documents in four months. So
`queryName` existed for the whole window while carrying the opposite meaning:
a lookup that *failed*. Counting those as contact answers backwards — a name
nothing in the estate could reach reads as a name a host visited.

## Why the existing guard could not catch it

`AT_WINDOW_EDGE` compared `first_seen` against the start of the retention
window. The real limit was 107 days inside that window, so nothing was ever
near the edge and the guard was silent by construction. It was not a weak
threshold; it was the wrong reference point.

The damage is directional and quiet. Collection beginning recently makes
*every* first-seen recent, so the discriminator does not merely weaken — it
inverts. Long-standing infrastructure reads as "first contacted around the
time of this email", which is the finding. A panel that says that confidently
is worse than no panel.

## What the floor actually is

Measured, not assumed, and measured **per host** — because the floors differ:

| per-host first event-22 + `queryName` doc | hosts |
|---|---|
| 2026-08-22 | 1 |
| 2026-09-24 | 1 |
| **2026-10-02** | **140** |
| 2026-10-03 … 2026-10-12 | 33 |

A single global floor is set by whichever host started earliest — two
outliers here — giving 2026-08-22, which nothing ever reaches. That makes the
grace window dead code and reinstates the bias. The floor for an indicator is
therefore the **earliest floor among the hosts that actually hold the value**:
earliest, because a host that was collecting from the start and still did not
resolve the name until later is the evidence that the name is new.

And the floor must be measured on **the same predicate as the first-seen
query, minus the value**. Dropping just the `exists(queryName)` clause moved
the floor from 2026-08-22 to 2026-06-20 — event-22 documents exist that do not
carry the field. A looser predicate always gives an earlier floor, the grace
window never fires, and the bias comes back in through the instrument.

## The second wrong number: the baseline

The same sentence said "before this email" and measured against
`email_investigation_runs.created_at` — the **upload time**. Three anchors are
available and two are wrong:

- the **`Date` header** is written by the sender's client. A phishing message
  can set it to any value, and a backdated one turns every estate hit into
  "ordinary infrastructure" — including the attacker's own domain.
- the **upload time** is when an analyst opened the investigation. For any
  retrospectively reported message it is late, so a domain registered after
  the mail but before the upload reads as pre-existing.
- the **earliest `Received` header our own infrastructure wrote** is the only
  one of the three our side produced.

"Earliest `Received`" alone is also wrong, and wrong in the same direction as
`Date`: headers are prepended, so the bottom of the chain is the oldest *and*
was written by the sender's MTA. A `min()` over the chain is a forgeable value
wearing the costume of a measurement — and an attacker can inject a header
claiming `by` our own MX, so matching our identity anywhere in the chain is
forgeable too. What is not forgeable is **position**: our MTA prepends above
everything that arrived with the message, so our headers are a contiguous run
at the top. The anchor is the earliest header in that run, and the run ends at
the first hop that is not ours.

No anchor is `check_failed`. There is deliberately no fallback, because every
fallback available substitutes an attacker-controlled value for a missing
trustworthy one while keeping the confident wording.

## What changed

- `DNS_EVENT_QUERY = "22"` pinned via `_SEMANTIC_FILTERS`, applied to the DNS
  question only — `data.dstip` comes from an appliance that writes no Windows
  event id, so the pin would zero it.
- `OpenSearchEstateClient.observation_floor()` — per-host collection start on
  the lookup's own predicate; raises `PartialResult` on an incomplete
  aggregation, because a partial `min` is a *later* floor than the truth,
  which widens the grace window and hides the first-seens it exists to flag.
- `AT_WINDOW_EDGE` → `AT_OBSERVATION_FLOOR`, against the measured floor.
- `relative_to()` requires `floor` and `anchor_statement`; both sentences now
  state the observable history span, so "before this email" cannot be read as
  unbounded.
- `lookup()` refuses a `reference_time` with no `reference_anchor` — the
  mistake is unwriteable rather than discouraged, and the store is not queried
  for a comparison that cannot be made.
- `app/services/email_anchor.py`, and `email_ioc_service` resolves the anchor
  **at parse time** for both `.eml` and `.msg`.

## Verified live, 2026-10-15

| indicator | hosts | floor (its hosts) | first_seen | gap | was | now |
|---|---|---|---|---|---|---|
| `aka.ms` | 47 | 2026-10-02 11:27:31 | 2026-10-02 11:49:42 | **22 min** | `pre_existing` | `at_observation_floor` |
| `eur04.safelinks…` | 2 | 2026-10-02 11:41:51 | 2026-10-05 12:31:24 | 72.8 h | `pre_existing` | `pre_existing` |

The 22 minutes is worth recording: even the original two-hour threshold would
have caught `aka.ms` *once the floor was the floor*. The grace window was
never the defect, which is why it is now sized by which direction of error
hurts rather than by this sample.

## What is still owed

1. **`EMAIL_OWN_MTA_IDENTITIES` is empty**, so every run resolves
   `check_failed` for its anchor. The value is a fact about the customer's
   mail path — which hosts receive their mail — and cannot be guessed: a
   wrong entry trusts a chain we do not own. Until it is set, the estate panel
   can report hits and absences but **no before/after sentence**.
2. **The 38 existing runs cannot be backfilled.** `email_investigation_runs`
   has no raw-email column and does not retain the Received chain — exactly
   one of the 38 contains the string "received" anywhere in its stored result.
   Their anchors are unrecoverable; they stay `check_failed`.
3. **The floor will move.** It is measured per call rather than cached, so it
   follows retention forward; but when the October indices age out, the floor
   becomes retention again and the two limits swap which one binds. Nothing
   needs changing for that — it is the reason the floor is `max`-like by
   construction rather than a constant.
