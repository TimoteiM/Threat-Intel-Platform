# CrowdStrike Falcon — where it stands, end of 2026-10-15

> **Population corrected 2026-10-21.** This document referred to the
> Falcon tenant as a customer's. It is **Expertware's own estate** —
> CrowdStrike reports one CID across 176 of 176 devices, every domain an
> `expertware.net` domain. The measurements stand; the word "customer"
> did not. See `docs/measurements/POPULATION.md`.

**Written for:** whoever picks this up next, including me tomorrow.

At 09:00 Falcon had a verified credential and a successful ping, and nothing a
user could see. It now has a panel on the alert page, driven by real data, and
one live false-negative defect was found and closed on the way.

## What a user can see now

On any alert investigation whose run names a host, at the bottom of the log
section: **CrowdStrike Falcon — this host.**

- **EDR coverage** — sensor installed or not, OS and build, sensor version,
  status, prevention policy, reduced-functionality mode, site, domain, first
  and last seen. "No sensor on this host" renders as a *finding*, because the
  Devices API validates `hostname` (an unknown field is a 400), so the empty
  result is a real negative.
- **Detections** — grouped by (name, filename), headline is **distinct open**
  detections. Tactic, technique, file, user, disposition, status per group.
  Closed ones collapse. The raw row count is behind a disclosure, labelled as
  repetition.
- **The window actually covered**, which is not always the window requested.
- **The field control's state**, in the footer, because every "nothing found"
  above depends on it.

Verified live, through the route, on real runs:

| host | result |
|---|---|
| `EXP-22MY264` | managed, Windows 11 build 26200, sensor 7.40.21309.0, prevention applied — **4 open of 9 distinct** from 500 raw rows |
| `ExpDC001` | managed, Windows Server 2016, sensor reporting, 0 detections |
| `EXP-26ML4Y2` | managed — *"Covers 4 days, not 30: this host's sensor was enrolled 2026-10-11"* |

Reach: 95.3% of alert runs in the last 7 days carry an `entity_host`
(1,993 of 2,091); 89.4% of hosts in SIEM alerts match a Falcon device on a
plain case-insensitive hostname compare.

## The defect found, and why it is worth remembering

`ALERT_FILTER_FIELDS` mapped every indicator kind to `behaviors.*`. **The
Falcon alert record has no `behaviors` key** — 0 of 200 sampled alerts carry
one — and the Alerts API answers an unknown field name with **HTTP 200 and
zero resources**. So every hash lookup returned "the EDR has nothing" while
the field worked perfectly under its real name: the same hash gives 17 rows as
`sha256` and 0 as `behaviors.sha256`.

That class is now named in `docs/problems/false-exculpation.md`: we asked, the
tool had something, and we told the analyst it had nothing. Worse than a false
negative because it is acted on, invisible, and becomes evidence.

**Damage: none, measured two ways.** No evidence row has ever carried a
`falcon` block (0 of 2,608), and all 84 stored attachment-hash/field pairs
across 26 email runs re-queried against the corrected field return **zero
hits, zero errors** — with both field controls passing first, so the zero is a
measurement and not another empty 200.

## Measured vs assumed

Everything load-bearing was measured today. What that means for each claim:

| claim | basis |
|---|---|
| 182 devices, 2,048 alerts | unfiltered queries |
| alert retention reaches 2026-07-17 (90 days) | oldest alert, sorted ascending; `>'2024-01-01'` returns the same total as `>'2026-06-01'`, so no silent clamp |
| 90 days is the tier-independent figure for detections | community sources only — **no official CrowdStrike page found**, so the measurement is the authority and 90 is a sanity bound |
| hostname join needs no normalisation | 160/179 exact, 0 needing suffix stripping |
| Devices validates fields, Alerts does not | 400 vs 200-with-zero, probed both ways |
| intel / iocs / falconx / scanner unavailable | 403 scope-not-permitted, re-measured today |
| no alert field carries a domain or a remote IP | every candidate probed, all 200/0 |

Nothing in the panel now asserts a window it has not established: an
unmeasured retention floor withholds the window claim rather than defaulting
to what was asked.

## Open questions

1. **A step change in Falcon alert volume, then silence — and the dataset
   that would explain it cannot be read.** See the section below; this is no
   longer "ambiguous", it is a confirmed step with an unreadable cause.
2. **Can this API client be granted the intel scope?** If yes, "what does
   CrowdStrike know about this indicator" becomes answerable and the email
   panel gains a real question. If no, the 403 should be recorded once as a
   capability absence rather than retried per investigation. Needs someone with
   Falcon console admin.
3. **Are `DC`, the two SQL servers and `dns1` deliberately out of EDR scope?**
   A question for whoever owns the licence count — see the coverage document.

## Still to build, in order

1. **Attachment-hash lookup on the email panel.** The only Falcon question an
   email can ask. The field name is now correct and control-gated, so this is
   small. Not domains, not the sender IP — neither exists in Falcon.
2. **The coverage view in the product.** The 19-host gap is currently a
   document (`docs/outbound/falcon-edr-coverage-gap.md`) rather than a page.
   The join is measured and sound, so this is reporting work, not research.
3. **Stale-sensor list.** 9 of 182 devices last reported over 31 days ago, 10
   more between 8 and 30 days. Covered on paper, possibly not in fact — a
   different list and a different fix from the 19.
4. **Falcon ingest** (polling detections into the alert pipeline) is still a
   separate pass and still needs `_create_alert_run` extracted from the API
   module first, plus a field map that quarantines unmapped fields, plus a
   decision on Falcon's own MITRE attributions as a third technique namer.
   `integration_directions` says `enrichment` alone, correctly.

## Consolidation debt I created

- Four hand-rolled `${h}h ago` formatters remain (`watchlist`, `clients`, the
  dashboard, `DevicesTab`). `src/lib/time.ts` is the one to grow into; only
  the Falcon panel and the two integrations-card sites use it so far.
- `FalconHostPanel` renders `detections.basis` and the footer's
  `field_control`; the first is now deliberately one short sentence so the two
  do not say the same thing twice.

## Where things live

| | |
|---|---|
| client | `backend/app/integrations/falcon_client.py` — `lookup_host`, `alerts_field_control`, `alert_retention_floor`, `alert_filter_field` |
| shaping | `backend/app/services/falcon_host_panel_service.py` — `coverage`, `group_detections`, `effective_window`, `unjoinable` |
| route | `GET /api/alert-investigations/{run_id}/falcon` |
| panel | `frontend/src/components/report/FalconHostPanel.tsx` |
| what it can answer | `docs/design/falcon-panel.md` |
| the failure class | `docs/problems/false-exculpation.md` |
| field names | `docs/problems/a-field-name-is-not-a-question.md` |
| coverage gap, for handing on | `docs/outbound/falcon-edr-coverage-gap.md` |

Tests: 32 panel service, 15 field control. Full unit suite at the enumerated
14 tolerated failures, diffed by name. Frontend typechecks and builds.

Branch `feature/email-investigation-upload` at `f0a0ae7`, pushed. Liveness
green on all limbs.


---

# The alert step change, 2026-09-14

Added after the first version of this note called the silence "ambiguous". It
is not. Two corrections to my own figures first, because both were wrong in
the direction that made the series look benign.

**The series was undercounted.** I built it from paired bounds,
`created_timestamp:>'A'+created_timestamp:<'B'`, which silently drops rows:
the buckets summed to 1,888 of 2,048 — 7.8% missing. Rebuilt from
*differences of single-bound cumulative totals*, which reconciles **exactly**
to 2,048:

| week of | alerts | |
|---|---|---|
| 2026-07-13 | 15 | (partial — retention begins 07-17) |
| 2026-07-20 | 79 | |
| 2026-07-27 | 73 | |
| 2026-08-03 | 117 | |
| 2026-08-10 | 82 | |
| 2026-08-17 | 52 | |
| 2026-08-24 | 26 | |
| 2026-08-31 | 80 | |
| 2026-09-07 | 33 | |
| **2026-09-14** | **1450** | the `wsl.exe` flood on `EXP-22MY264` |
| 2026-09-21 | 9 | |
| 2026-09-28 | 20 | |
| 2026-10-05 | 12 | |
| 2026-10-12 | **0** | |
| after 10-19 | 0 | |

**And I compared the wrong things.** I read the zeros against the whole
period, which includes the flood and makes the baseline meaningless. Split at
the flood:

| | weeks | mean | min | max |
|---|---|---|---|---|
| before (excl. partial first) | 79, 73, 117, 82, 52, 26, 80, 33 | **67.8** | 26 | 117 |
| after | 9, 20, 12, 0 | **10.2** | 0 | 20 |

A **6.6× drop**, and — the part that settles it — **the two ranges do not
overlap**: the quietest pre-flood week (26) is higher than the busiest
post-flood week (20). That is a step change, not a low tail. My earlier
"within the baseline" reading was an artifact of pooling across the step.

The silence itself is confirmed independently of the bucketing:
`created_timestamp:>'2026-10-08'` returns **0** on a single-bound query. Seven
days. Sensors are live — 153 of 182 devices checked in within a day — so it is
not a sensor outage.

## What the audit log shows: it cannot be read

The hypothesis worth testing is that an exclusion or policy change was added in
response to the flood, broad enough to suppress real detections. That would
produce a quiet estate and a stopped flow at once. **This credential cannot
test it.**

| what would answer it | result |
|---|---|
| `/policy/queries/ml-exclusions/v1` | **403** scope not permitted |
| `/policy/queries/ioa-exclusions/v1` | **403** |
| `/policy/queries/sv-exclusions/v1` | **403** |
| `/policy/queries/prevention/v1` | **403** |
| `/policy/queries/sensor-update/v1`, `firewall`, `device-control`, `response` | **403** |
| `/audit-events/queries/audit-events/v1` and variants | **404** — not the right paths |
| `/sensors/entities/datafeed/v2` (Event Streams) | **200**, but forward-only from connection; it cannot answer about September |

So the outcome is neither of the two the question anticipated. It is not "a
confirmed exclusion explains the silence", and it is not "no change found".
It is **`check_failed` on the exclusion question** — the record of whether an
exclusion was added is not readable with these scopes, and absence of evidence
here is absence of access, not absence of a change.

## What *is* visible, without diagnosis

Device records carry per-policy application dates, which are in scope. Three
facts, offered as coincidence and not as cause:

1. **A sensor_update policy was applied to 142 of 182 devices on 2026-09-15
   and 2026-09-16** — inside the flood week, immediately before the drop. That
   cohort now runs 7.40.21309.0 (100), 7.39.21113.0 (29) and 8.10.21408.0
   (13). A sensor rollout is not an exclusion, but a sensor version change can
   change detection behaviour, and this is the only fleet-wide event visible in
   that week.
2. **No fleet-wide prevention-policy change.** Prevention was applied to 1–4
   devices per day through September and October, with the bulk (152 of 182)
   back in August — before the flood. Five distinct prevention policies, five
   distinct `settings_hash` values. Note the limit: a policy's *contents* could
   have been edited without that being visible here, so this rules out mass
   reassignment, not editing.
3. **A fleet-wide `global_config` application on 2026-10-13/14/15** (80, 61,
   12 devices). That is *after* the silence began on 10-08, so it cannot
   explain it, and the monthly pattern (3 in August, 12 in September, 165 in
   October) is as consistent with routine re-application as with a change.

## Correction: there are two events, not one

The first version of this section said the drop was confined to the
sensor-update cohort. **That claim holds for the mid-September step and is
wrong for the October stop**, and the error was pooling: the per-cohort rates
were computed over "21 Sep onward", which spans a *second* inflection.

Per cohort, by week, nothing averaged:

| week of | updated (142) | not updated (40) |
|---|---|---|
| 31 Aug | 83 | 8 |
| 7 Sep | 24 | 9 |
| **14 Sep** | **1427** | 1 |
| 21 Sep | 9 | **23** ← its last |
| 28 Sep | 9 | 0 |
| 5 Oct | 19 | 0 |
| 12 Oct | **0** | 0 |

Last alert: updated cohort **2026-10-08 09:22**; non-updated cohort
**2026-09-21 16:09**. The control cohort did not stay level — it stopped
*first*, 24 days ago. Its 0.0240/device/day over the pooled window was 23
alerts in that window's opening week and nothing after, and 40 devices at that
rate implies ~7 alerts a week that do not exist. Multiplying a rate back out
against its population is the check that catches this.

So:

- **the step** (mid-September) is visible in the updated cohort, about
  four-fold, and is consistent with the sensor change. The 40-device cohort is
  silent in 7 of 14 weeks, so it cannot confirm or deny a four-fold change.
- **the stop** (8 October, estate-wide) is a second event the sensor policy
  cannot explain, because it never touched those 40 devices. Its strongest
  evidence is that the 142-device cohort had **never** produced a zero week in
  90 days and now has.

**And the "estate-wide stop" was itself a composite.** Corrected again: the
zero since 8 October is two cohorts stopping 17 days apart, not one event.

| group | devices | last alert |
|---|---|---|
| no 15/16 Sep sensor policy | 40 | **2026-09-21 16:09:57** |
| device since left the fleet | — | **2026-09-30 11:15:30** |
| received the sensor policy | 142 | **2026-10-08 09:22:31** |

A first pass called this "three events, 17 days apart". **That overreads the
dates in the opposite direction from the pooled version, and is also wrong.**
Three different last-alert dates are exactly what a *single* mid-September rate
reduction produces: each group dribbles out and stops when its last alert
happens to land, and the largest, most active group stops last by arithmetic —
142 devices against 40 is 3.5× the exposure. The removed-device group stopped
when those devices left.

So the honest position is that the dates **cannot** distinguish one cause from
several. They are observations consistent with both a single mid-September
reduction with a sparse tail and with separate per-group events, and the only
group that could date its own stop independently — the 40-device one — is
silent in 7 of 14 weeks and cannot. The estate-level date was wrong about what
happened; so was the three-event reading.

The outbound document is restated as that sequence, with each last-alert
timestamp given explicitly. It is also **frozen and marked not-to-be-sent**
pending the one check that can invalidate it: whether Falcon's own console
shows detections after 8 October that this API does not return. If it does,
the finding is about our collection rather than the estate itself, and the
document needs rewriting rather than amending.

Recorded as a method note in `pooling-across-a-regime-change`, now covering
both dimensions — a time boundary hides a step, a group boundary hides a
divergence, and the procedure is the same for both.

## What would settle it

- **Read access to ML/IOA/sensor-visibility exclusions** — one scope on the
  API client, and the question becomes a single query.
- Failing that, someone with Falcon console access can read the audit log
  directly for the week of 2026-09-14: look for exclusions created, and for
  prevention-policy edits.
- Independently: if the zero persists past about 2026-10-22, "quiet estate"
  stops being a viable reading on its own, because no pre-flood week was
  anywhere near zero.
