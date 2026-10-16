# Falcon alert volume: an unexplained seven-day gap in OUR OWN estate

> ## ⛔ THIS HAS NO CUSTOMER AUDIENCE. 2026-10-16.
>
> **Every device in this Falcon tenant is Expertware's own.** Measured across
> all 182:
>
> | `machine_domain` | devices |
> |---|---|
> | `int.expertware.net` | 144 |
> | `ext.expertware.net` | 24 |
> | `dev.expertware.net` | 10 |
> | *(empty)* | 4 |
>
> `site_name` is `EXPERTWARE` on 144 and `Default-First-Site-Name` on 34;
> every populated `ou` ends in `ExpertWare`. There is **no customer estate in
> this tenant**, so a document addressed to "the security manager and whoever
> owns the CrowdStrike configuration" has nobody to go to. It is an internal
> report about our own endpoints and always was.
>
> This is the third and largest reframing of this file. The sequence is worth
> keeping, because each step was a measurement that contradicted the framing
> built on the one before:
>
> 1. *A customer's estate has gone quiet* — written before anyone asked whose
>    devices these were.
> 2. *The untriaged queue is our service gap* — `assigned_to_name` resolved to
>    our own `users` table.
> 3. **Both estate and analysts are ours** — the devices resolve to
>    Expertware domains.
>
> Nobody checked whose machines they were for two days of analysis. That is
> README rule 20's clause about establishing what a thing *is* before
> reasoning about how it behaves, applied to the subject of a report rather
> than to a component.
>
> **The findings all survive; only the audience changes.** A seven-day gap in
> our own EDR output is still a seven-day gap, and arguably a more urgent one:
> it is our own detection coverage, and nobody noticed for eight days.

> ## ⚠️ And a dominant term that invalidates every rate below
>
> **One host, `EXP-22MY264`, is 1,442 of the 2,047 alerts — 70.4%.** It is a
> Windows 11 **laptop** on `int.expertware.net`, enrolled 2025-08-20, and
> **1,323 of its alerts are named `TestingActivity`**. It holds **371 of the
> 378 true positives in the whole corpus (98%)**.
>
> Disaggregated, because pooled these are one machine's numbers:
>
> | | all hosts | excluding EXP-22MY264 | only EXP-22MY264 |
> |---|---|---|---|
> | alerts | 2,047 | 605 | 1,442 |
> | closed / open | 1,728 / 319 | 307 / 298 | 1,421 / **21** |
> | `true_positive` (of closed) | 378 (21.9%) | **7 (2.3%)** | 371 (26.1%) |
> | distinct `sha256` | 223 | 204 | 26 |
> | median seconds to resolve | 977 | **619** | 1,047 |
>
> So the estate's real true-positive rate is **2.3% of closed alerts, not
> 21.9%** — an order of magnitude — and the 319-alert untriaged queue is
> almost entirely *not* that host (298 of 319). One laptop running test
> activity is worked diligently; everything else's leads are untouched.
>
> This is the sixth instance of a statistic whose dominant term is an
> artefact, after `Manager: Siembiot`, `Windows-Test-Device` and the rest —
> and the platform already built a production/test host classification on
> 2026-10-12 for exactly this reason. **Falcon's devices are not in it: 0 of
> 2,047 alerts have a classified host.** Extending that classification to
> Falcon device names is the fix, and it is also what would have caught this
> on day one.

> ## Earlier framing, kept for the record
>
> `assigned_to_name` on the closed alerts resolves to **9 of 11 distinct names
> matching rows in this platform's own `users` table**. The people triaging
> this customer's Falcon console are **Expertware analysts** — our own SOC,
> doing the work we are contracted to do. Which means:
>
> * The **319 untriaged alerts** are a finding about **the service we sell
>   them**, not about their estate. The `epp` queue is worked in a median of
>   **584 seconds**; the `automated-lead*` queue has **never been touched in
>   four months**, by us.
> * Sending a customer "you have 319 untouched alerts" when we are the ones
>   contracted to touch them would have been the worst outcome available this
>   week.
>
> ### This is not a performance finding, and it must not be read as one
>
> Named individuals and closure counts appear below, and a list of people
> beside a queue they did not work reads as a performance table whether or not
> it was meant as one. **It is not one, and the measurements say the
> opposite:** 1,447 alerts worked at a median of **ten minutes** is evidence
> that those analysts are doing the job well.
>
> **The finding is that a queue has no owner.** Nobody works a view they were
> never assigned, so the gap is above the people in it — an assignment,
> tooling and coverage decision that was never made. Any use of the figures
> below to appraise an individual is a misreading of what was measured.
>
> **And the names do not appear in anything that goes to the customer, in any
> version.** They are here because resolving `assigned_to_name` is what
> established whose service gap this is; that question is now answered and the
> names have done their work. The customer-facing question is about alert
> volume and nothing else.
>
> A frozen document with the wrong framing is still a document someone can
> open, so this banner is the point of the file until it is rewritten as two
> separate pieces of work:
>
> 1. **An internal service finding** — the lead queue is unworked. Ours to fix
>    or ours to decide is out of scope, and either way it is a conversation
>    with the SOC, not a customer communication.
> 2. **A genuine joint question** — the seven-day alert gap from 8 October,
>    which is still unexplained and whose remaining candidates are all on the
>    producer's side of the wire.
>
> Nothing in this file is customer-ready, and the volume sections cannot be
> made so until the console check lands.

> ## The first thing to do is not a query
>
> **Ask the four analysts.** Loredana Hreceniuc (437 closures), Elisabeta
> Ifrim (386), Alexandru Adochitei (372) and Ioana Dutuc (252) were in that
> console daily until the boundary. One of them knows whether the queue went
> quiet, whether they were told to stop working it, whether their access
> changed, or whether something was reconfigured on or around 8 October.
>
> That is five minutes with a colleague and **no amount of API work
> substitutes for it.** It is the first thing to hand to whoever is running
> this work; it cannot be done from inside the platform.

**Audience: internal only.** Our own SOC lead and whoever owns Expertware's
CrowdStrike configuration. There is no customer in this tenant — see the top
banner. Nothing in this file is addressed outward, and the earlier
"For: the security manager" line was written before anyone established whose
devices these are.
**Measured:** 2026-10-15 and 2026-10-16, read-only against the Falcon API.
Nothing was changed.

> **One check still outstanding on the volume question:** how many *distinct
> devices* produced the 40-device group's final 23 alerts on 21 September? If
> it is one or two machines, that group never had a rate at all and the "step
> confined to the updated group" reading loses its comparator. One aggregation
> over alerts already retrieved.

## The observations

Four dates. They are given as observations because, as the next section
explains, they do not by themselves establish how many separate things
happened.

| what | when | who |
|---|---|---|
| alert rate fell about four-fold and stayed down | week of **14 Sep** | the 142 devices that received a sensor-update policy on 15/16 Sep |
| last alert | **2026-09-21 16:09:57** | the 40 devices that did **not** receive that policy |
| last alert | **2026-09-30 11:15:30** | devices no longer present in the fleet |
| last alert | **2026-10-08 09:22:31** | the 142-device group |

**No Falcon alert has been raised anywhere in this estate since 8 October
2026** — seven days, and the first full week with no alert in the 90 days
retained.

Your 182 Falcon sensors are healthy: 153 checked in within the last 24 hours.
So none of this is an agent outage or a connectivity problem. The sensors are
reporting; they are not raising detections.

## How many events this is — we cannot tell

Two readings fit these dates equally well, and the data cannot separate them.

**One event.** A single reduction in mid-September cut every group's rate. Each
group then produced its remaining alerts sparsely and fell silent whenever its
last one happened to land. Under this reading the *order* of the three dates is
arithmetic, not meaning: the 142-device group has 3.5 times the exposure of the
40-device group, so it is the one most likely to produce the latest final
alert, and the removed-device group stopped when those devices left.

**Several events.** The mid-September reduction affected only the 142 updated
devices, and the other groups stopped separately for their own reasons — which
would mean 21 September and 8 October are two different causes 17 days apart.

**What would distinguish them is a group with enough activity to date its own
stop, and we do not have one.** The 40-device group is silent in 7 of its 14
weeks; three consecutive zero weeks merely equals its longest earlier quiet run
(the first three weeks of July). Its 23 final alerts all land within hours of
each other on 21 September, which looks more like one incident on one or two
machines than a rate tailing off — but 23 events is too few to carry that
conclusion.

So this document does not claim a number of causes. It claims the four dates
above, the four-fold step on the updated group, and seven days of estate-wide
silence.

## The weekly series, by group

| week beginning | 142 updated devices | 40 other devices |
|---|---|---|
| 20 Jul | 50 | 0 |
| 27 Jul | 73 | 0 |
| 3 Aug | 45 | 7 |
| 10 Aug | 116 | 29 |
| 17 Aug | 2 | 8 |
| 24 Aug | 20 | 0 |
| 31 Aug | 83 | 8 |
| 7 Sep | 24 | 9 |
| **14 Sep** | **1,427** | 1 |
| 21 Sep | 9 | **23** ← last |
| 28 Sep | 9 | 0 |
| 5 Oct | 19 | 0 |
| 12 Oct | **0** | 0 |

The 23 alerts in the 40-device group's final week all fall in its first hours,
on 21 September. A weekly figure makes that group look active that week; the
timestamp is what shows it stopping.

> **The 1,427 figure is not a security event.** It is one developer
> workstation (`EXP-22MY264`) running `wsl.exe` repeatedly, producing 936
> near-identical rows plus related activity. It matters only because event 1
> begins in that same week, and because that kind of noise is what prompts a
> configuration change.

## What each event is, and is not, supported by

**The step.** For the 142 updated devices: 116, 83 and 24 alerts in
the weeks before the sensor policy, then 9, 9 and 19 after it. Consistent with
the sensor change. The 40-device group cannot corroborate or contradict it:
that group is silent in 7 of its 14 weeks, which is too irregular to detect a
four-fold change either way.

**The 40-device group's silence from 21 September.** Three consecutive zero
weeks, which equals that group's longest earlier quiet run. For this group
alone the silence is suggestive rather than conclusive, and its earlier date
is as consistent with low exposure as with a separate cause.

**The 142-device group's silence from 8 October.** This is the
strongest single observation in the document. That group had produced alerts
every week for the whole 90-day retention period, including 2 in its quietest
week, and has now produced none for seven days.

**What the sensor policy cannot explain on its own:** the 40-device group
going quiet at all, since it never touched those devices. Either something
else did, or the step was estate-wide and only measurable on the larger group.

## Two candidate causes, and what could not be tested

- **(A) Detections are being suppressed** — an exclusion or policy change,
  plausibly in response to the 14 September noise, written broadly enough to
  catch genuine detections.
- **(B) Detections are not being generated** — a sensor change altered what
  the agents raise.

The group split tests these for **the step**, because a suppression rule keys on
files, paths or hashes and would quiet matching devices regardless of sensor
version, whereas a sensor change can only affect devices whose sensor changed.
On that test the step favours **(B)** — *if* the step was confined to the
updated group, which the 40-device group is too sparse to confirm.

It does not test the silences. For those, (A) and (B) are both live, and so
is a third possibility the group split cannot see: a change in alert
**delivery or retention** rather than in detection. That third possibility is
the one the outstanding console check addresses, and it is why this document is
not yet sendable.

**The exclusion configuration could not be read.** The API credential this
platform holds is refused — `403 access denied, scope not permitted` — for
machine-learning exclusions, IOA exclusions, sensor-visibility exclusions and
every policy endpoint, and the historical audit log is not reachable with it.
(A) is therefore not ruled out for any of the three events. We could not look.

## Limits on these figures

- **Devices that have left the fleet.** 80 of the 556 pre-September alerts and
  4 of the 64 since 21 September come from device records no longer present and
  cannot be assigned to either group. They are excluded as unknown rather than
  counted either way — and their own last alert is 30 September.
- **The 142-device group is not one sensor version.** It now spans 7.40 (100
  devices), 7.39 (29) and 8.10 (13).
- **The 40-device group is small and bursty.** Half its weeks are zero.
- **Alert retention is 90 days**, so nothing before 17 July can be compared.

## What we suggest, in order

1. **Confirm whether the Falcon console shows detections after 8 October that
   this platform does not receive.** This is the first step because it can
   invalidate everything above: if the console has them, the problem is in
   collection, not in your estate.
2. **If the console also shows none**, check the audit log around each of
   the dates — 15/16 September, 21 September, 30 September and 8 October — for
   exclusions created and prevention-policy edits. Checking all of them costs
   little and does not require deciding first how many events there were.
3. **Ask CrowdStrike support about the 15/16 September sensor-update policy**:
   what it changed, and whether a four-fold fall in detections on those devices
   is expected.
4. **Consider granting this platform read access to exclusions** (one API
   scope), so this class of question can be answered rather than reported as
   unanswerable.

## How this was measured

Read-only, through the existing API credential:

- every alert in retention retrieved and counted locally — 2,048 records,
  reconciling exactly — rather than through server-side date filters, which
  drop rows at period boundaries;
- device records read for sensor version and policy application dates;
- each group tabulated separately, and each inflection point treated as its own
  boundary rather than averaged across.

No configuration, policy, exclusion, detection or host state was modified.

---

# ADDENDUM — 2026-10-16. Still DRAFT, still NOT TO BE SENT.

Two measurements over the **full alert population** rather than a recent
window: all 2,047 alerts CrowdStrike holds for this tenant,
2026-07-20 → 2026-10-15, with `meta.pagination.total` checked equal to the
number fetched so this is the population and not a page.

## 1. There are 319 alerts nobody has triaged, and the newest is 8 October

The population splits into two families that are triaged in completely
different ways:

| `product` | alerts | `status` | `resolution` present | first | last |
|---|---|---|---|---|---|
| `epp` | 1,728 | **100% closed** | 100% | 2026-07-23 | 2026-10-15 |
| `automated-lead-context` | 265 | **100% new** | 0% | 2026-07-20 | 2026-10-08 |
| `automated-lead` | 54 | **100% new** | 0% | 2026-07-20 | 2026-10-08 |

**Every `epp` alert has been closed and not one `automated-lead*` alert has
ever been touched** — over the same four months, with both families arriving
throughout. There are no exceptions in either direction: the two
cross-cells are empty.

So **319 alerts are sitting unread**, the oldest from 20 July, the newest from
8 October. Whether that family is noise the customer deliberately ignores, or
a queue that was never assigned to anyone, is a question only they can answer
— and it is probably the most operationally significant thing in this
document. The two readings have opposite remedies: one is a tuning exercise,
the other is a gap in coverage that has been open for 88 days.

For this platform it also means something narrower: no field's coverage
measured across all 2,047 transfers to either family. `resolution`,
`severity_name`, `confidence`, `priority_value` and `tags` are populated on
100% of the closed family and **0%** of the open one.

## 2. The 8 October date is shared, and a single query dissolves the
   per-family reading rather than confirming it

The `automated-lead*` families' last alert is 2026-10-08, which is the date
this document's open question is about. That looked like a second,
family-specific silence. Per-day counts per family say otherwise:

| day | `automated-lead` | `automated-lead-context` | `epp` |
|---|---|---|---|
| 2026-10-05 | 0 | 0 | 7 |
| 2026-10-06 | 1 | 6 | 0 |
| **2026-10-08** | 1 | 2 | 2 |
| 2026-10-09 → 10-14 | 0 | 0 | 0 |
| 2026-10-15 | 0 | 0 | **1** |

**All three families go quiet after 8 October, not one of them.** The estate
produced **one alert in the seven days to 10-15**, against 2,046 in the
preceding 81 days — and that single alert is the evidence the integration
still delivers at all.

Two controls against over-reading it:

* **Every family is intermittent.** Active on 42% (`automated-lead`), 54%
  (`automated-lead-context`) and 45% (`epp`) of the calendar days in its own
  span. A multi-day gap is normal here, so gap *length* is weak evidence and a
  seven-day one is not self-evidently abnormal.
* **Two silences sharing a date is a hypothesis, not a finding.** This
  document has already been corrected once for promoting a date pattern into a
  cause. What the query establishes is narrower and more useful: the silence is
  **estate-wide, not per-family**, so an explanation scoped to one alert
  product is ruled out, and the remaining candidates are a single cause
  upstream of all three — or genuinely low activity.

**The decisive check is unchanged and is not in the API:** whether Falcon's own
console shows detections after 8 October that we do not receive. Everything
above constrains the question; none of it answers it.

---

# ADDENDUM 2 — 2026-10-16. Our own side, checked and eliminated.

The right instinct was to suspect ourselves first: all three alert families
going quiet together on a shared integration points at the consumer, not the
producer, and
[a-failed-ingest-leaves-no-trace](../problems/a-failed-ingest-leaves-no-trace.md)
is an open known defect whose signature is a gap with no record of it.

**It is not us, and the reason is decisive rather than a judgement.**

| check | result |
|---|---|
| Is there a Falcon ingest path? | **No.** No task in `app/tasks`, no beat schedule entry, no table whose name contains `falcon`, `crowdstrike` or `edr`. Falcon is queried **live** on every panel render and lookup. |
| When did this platform first hold a Falcon credential? | **2026-10-14 07:40**, `tenant_integrations` row created; secret set 07:46. `integration_audit` has no earlier Falcon row. |
| Deploys / container recreation in the 6th–10th window? | Commits on 10-09 and 10-12, none on 10-10 or 10-11. Containers in question were recreated 10-15/10-16, after the fact. |

**We were not connected during the gap.** The boundary is 8 October and our
credential did not exist until 14 October — six days later. There is no
collector between Falcon and this measurement, so there is no cursor to stall,
no queue to drop, and no deploy that could have interrupted a feed that did
not exist. The 2,047 alerts are Falcon's own ~90-day retention, read live, and
the 8 October boundary sits inside **their** store. By the same token nothing
in the original cohort analysis is an observation of a live transition: all of
it is retrospective, pulled after 14 October.

The one self-shaped mechanism not eliminated by that is **the scope of our API
credential** — a client scoped to a subset of hosts cannot see alerts from the
rest. It is unlikely to produce a *date* boundary, since scope restricts by
host rather than by time, and Falcon's device inventory returns **182
devices** against roughly 190 hosts the log store sees, so there is no sign of
a gross restriction. It cannot be fully excluded from our side.

## The fleet is alive, which is what makes the console check interpretable

Measured on `/devices/entities/devices` for all 182:

| |  |
|---|---|
| devices with `last_seen` on/after 2026-10-09 | **163 of 182** |
| devices that reported today (2026-10-16) | **140** |
| `reduced_functionality_mode` not `no` | **1 of 182** |

So the sensors are connected, reporting and not degraded — and produced **one
alert in eight days.** This is not a connectivity story.

`/incidents/queries/incidents/v1` and `/behaviors/queries/behaviors/v1` are
both **404** to this credential, as `/detects/v1` already was, so there is no
second Falcon resource available to corroborate from.

## The intermittency control failed to explain the gap, which is a stronger result than cautioning against the reading

Addendum 1 offered each family's activity rate as a reason not to over-read a
seven-day gap. Doing the arithmetic on what that control returned:

* 2,046 alerts in 81 days is **25.3 per day**. One alert in the seven days to
  10-15 is **0.14 per day — a 99.4% drop.**
* Under each family's own observed activity rate, a seven-consecutive-day
  silence is `(1 − p)^7`: **1.5%** for `epp` (p = 0.45), **2.2%** for
  `automated-lead` (p = 0.42), **0.4%** for `automated-lead-context`
  (p = 0.54).
* Those three cannot simply be multiplied, because they share one integration
  and independence is precisely what is in question. But each one alone is a
  1-in-50 event or rarer, and **all three at once is not something
  intermittency explains.**

So the control did not say "this gap is normal". It said "this gap is not
accounted for", which is the stronger finding.

## Status: STILL FROZEN. Not to be sent.

The surviving hypotheses are both on the producer's side of the wire:

1. **Detections are not being generated** — a policy, exclusion or sensor
   configuration change on or around 8 October. The fleet is online, so this
   would be a deliberate or accidental change in what triggers.
2. **Detections exist and the Alerts API is not returning them to this
   credential** — a visibility or scope question, which is the one shape that
   is still partly ours.

**This document must not be sent as a customer finding until the console
distinguishes those two**, because the two have opposite meanings for the
customer: the first is a configuration conversation, the second is us failing
to see their alerts. Everything measured here constrains the question; none of
it answers it.

And if the console *does* show detections after 8 October that we do not
receive, then this stops being an alert-volume document and becomes the first
real instance of
[a-failed-ingest-leaves-no-trace](../problems/a-failed-ingest-leaves-no-trace.md)
— the defect that backlog item predicted, found in production.

---

# ADDENDUM 3 — 2026-10-16. The boundary survives every time field, and two
# framings in this document were wrong.

## 1. The 8 October boundary is an arrival boundary, not a triage artefact

This record type demonstrably carries fields written at closure —
`severity_name` is on 1,728/1,728 closed alerts and 0/319 open ones — so a
*timestamp* written at triage rather than at arrival was a live possibility,
and the per-day count that produced the boundary was built on
`created_timestamp` alone. Rebuilt on every time field the record carries:

| field | present | min | max | dated after 10-08 |
|---|---|---|---|---|
| `created_timestamp` | 2,047 | 2026-07-20 | 2026-10-15 | 1 |
| `context_timestamp` | 1,993 | 2026-07-20 | 2026-10-15 | 1 |
| `crawled_timestamp` | 2,047 | 2026-07-20 | 2026-10-15 | 2 |
| `timestamp` | 2,047 | 2026-07-20 | 2026-10-15 | 2 |
| **`updated_timestamp`** | **2,047** | 2026-07-20 | **2026-10-15** | **2** |
| `signal_*_timestamp` | 54 | 2026-07-20 | 2026-10-08/10 | 0–1 |

**`updated_timestamp` is the control and it closes the question.** It is
written whenever a record is touched, and `updated ≥ created` always. If
arrivals had continued while triage stopped, it would cluster before 10-08
while `created_timestamp` ran on. If the boundary were a triage artefact, the
reverse. Instead **both stop together, and at most 2 of 2,047 records have
been touched at all since 8 October.**

So the gap is real on every available clock. It is not an artefact of which
field was counted.

## 2. The 20 July edge is a retention floor we created, not a start

`alert_retention_floor` measures the oldest alert this subscription returns as
**2026-07-20, 88 days ago** — consistent with a ~90-day alert retention. And
the sensors long predate it: device `first_seen` runs back to **August 2024**,
with roughly **95 of 182 devices enrolled before 20 July 2026**, some by two
years.

So the left edge of every figure in this document is `at_retention_floor`, not
the beginning of activity. Any statement of the form "this began on 20 July"
is a statement about our query window. The right edge is unaffected, and so is
the 8 October boundary, which sits well inside the window.

## 3. CORRECTION — the analysts who are not triaging the lead queue are OURS

Addendum 1 said the 319 untriaged alerts raise a question "only they can
answer". **That is wrong.** `assigned_to_name` on the closed alerts resolves
to **9 of 11 distinct names matching rows in this platform's own `users`
table** — Loredana Hreceniuc (437 alerts), Elisabeta Ifrim (386), Alexandru
Adochitei (372), Ioana Dutuc (252), and five more. Two names (Adi Roman,
Iulian Cocris) do not match any account here.

And the closures are **human, not a rule**: `seconds_to_resolved` has a median
of **584 s (~10 minutes)**, p95 of 7.3 hours and a maximum of 1.5 days.
(`seconds_to_triaged` is 0 on 2,016 of 2,047 and carries no information.)

So the contrast is not "the customer works one queue and ignores another" — it
is that **our own SOC works the `epp` queue within minutes and has never
touched the `automated-lead*` queue in four months.** That is a question for
us before it is a question for them, and it changes who this part of the
document is addressed to. Worth noting separately: Ioana Dutuc has triaged 252
alerts in the customer's Falcon console and has **never logged into this
platform** (`last_login_at` is null).

## 4. CORRECTION — "no corroborating resource" was not established

Addendum 2 reported `/incidents` and `/behaviors` as 404 and concluded there
is no second Falcon resource to corroborate from. The path shapes were
wrong-ish and the conclusion is unsupported either way:

| path | status |
|---|---|
| `/incidents/queries/incidents/v1` | 404 |
| `/incidents/queries/behaviors/v1` (the correct behaviours path) | 404 |
| `/incidents/entities/behaviors/GET/v1` | 404 |
| `/detects/queries/detects/v1` | 404 |
| `/alerts/queries/alerts/v1` | **200, total 2,041** |
| `/alerts/queries/alerts/v2` | **200, total 2,047** |
| `/not/a/real/path/v9` (control) | 404 |

The 404 body for `/incidents/queries/incidents/v1` is **byte-identical in
shape to the nonsense path's** — a generic `"Not Found: Please provide
trace-id"` with no scope message — so the status cannot separate *unscoped*
from *not available on this cloud*. The honest reading is `check_failed`: a
second corroborating resource has **not been shown to be unavailable**, it has
not been reached.

Also noted: **v1 and v2 of the alerts query disagree about the population by
6** (2,041 against 2,047). Every count in this document is v2's.

## What the console check should ask

Not only *"are there detections after 8 October that we do not receive?"* but
**"what changed in this tenant's configuration on or around 8 October?"** —
prevention policy, exclusions, host groups, sensor update policy. A
suppression introduced on 8 October is producer-side, is the worst of the
surviving readings for the customer, and leaves a trace in the console's own
change history. That turns a yes/no into a cause.

---

# ADDENDUM 4 — 2026-10-16. A shared cause becomes available, because one side of it is ours.

## Two processes stopped on the same date, and one of them is us

* **CrowdStrike stopped producing alerts** — 1 in the seven days to 10-15
  against 25.3/day before.
* **Expertware analysts stopped working them** — at most 2 of 2,047 records
  touched since 8 October, on `updated_timestamp`.

The `updated_timestamp` control correctly rules out the *artefact* reading:
both stopped, not one, so the boundary is not an accident of which clock was
counted. But two independent processes halting on the same day wants a
**shared cause**, and until `assigned_to_name` was resolved there was no
candidate that could reach both — the producer and the consumer looked like
different organisations. They are not.

**The fleet constrains what the shared cause can be.** 163 of 182 devices
reported on/after 10-09, 140 today, 1 of 182 degraded. So device management is
intact and detection output is absent: whatever happened left sensors checking
in and stopped what they raise. A **licensing or module change** fits that
shape — a dead subscription does not, because a dead subscription takes the
device check-ins with it.

**That is a candidate, not an assertion.** Falcon console internals have been
guessed wrong in this work before, and the one thing that distinguishes these
readings is not in the API.

## So the console check has three parts, not one

1. Are there detections after 8 October that this platform's API does not
   return?
2. **What changed in this tenant's configuration on or around 8 October** —
   prevention policy, exclusions, host groups, sensor update policy. A
   suppression introduced that day is producer-side and leaves a trace in the
   console's own change history.
3. **What is this tenant licensed for, and did its subscription or module
   state change around that date?** Entitlements, module enablement, seat or
   SKU changes. This is the part that can stop detections while leaving device
   management working, which is exactly the shape the fleet measurement
   leaves open.

Each of the three turns a yes/no into a cause. None of them is answerable from
the API with this credential.

---

# ADDENDUM 5 — a product finding, separate from everything above

**Four analysts, 1,447 closures, in someone else's console — and the people
who do the work are not users of the thing being built for them.**

| analyst | closures in Falcon | logins to this platform |
|---|---|---|
| Loredana Hreceniuc | 437 | last 2026-10-06 |
| Elisabeta Ifrim | 386 | last 2026-10-15 |
| Alexandru Adochitei | 372 | last 2026-10-15 |
| **Ioana Dutuc** | **252** | **never** |

Ioana Dutuc has triaged 252 alerts in the customer's Falcon console and has
never once logged into this platform.

Two consequences, and the second is the useful one.

**It is a risk.** A platform built for a workflow whose practitioners do not
use it accumulates design decisions nobody has validated, and the gap is
invisible from inside: every page renders, every test passes, and the measure
of whether any of it helps is absent.

**It is also the cheapest design input available.** Every judgement made this
week about the escalation feature is currently a guess that these four could
settle in half an hour:

* what should open an investigation record, against what they actually chase;
* whether a host list is worth 565 API calls, or whether prevalence alone
  answers the question they have;
* what an analyst wants to see first on a verdict strip;
* whether the `automated-lead*` family is noise they correctly ignore or a
  queue nobody assigned.

**And their median closure time is the benchmark the cost analysis was
missing** — see §4 of
[indicator-lookup-escalation](../design/indicator-lookup-escalation.md). A
real triage on this estate takes **584 seconds**. That is what a lookup's
latency has to be measured against, and it is a measurement rather than taste.

---

# ADDENDUM 6 — the v1/v2 disagreement is resolved, and it changes the console check

Six records are visible to `/alerts/queries/alerts/v2` and not to
`/alerts/queries/alerts/v1` (2,047 against 2,041). Six is noise against 2,047
and it is **larger than the entire `ignored` population (5)** and comparable
to the **10 hashes the gate fires on**, so it was identified rather than
left as a line.

The id sets are directly comparable — 2,041 shared, 6 in v2 only, 0 in v1
only — and the six have one signature:

| | |
|---|---|
| `show_in_ui: False` across the population | **6 of 2,047** |
| the v1/v2 difference | **6** |

Exactly the hidden records. **v1 returns the UI-visible population; v2
includes alerts the console does not display.** Their products are mixed
(3 `automated-lead-context`, 1 `automated-lead`, 2 `epp`) and their statuses
are 4 `new` / 2 `closed`, so nothing else distinguishes them.

**This has a direct consequence for the console check**, and it is the reason
it was worth one query: a human in the console sees the **2,041**, not our
2,047. Comparing "what the console shows" against "what the API returns"
without that correction manufactures a six-record discrepancy that looks
exactly like the thing the check is testing for. The comparison baseline is
`show_in_ui: True`.

Every figure in this document and in the escalation spec is a **v2** number:
2,047; the 1,728/319 split; `resolution` at 1,345/378/319/5; 223 distinct
hashes; the 4.5% and 60.1% fire rates. They are stated as v2 numbers rather
than silently re-based, because the two populations answer different
questions — v2 is what the API holds, v1 is what an analyst can see.
