# CrowdStrike Falcon: alert volume dropped, then two groups of devices went silent 17 days apart

> **DRAFT — NOT TO BE SENT.** One check outstanding that can invalidate this
> entire document: whether Falcon's own console shows detections after
> 8 October 2026 that this platform's API does not return. If it does, the
> finding is about our collection and not about your estate, and everything
> below needs rewriting rather than amending. That check is in progress.
> Nothing further is being added to this document until it comes back.

**For:** the security manager and whoever owns the CrowdStrike configuration.
**Measured:** 2026-10-15, read-only against the Falcon API. Nothing was
changed.

## The sequence

Three events, in order. They are listed separately because aggregating them
produces a single "the estate went quiet on 8 October" that is true at the
total level and wrong about what happened.

| # | when | what | who |
|---|---|---|---|
| 1 | week of **14 Sep** | alert rate fell about four-fold and stayed down | the 142 devices that received a sensor-update policy on 15/16 Sep |
| 2 | **21 Sep 16:09** | last alert, then nothing — 24 days | the 40 devices that did **not** receive that policy |
| 3 | **8 Oct 09:22** | last alert, then nothing — 7 days | the 142-device group |

Last alert per group, stated explicitly because these dates are the finding:

| group | devices | last alert |
|---|---|---|
| did not receive the 15/16 Sep sensor policy | 40 | **2026-09-21 16:09:57** |
| device no longer in the fleet | — | **2026-09-30 11:15:30** |
| received the 15/16 Sep sensor policy | 142 | **2026-10-08 09:22:31** |

**So the estate-level zero since 8 October is the sum of three groups that
stopped separately, 17 days apart at the extremes — not one estate-wide
event.** Any explanation that fixes a single date cannot be the whole
explanation.

Your 182 Falcon sensors are healthy — 153 checked in within the last 24 hours
— so none of this is an agent outage or a connectivity problem.

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

**Event 1 — the step.** For the 142 updated devices: 116, 83 and 24 alerts in
the weeks before the sensor policy, then 9, 9 and 19 after it. Consistent with
the sensor change. The 40-device group cannot corroborate or contradict it:
that group is silent in 7 of its 14 weeks, which is too irregular to detect a
four-fold change either way.

**Event 2 — the 40-device group's silence from 21 September.** Three
consecutive zero weeks. Note honestly that this *equals* that group's longest
earlier quiet run (the first three weeks of July), so for this group alone the
silence is suggestive rather than conclusive. What is not ambiguous is its
timing: it begins 17 days before the other group's.

**Event 3 — the 142-device group's silence from 8 October.** This is the
strongest single observation in the document. That group had produced alerts
every week for the whole 90-day retention period, including 2 in its quietest
week, and has now produced none for seven days.

**What the sensor policy cannot explain:** event 2. It never touched those 40
devices.

## Two candidate causes, and what could not be tested

- **(A) Detections are being suppressed** — an exclusion or policy change,
  plausibly in response to the 14 September noise, written broadly enough to
  catch genuine detections.
- **(B) Detections are not being generated** — a sensor change altered what
  the agents raise.

The group split tests these for **event 1**, because a suppression rule keys on
files, paths or hashes and would quiet matching devices regardless of sensor
version, whereas a sensor change can only affect devices whose sensor changed.
On that test event 1 favours **(B)**.

It does not test events 2 and 3. For those, (A) and (B) are both live, and so
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
  counted either way — and their own last alert, 30 September, is why the
  stop decomposes into three dates rather than two.
- **The 142-device group is not one sensor version.** It now spans 7.40 (100
  devices), 7.39 (29) and 8.10 (13).
- **The 40-device group is small and bursty.** Half its weeks are zero.
- **Alert retention is 90 days**, so nothing before 17 July can be compared.

## What we suggest, in order

1. **Confirm whether the Falcon console shows detections after 8 October that
   this platform does not receive.** This is the first step because it can
   invalidate everything above: if the console has them, the problem is in
   collection, not in your estate.
2. **If the console also shows none**, check the audit log around each of the
   three dates — 15/16 September, 21 September and 8 October — for exclusions
   created and prevention-policy edits. Three dates, not one.
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
