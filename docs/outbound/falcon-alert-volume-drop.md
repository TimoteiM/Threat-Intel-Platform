# CrowdStrike Falcon: your EDR has raised no alert in seven days, and volume fell in mid-September

**For:** the security manager and whoever owns the CrowdStrike configuration.
**Measured:** 2026-10-15, read-only against the Falcon API. Nothing was
changed.

## The headline

**No Falcon alert has been raised anywhere in this estate since 8 October
2026.** That is seven days, and it is the **first full week with no alert in
the entire 90 days** the platform can see.

Your 182 Falcon sensors are healthy — 153 of them checked in within the last
24 hours — so this is not an agent outage and not a connectivity problem. The
sensors are reporting; they are not raising detections.

Separately, and earlier, **alert volume stepped down in mid-September** and
never recovered. These look like two different events and the sections below
keep them apart, because they have different evidence behind them and probably
different causes.

## What the volume did

Falcon alerts per week for this estate, across the full 90 days retained,
split by whether the device received a sensor-update policy on 15/16 September
(142 devices did, 40 did not):

| week beginning | 142 updated devices | 40 other devices | total |
|---|---|---|---|
| 20 Jul | 50 | 0 | 79 |
| 27 Jul | 73 | 0 | 73 |
| 3 Aug | 45 | 7 | 117 |
| 10 Aug | 116 | 29 | 82 |
| 17 Aug | 2 | 8 | 52 |
| 24 Aug | 20 | 0 | 26 |
| 31 Aug | 83 | 8 | 80 |
| 7 Sep | 24 | 9 | 33 |
| **14 Sep** | **1,427** | 1 | 1,450 |
| 21 Sep | 9 | **23** | 9 |
| 28 Sep | 9 | 0 | 20 |
| 5 Oct | 19 | 0 | 12 |
| 12 Oct | **0** | **0** | **0** |

(The two cohort columns and the total differ because some alerts come from
devices that have since left the fleet — see "limits" below. Weekly totals are
counted from complete records, not from date-filtered queries.)

> **The 1,427 figure is not a security event.** It is one developer
> workstation (`EXP-22MY264`) running `wsl.exe` repeatedly, producing 936
> near-identical rows plus related activity. It matters only because the
> change in behaviour begins in that same week, and because that kind of noise
> is what prompts a configuration change.

The last alert from each group:

| | last alert |
|---|---|
| the 142 updated devices | **2026-10-08 09:22** (7 days ago) |
| the 40 other devices | **2026-09-21 16:09** (24 days ago) |

## Event one: the mid-September step down

For the 142 devices that received the sensor-update policy on 15/16 September,
alert volume fell about **four-fold** and stayed down: 116, 83 and 24 alerts in
the weeks before the change, then 9, 9 and 19 after it. That group had **never**
had a zero week before this month.

The 40 devices that did not receive the policy are too few and too irregular to
say anything confident about — their weekly counts across the whole period are
0, 0, 0, 7, 29, 8, 0, 8, 9, 1, 23, 0, 0, 0. A group that is silent in 7 of 14
weeks cannot be used to confirm or deny a four-fold change.

So: **the step down is visible in the updated group and is consistent with the
sensor change. It is not established for the estate as a whole.**

## Event two: the stop, and it is not explained by event one

Since 8 October both groups are at zero. The 40 non-updated devices have in
fact raised nothing since **21 September**.

The sensor-update policy cannot account for this, because it did not touch
those 40 devices. Whatever stopped alerts on 8 October — and possibly on
21 September for the smaller group — is a second thing.

One honest caveat on dating the second group's stop: three consecutive zero
weeks equals the longest quiet run that group had earlier in the period (the
first three weeks of July). For 40 devices with bursty activity, three zero
weeks alone is suggestive, not conclusive. **What is not ambiguous is the
whole-estate zero since 8 October**, because the 142-device group had never
produced a zero week in 90 days and now has.

## Two candidate causes, and what we could and could not test

- **(A) Detections are being suppressed.** An exclusion or policy change —
  plausibly a response to the 14 September noise — written broadly enough to
  suppress genuine detections.
- **(B) Detections are not being generated.** A sensor change altered what the
  agents raise.

The cohort split tests these for the **step**, because a suppression rule keys
on files, paths or hashes and would quiet matching devices regardless of
sensor version, while a sensor change can only affect devices whose sensor
changed. On that test the step favours **(B)**.

It does **not** test the **stop**, where both groups are silent. For that, (A)
and (B) are both live, and so is a third possibility we cannot see: a change in
alert *delivery* or retention rather than in detection.

**We could not read your exclusion configuration.** The API credential this
platform holds is refused — `403 access denied, scope not permitted` — for
machine-learning exclusions, IOA exclusions, sensor-visibility exclusions and
every policy endpoint, and the historical audit log is not reachable with it.
So (A) is not ruled out anywhere. We could not look.

## Limits on these figures

Stated so they are not read as more precise than they are.

- **Devices that have left the fleet.** 80 of the 556 pre-September alerts and
  4 of the 64 since 21 September come from device records no longer present,
  so they cannot be assigned to either group. They are excluded as unknown
  rather than counted either way.
- **The 142-device group is not one sensor version.** It now spans 7.40 (100
  devices), 7.39 (29) and 8.10 (13).
- **The 40-device group is small and bursty.** Half its weeks are zero.
- **Alert retention is 90 days**, so nothing before 17 July can be compared.

## What we suggest, in order

1. **Establish whether the stop is real, today.** Someone with console access
   can confirm whether Falcon shows detections after 8 October that this API
   does not return. If the console also shows none, the estate genuinely has
   raised nothing for a week and that is the priority.
2. **Check the audit log for the week of 14 September** — exclusions created,
   prevention-policy edits — and for anything around 8 October. This is the
   question we could not ask.
3. **Ask CrowdStrike support about the 15/16 September sensor-update policy**:
   what it changed, and whether a four-fold fall in detections on those devices
   is expected.
4. **Consider granting this platform read access to exclusions** (one API
   scope), so this class of question can be answered directly rather than
   reported as unanswerable.

## How this was measured

Read-only, through the existing API credential:

- every alert in retention retrieved and counted locally — 2,048 records,
  reconciling exactly — rather than through server-side date filters, which
  drop rows at period boundaries;
- device records read for sensor version and policy application dates;
- volume split at each inflection point separately rather than averaged across
  them, and normalised per device and per day where windows differ in length.

No configuration, policy, exclusion, detection or host state was modified.
