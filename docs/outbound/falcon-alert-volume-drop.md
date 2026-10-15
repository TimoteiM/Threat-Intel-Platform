# CrowdStrike Falcon: alert volume fell sharply on 15 September, and has not recovered

**For:** the security manager and whoever owns the CrowdStrike configuration.
**Measured:** 2026-10-15, read-only against the Falcon API. Nothing was
changed.

## What we found

Your EDR has produced almost no alerts for a month, and nothing flagged it.

Falcon alert volume for this estate, by week, over the whole 90 days the
platform retains:

| week beginning | alerts |
|---|---|
| 20 Jul | 79 |
| 27 Jul | 73 |
| 3 Aug | 117 |
| 10 Aug | 82 |
| 17 Aug | 52 |
| 24 Aug | 26 |
| 31 Aug | 80 |
| 7 Sep | 33 |
| **14 Sep** | **1,450** — see note |
| 21 Sep | 9 |
| 28 Sep | 20 |
| 5 Oct | 12 |
| 12 Oct | **0** |
| since | **0** |

Before 14 September: a mean of **68 alerts a week**, never fewer than 26.
After it: a mean of **10**, never more than 20. The two ranges do not overlap —
the quietest week before is higher than the busiest week since. This is a step
change, not a quiet spell.

**No Falcon alert has been raised anywhere in this estate since 8 October** —
seven days at the time of writing.

The sensors themselves are healthy: 153 of your 182 Falcon-managed devices
checked in within the last 24 hours. So this is not an agent outage, and it is
not a connectivity problem.

> **Note on the 14 September week.** The 1,450 figure is not a security event.
> It is one developer workstation (`EXP-22MY264`) running `wsl.exe` repeatedly,
> which generated 936 near-identical rows, plus related activity. We mention
> it because the drop begins in that same week, and because it is the kind of
> noise that prompts someone to make a configuration change.

## Why this matters

For roughly four weeks, your endpoint detection platform has been reporting
almost nothing. Either there has been almost nothing to report, or it has
stopped telling you. Nothing in the console distinguishes those two, which is
why it went unnoticed: an EDR that reports nothing looks exactly like an estate
with no problems.

For context on what is at stake, 19 hosts in this estate have **no** Falcon
sensor at all, including a domain controller — that is a separate finding in
`falcon-edr-coverage-gap.md`.

## Two possible causes, and which one the evidence supports

These get conflated and they call for different fixes:

- **(A) Detections are being suppressed.** An exclusion or a policy change —
  plausibly added in response to the 14 September noise — written broadly
  enough to suppress genuine detections along with the `wsl.exe` noise.
- **(B) Detections are not being generated.** A sensor change altered what the
  agents raise in the first place.

A **sensor-update policy was applied to 142 of your 182 devices on 15 and 16
September**, inside the noisy week and immediately before the drop. 40 devices
did not receive it. That split lets the two causes be told apart, because they
predict different things:

- A suppression rule keys on files, paths or hashes, so it would quiet **all**
  devices that match it, regardless of sensor version.
- A sensor change can only affect the devices whose sensor changed.

Alert rate per device per day, with the different window lengths accounted for:

| | before 14 Sep | since 21 Sep | change |
|---|---|---|---|
| the 142 devices that took the update | 0.0495 | 0.0109 | **4.6× drop** |
| the 40 devices that did not | 0.0258 | 0.0240 | **1.1× — essentially unchanged** |

**The drop is confined to the devices that received the sensor-update policy.**
The 40 devices that did not take it are raising alerts at very nearly the rate
they always did.

That points to **(B)** — something about the sensor change, not a suppression
rule applied across the estate. A broad exclusion would have quieted both
groups.

## What we could not check, and why that matters

We could not read your exclusion configuration. The API credential this
platform holds is refused (`403 access denied, scope not permitted`) for
machine-learning exclusions, IOA exclusions, sensor-visibility exclusions, and
every policy endpoint. The historical audit log is not reachable with it
either.

So **(A) is not ruled out** — we could not look. It is specifically possible
that a change was made to the same 142 devices at the same time as the sensor
update, which would look identical in the data we can see. What we can say is
that a suppression rule applied *estate-wide* is inconsistent with the 40
unaffected devices.

Two further limits, stated so the figures are not read as more precise than
they are:

- 60 alerts since 21 September could be matched to a current device; 4 could
  not, because the device is no longer in the fleet. Those 4 are excluded as
  unknown rather than counted either way. For the earlier period 80 of 556
  were in that position — a larger share, consistent with machines having been
  replaced since.
- The 142-device group is not a single sensor version. It now spans 7.40
  (100 devices), 7.39 (29) and 8.10 (13).

## What we suggest

1. **Check the Falcon audit log for the week of 14 September** — exclusions
   created, and prevention-policy edits. This is the one question we could not
   ask, and it takes a console user a few minutes.
2. **Check what the 15/16 September sensor-update policy actually changed**,
   and whether the resulting versions are expected. If the intent was a routine
   upgrade, the 4.6× fall in detections on those devices is worth raising with
   CrowdStrike support.
3. **Confirm whether the quiet is real.** If no alert appears across the whole
   estate by around 22 October, "nothing happened" stops being a credible
   explanation, because no week before 14 September came close to zero.
4. **Consider granting this platform read access to exclusions** (one API
   scope). It would let us answer this class of question directly rather than
   reporting that we cannot.

## How this was measured

Read-only, through the existing API credential:

- every alert in retention retrieved and counted locally (2,048 records,
  reconciled exactly) rather than through server-side date filters, because
  those drop rows at period boundaries;
- device records read for sensor version and policy application dates;
- alert volume split at 14 September and normalised per device and per day,
  since the two periods are 59 and 24 days long.

No configuration, policy, exclusion, detection or host state was modified.
