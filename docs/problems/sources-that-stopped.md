# Two sources stopped sending, and nothing could tell

**Status** Detector built and running (`ingest_freshness_service`, beat entry
`ingest-freshness-watch`). The cause of the two outages is **not** diagnosed —
that needs whoever owns the integrations. The question to ask them is at the
bottom of this page.

Every figure names its table.

---

## What was measured

From `alert_body_investigation_runs` — the right table because it is where an
alert lands when it arrives, so a source missing from it has not arrived:

    windows_eventchannel    9,217 runs   last seen 2026-10-09   793 in 7 days
    appsec-agent            2,685 runs   last seen 2026-09-22     0 in 7 days
    fortigate-firewall-v5   2,533 runs   last seen 2026-09-17     0 in 7 days
    palo_alto_panos           224 runs   last seen 2026-10-09     20 in 7 days

Confirmed from the alert bodies rather than from `graph_source_type`: of 857
runs created in the last seven days, **none** is appsec-agent or Fortigate.
Two sources that were **17.7% and 16.6% of all stored alerts** have delivered
nothing for 17 and 23 days.

## Why nothing noticed for three weeks

`pipeline_health_service` watches queue depth and time since the last verdict.
Both are **downstream of ingest**. An alert that never arrives is never queued,
so a dead feed and a healthy quiet estate produce exactly the same queue — the
same shape as the stall that watchdog was written for, one layer up, and the
same shape as a threat feed that failed 6,259 consecutive times at debug level
and surfaced as `threatfox_count = 0`.

Stated as the rule: **every alarm in this platform measured work in progress,
and none measured work that never arrived.**

## The trap that made this hard to establish

The first measurement said PAN-OS had also stopped — 0 runs in 7 days. It had
not; it had delivered 20.

`graph_source_type` is written when a run is **materialised**, not when it
arrives, so a source delivering right now has recent runs with no source type
at all. Reading that column reports a live source as dead. Old runs are all
materialised, so it is correct for a historical baseline and wrong for the
present.

The detector therefore reads two different sources on purpose:

    the historical cadence   from `graph_source_type`   (complete, past)
    the recent arrivals      from the alert bodies      (authoritative, now)

and the recent half costs one classification pass over a few hundred bodies.

## How a source is judged

Against **its own cadence**, not a fixed threshold. The median gap between its
arrivals — median rather than mean, because one past outage in the history
would drag a mean far enough that the source could never be late again, so the
outage would raise the bar meant to catch it.

Stale requires both halves, as in the queue watchdog: nothing arrived inside
its allowed silence **and** its last arrival is older than that. Allowed
silence is three of its own gaps, floored at 12 hours.

Counted per source, not over one shared window. One seven-day window for
everything would mean nothing can be stale until seven days of total silence,
so for `windows_eventchannel` — a median gap of about a minute — the cadence
logic would never bind and the detector would be seven days slow on the source
it matters most for. Per source it is 12 hours; `syscheck_integrity_changed`,
with a 74-hour cadence, keeps its 9.26 days.

**It holds no list of sources to watch.** Seven hand-maintained lists in this
codebase have swallowed a feature with no error, and a watchdog whose coverage
is a literal would silently not watch the next source onboarded. The population
is whatever has actually delivered.

**A source with no cadence is unjudgeable, not fresh.** Seven sources hold
between 1 and 18 runs and have no rhythm to be late against. They report an
absence with its reason, under a new kind `too_little_history` — `never_observed`
means a check ran and never matched, `unrated` means a source states no value,
and filing this under either would assert something untrue.

## What it says on the live estate

    fresh        windows_eventchannel       9217 runs   203 in 12h
    STALE        appsec-agent               2685 runs     0 in 12h   silent 17.3d
    STALE        fortigate-firewall-v5      2533 runs     0 in 12h   silent 23.6d
    fresh        unstructured syslog         636 runs    11 in 12h
    fresh        palo_alto_panos             224 runs     3 in 12h
    fresh        syscheck_integrity_changed   53 runs    10 in 168h  silent 1.9d
    unjudgeable  7 sources under 40 runs

Exactly the two, no false alarms, and the slow source correctly left alone.

## What this changes about sequencing

Fortigate was the next field map in line. It has had no traffic for 23 days, so
a map for it repairs 2,533 historical alerts and earns nothing forward, for a
source that may not come back. PAN-OS was live at 15–45 a week. That comparison
is settled and Fortigate moves down.

## The question for whoever owns these integrations

Needs asking rather than waiting on, because the two answers lead opposite
ways and the platform cannot tell them apart:

1. Was `appsec-agent` deliberately turned off on or about **2026-09-22**, and
   `fortigate-firewall-v5` on or about **2026-09-17**? Different dates, five
   days apart, so possibly two unrelated changes.
2. If neither was deliberate: both arrive through Wazuh. Is the decoder still
   enabled, is the agent still reporting, and does the manager still receive
   them? A source that stops at the decoder and a source that stops at the
   device look identical from here.
3. If one was deliberate: should its 2,685 or 2,533 historical alerts stay
   visible in cases and graphs, or be marked end-of-life so a reader knows the
   silence is expected rather than a gap?

Until (1) is answered, treat both as unexpected. A customer change we were not
told about and a broken feed we are blind to need the same detector, which now
exists; they need different fixes, which this page cannot choose between.
