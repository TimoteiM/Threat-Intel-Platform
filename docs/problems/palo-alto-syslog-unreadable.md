# Palo Alto syslog: one source, four defects

**Status** Problem statement. Promoted out of the deferred field-map list
because it is not a coverage gap — it is the common factor in four separate
findings, one of which hides a true positive.

Every figure names its table.

---

## What the source is

Comma-positional PAN-OS syslog, arriving outside Wazuh. One line, abbreviated:

```
<12>Sep 14 08:21:27 172.16.23.1 1,2026/09/14 08:21:26,013101014199,THREAT,spyware,2818,...
```

From `alert_body_investigation_runs`: **852 runs**, `alert_source = 'unknown'`,
no `decoder.name`, so `graph_source_type` resolves to `unstructured syslog`.
That is 5.6% of the 15,271 alerts in the store — small by volume, and it is
not the volume that matters.

## The four defects, each measured

**1. No field map, so nothing is extracted.** The graph extractor reads Wazuh's
flattened `data.win.eventdata.*` names; PAN-OS carries none of them. Measured
on `alert_graph_entity`: **0 entities** from any of the 852 runs.

The consequence is not an empty page — it is an empty page on a **true
positive**. Case #1106 is one of only four cases in `alert_case_spine`
resolved `true_positive`, and its graph draws nothing. It now says why, which
is the honest-absence convention doing its job, but saying why is not the same
as showing the incident.

**2. No severity, so it cannot be ranked.** Measured on
`alert_body_investigation_runs.source_severity` after the normalisation
backfill: **852 of 852 unrated**. PAN-OS states a severity in its own CSV
positions, and `read_fields` sees `severity` on 2 runs and
`threatInfo.confidenceLevel` on 9 — enough to show the data is there,
nowhere near enough to read it positionally.

This interacts badly with the bounded graph read. Unrated alerts keep a
proportional share of the bound rather than sorting last, so they are not
excluded — but within that share there is no ordering at all, because every
one of them is unrated.

**3. Truncated titles, feeding truncated case names.** Measured before
migration 057: **771 rows stored a `title` of exactly 255 characters, and all
771 have `source_severity = NULL`** — i.e. every single truncation is this
source. The syslog line is long and lands in `title`.

That matters beyond display: the case label is derived from the first alert's
title, so a truncated title becomes a truncated case name. The column is now
`text`, which stops new truncation; the 771 already-cut values cannot be
recovered from the title column, though `alert_body` still holds the full
line.

**4. It scores near zero, for structural reasons.** Measured by joining
`alert_case_spine` to `alert_body_investigation_runs` on host and window and
grouping on `graph_source_type`: **140 live cases** have this as their
dominant source, with a **median `peak_score` of 0**. 38.6% of them earn the
30-point indicator bonus, against 6.3% for `windows_eventchannel` — because
PAN-OS alerts do carry external addresses, which is the one part of the
phishing-shaped `indicator_risk_score` they can reach.

So this source is simultaneously unreadable, unrankable, unnameable, and
scored by the one signal that has nothing to do with how severe its events
are.

## Why this is its own item rather than a field map

A field map fixes defect 1 and part of 2. The other half of 2 needs the CSV
positions decoded, 3 is already fixed forward but leaves 771 historical rows
cut, and 4 is the `indicator_risk_score` problem, not a parsing problem.

More importantly, the comparison that was used to defer Fortigate does not
apply here. Fortigate is 16.6% of alerts and contributes **5 distinct external
addresses** — high volume, near-zero pivot value. PAN-OS is 5.6% of alerts and
contains **a true positive this platform cannot draw**. Volume is the wrong
measure for both, in opposite directions.

## What a fix would need, in order of value

1. **A positional field map for PAN-OS THREAT lines** — source and destination
   address, port, action, threat name, severity, and the application. That
   alone answers defects 1 and 2, and gives case #1106 a graph.
2. **Severity from the PAN-OS severity position**, normalised like FortiOS's
   `data.level` (see `source_severity_service`), with the same louder-wins rule
   if it states more than one grading.
3. **Nothing for the 771 truncated titles.** They can be re-derived from
   `alert_body`, which still holds the full line, but re-deriving a stored
   title is rewriting a displayed value and should be a decision rather than a
   backfill.

## It is a live feed, so a field map earns forward

Measured on `alert_body_investigation_runs.created_at` for the 859 runs whose
`graph_source_type` is `unstructured syslog` or empty — the right filter
because that is exactly the population with no field map:

    span            2026-08-05 .. 2026-10-09
    last 7 days     85 runs
    last 2 days     40 runs
    by week         78, 127, 87, 89, 119 (newest five)

So roughly 85-125 alerts a week, arriving now. A field map is not archaeology:
it repairs the past *and* stops the next 85 a week from being unreadable. That
removes the one argument for leaving this on a deferred list.
