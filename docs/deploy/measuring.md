# Measuring this system

**State which entry point you exercised. If it is not the one users hit, it is
not a measurement of the system.**

This is the same discipline as naming the table a figure came from. That rule
exists because several figures this session were correct queries against the
wrong source. This one exists because of a worse case: a measurement that was
correct, repeated, and about a code path nobody was on.

## What happened

The case graph's read is bounded to the 300 most severe alerts. That bound was
built, measured, reported with timings (215 ms to 3,958 ms, then 182–610 ms
after a row-based rewrite) and re-run across eleven cases.

It could never engage. The endpoint fed the graph from `case["alerts"]`, which
caps at 100, so the input was never above 300. Every one of those numbers
described the CLI's own query — a parallel implementation that happened to
agree about the output and differed about the path.

The cap also kept the **earliest** 100 alerts, because the list is sorted
ascending by event time. So on a large case the graph drew the opening of an
incident and presented it as the incident: `#1849` holds 1,889 alerts and the
graph saw 100 of them, spanning the first 0.68 hours of a 26.72-hour case.

## The rules

1. **Name the entry point.** A timing or a correctness claim states the call
   path it went through — `case_by_key -> graph_for_runs, as GET
   /api/detections/case/{key}/graph does`, not "the graph assembly".
2. **No parallel implementations in tooling.** `app/cli/case_graph.py` calls
   exactly what the endpoint calls and has an `assert_endpoint_path()` guard
   that fails if either side stops calling the other's functions. A CLI that
   measures its own query is a second system that agrees sometimes.
3. **Check whether a bound can engage** before measuring its effect. A bound
   whose input is capped below its threshold is dead code, and dead code has
   excellent performance.
4. **A cap on an ordered collection declares itself.** `correlate_alerts` now
   returns `alerts_truncated` and `alerts_shown` on every case.
   `alert_count` already differed from `len(alerts)`, so the truncation was
   detectable and nothing detected it.

## Where a cap is dangerous

Swept every slice in the read paths. A cap is dangerous when it is applied to
a collection **still in its original order** — `alerts[]` was sorted by event
time, so the cap silently kept the oldest and discarded the newest, the worst
possible direction for an incident view.

Every other cap found either slices an unordered display list or re-sorts by
relevance first (`pivot_service` by shared-attribute count, `investigations`
by similarity), which keeps the most relevant and is the right direction.
`alerts[]` was the only one left in time order.

And the leak went further than the payload: `alerts_at_close` was recorded
from the same capped list, so 24 of the 56 cases flagged for disposition
review read "judged on 100" when 100 is a floor rather than a count.
