# Derived case membership

**Status** Problem statement. No fix proposed yet; the product decision at the
end has to be made first.

**Why this exists** Three separate defects have traced to the same cause, and
the shared assumption behind them has never been written down. A fourth is
likely. Each time, the fix went into whichever feature tripped on it.

---

## What a case is today

A case is **not a row**. It is the result of a computation performed fresh on
every read.

`alert_case_spine` holds the *overlay* — the parts that have to survive a read:
who owns it, whether it is closed, its resolution, its narrative, its number,
its peak score. Its own docstring says so: *"Membership is not stored: which
alerts belong together is recomputed from event time on every read."*

Membership itself is derived by `correlate_alerts` in
`app/services/alert_correlation_service.py`, from four inputs:

1. a **lookback window** (`hours`), counted back from now;
2. the alerts in that window, grouped by `(alert_source, entity_host)`;
3. **session boundaries** within each group, from gaps between event times
   (`alert_session_service.session_starts`);
4. a **case key**, `sha256` of `(source, pinned-client, host, first event time,
   discriminator)`, where the discriminator is the first alert's id.

Two consequences follow directly from that construction, and both are the
root of everything below:

- **The window is part of a case's identity.** A cluster that forms over 720
  hours need not form over 48, because a different window admits different
  alerts, which moves the first event time, which changes the key.
- **The first alert is load-bearing.** Anything that changes which alert is
  first — a late arrival, a different window, a retention boundary — produces
  a different case.

## Every consumer that computes membership independently

| consumer | how it derives membership | window it assumes |
|---|---|---|
| `correlate_alerts` | the real derivation: grouping + session boundaries | caller's `hours`, default 48 |
| `case_by_key` | re-derives all cases, then picks the key | caller's `hours`, default 48 |
| the six single-case endpoints | `case_by_key(..., hours=CASE_LOOKUP_HOURS)` | 720, unified in migration-era commit |
| the Cases list page | `correlate_alerts(hours=...)` from the URL | 168 default, up to 17,520 ("All") |
| `app/cli/case_graph.py` | **its own SQL**: host + `[opened_at, closed_at]` | the spine's own window |
| `app/cli/case_supersession.py` | host + ±10/30 min around `opened_at` | a fixed ±40-minute band |
| the Reports page | `correlate_alerts` per month | one calendar month |
| the auto-close job | `correlate_alerts`, then the quiet-period rule | its own schedule window |
| `alert_entity_profile_service` | spine rows only, no membership | n/a |

**Nine consumers, four different notions of "the alerts in this case."** The
CLI's host-plus-window SQL is the one that most obviously disagrees: it
over-counts, because several cases on one host overlap in time, and it
produced 359,023 memberships for 15,255 alerts — about 23 cases per alert.

## The three defects, and what each one assumed

**1. The 48-versus-720-hour window bug.** The case detail endpoint derived
over 720 hours; the graph, observables, narrative, close and analyse endpoints
used the service default of 48. On any case older than two days the page drew
a full header and then four endpoints answering "No such case" — an empty
graph, no observables, and a manual close that could not find the case the
analyst was looking at. *Assumption that failed: that the window is an
irrelevant implementation detail of a lookup.*

**2. The 881 dead keys.** The key formula changed on 2026-10-07 with no
migration. Of 1,889 spine rows, 881 stopped resolving; 855 still had their
alerts and 811 carried a written AI analysis. Nearly half the case list
rendered nothing. *Assumption that failed: that a key derived from data is
stable enough to store references to.*

**3. The bounded-graph cost, still unresolved.** A case graph must bound what
it reads. The bound needs to know which alerts are in the case — and asking
that question costs 270–1,108 ms per case through `case_by_key`, because the
answer requires re-deriving every case in the window. Five of eleven bounded
cases still exceed the 400 ms budget, and the residue is this query, not the
graph assembly (19–46 ms). *Assumption that failed: that membership is cheap
to ask for.*

A fourth is already visible: **59.1% of cases hold exactly one alert** and
**24 cases (2.4%) hold 74.5% of all memberships**, with 32 of the 45 cases
above 20 alerts carrying ≤2 distinct rules. Both the fragmentation and the
host-wide buckets are properties of the grouping, and neither can be fixed
without deciding what a case is.

## The question underneath all three

**Should a case's membership be stored?**

Today's answer is no, and the docstring gives the reason: recomputing means a
case always reflects current evidence, and nothing can drift out of step. That
reasoning is sound and it is why the design is the way it is.

What it costs, measured:

- membership cannot be referenced — 881 rows proved that;
- membership cannot be asked for cheaply — 270–1,108 ms per case;
- membership is not agreed — nine consumers, four notions;
- a case's identity depends on the window it was viewed through, which is not
  a property any analyst would expect a case to have.

### Arguments for materialising

- A case becomes a thing that exists, so a key can be referenced, a pointer
  can be trusted, and a graph can join to it.
- Membership becomes one indexed read instead of a derivation, which removes
  the residual 400–610 ms and makes cross-case pivots affordable.
- One definition instead of nine, enforceable by a foreign key.
- The window stops being part of identity: a case viewed over "All" and over
  48 hours is the same case.

### Arguments against, which are real

- A stored case can be **wrong**: if an alert arrives late, or correlation
  improves, the stored membership no longer matches what the evidence now
  supports. The current design cannot be stale because it is never stored.
- Late arrivals need an explicit policy — join the existing case, open a new
  one, or reopen a closed one — and that is a product decision about what a
  case *means*, not an implementation detail. The platform already chose "a
  new case waits its own ten minutes" for the quiet period; materialising
  forces the same choice for membership.
- A migration has to assign membership for 1,889 existing rows, 881 of which
  no longer derive at all.
- Re-correlation becomes a job that rewrites rows, with all the idempotence
  hazards that implies — and this session already produced one
  non-idempotent migration that read its own output back as input.

### A middle option worth considering

Store membership as a **snapshot with provenance** rather than as truth:
`(case_key, run_id, assigned_at, derivation_version)`. Reads join to the
snapshot and are cheap and stable; a re-correlation job writes a new
`derivation_version` rather than mutating the old; and a case can show that
its membership was computed under an older definition — the same
honest-absence shape used elsewhere, rather than silently presenting a stale
set as current.

This keeps the property the current design is protecting (a case never
silently misrepresents current evidence) while removing the four costs above.

## What I am not proposing yet

No schema, no migration, no code. The decision that has to come first is
whether a case is a **record** or a **query**, because every one of the three
defects is a consequence of it being a query while the rest of the platform —
pointers, numbers, resolutions, narratives, graphs — treats it as a record.
