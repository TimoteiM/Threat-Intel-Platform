# Log context stopped on 2026-10-12, and it is one empty environment variable

**Symptom:** alerts arrive with no SIEM log context. The panel shows two
different claims at once — "no surrounding events were retrieved" *and* "log
retrieval is not available for this alert".

**Cause:** `OPENSEARCH_TENANT_VALUES` is empty in the deployed environment.

## The chain, measured end to end

```
OPENSEARCH_TENANT_VALUES = ''                     (deployed environment)
  → settings.opensearch_tenant_value_list = []
  → TenantIntegration.configured = False          (requires the value list)
  → collect_for_alert() returns status='unavailable', logs=[]
  → nothing is persisted, so there is NO alert_log_context ROW
  → the panel has no row to describe, and says so twice
```

Proved by supplying the one value in-process, changing nothing on disk:

| | status | logs |
|---|---|---|
| as deployed | `unavailable` | **0** |
| with `OPENSEARCH_TENANT_VALUES=wm-c00.siembiot.int` | `partial` | **450** |

450 events over 3 pages in 1,790 ms, both live nodes answering, zero node
failures, `tenant_filter: {field: manager.name, values: [wm-c00.siembiot.int]}`
applied. The environment was restored immediately afterwards.

## When, and the scale

Last `alert_log_context` row with `status='collected'`: **2026-10-12
12:26:32**. Since then, **zero rows across every hour** — 30 hours sampled
hour by hour, `ctx row = 0` throughout, and 1,601 alert runs in the last five
days carrying `tenant_id = 'c00'` with no context between them.

Status history over 7 days: 1,719 `collected` (newest 2026-10-12 12:26:32),
102 `empty`, 7 `skipped`, 2 `failed`.

**It is `NO ROW`, not `failed`.** Nothing got far enough to record a failure,
which is why no error surfaced anywhere: the only trace is the absence of
rows, and absence is what nothing alerts on.

## Not a code regression, and specifically not today's

* `TenantIntegration.configured` has required `opensearch_tenant_value_list`
  since **2026-09-24** and `opensearch_tenants.py` has not changed since. The
  predicate did not move; the value went missing.
* **Zero commits on 2026-10-14 touched any file in this path** —
  `alert_log_context_service.py`, `alert_log_selection.py`,
  `opensearch_client.py`, `opensearch_tenants.py`,
  `alert_log_followup_task.py` are all untouched today.
* The estate lookup's `OpenSearchEstateClient` is a new class in a new file
  with **no consumers**; the log path does not import it. Its refusal on a
  missing pin cannot have broken anything, because nothing calls it.
* The `materialise_run` measurement did not destroy log context, three ways
  over: it ran inside a transaction that was rolled back and verified
  (307/290 entities before and after), `alert_graph_store_service` contains
  **no reference to `alert_log_context` at all** — `log_events` is an input
  to it, never a write — and the rows have been absent since 2026-10-12,
  two days before that measurement.

The likeliest trigger is an `.env` change or a container recreate around
2026-10-12 12:30, which is where that day's commits cluster (`12:34 Merge the
two environment rules into one symmetry`, `13:00 .env gets its own deploy
rule`). **`env_file` is read when a container is created**, so a value lost
from `.env` takes effect at the next recreate and not at the edit — which is
exactly the standing rule, biting in the direction that removes a value
rather than adds one.

## The fix landed on the wrong process first — 2026-10-14 14:21

`OPENSEARCH_TENANT_VALUES` was added to `.env` and the **api** was recreated
at 14:21:47. `liveness.sh` immediately reported what was still wrong, which is
the first time the env-drift limb has fired on a real condition:

    ENV DRIFT: worker=1 beat=1 — docker compose up -d --force-recreate
        worker declared-but-absent: OPENSEARCH_TENANT_VALUES
        beat   declared-but-absent: OPENSEARCH_TENANT_VALUES

Measured per container: **api SET** (started 14:21:47), **worker ABSENT**
(10:57:51), **beat ABSENT** (10:52:52).

**Log context is collected in the worker, not the api.** Both call sites
dispatch with `.delay()` —
`api/alert_investigations.py:748` and `:1565` — so `alert_body_task` runs in
the Celery worker, and `_collect_log_context` with it. An api that has the
variable changes nothing about whether a new alert gets log context.

This is the api/worker split that cost 92 minutes on a pre-fix
`decision_engine` and 3h11m on a stale integrations payload, appearing a third
time in the direction that is hardest to notice: **the fix looks applied.**
The api is the process you can ask over HTTP, it answers correctly, and the
process that actually does the work is the one still missing the value.

**So the remaining step is `docker compose up -d --force-recreate worker beat`**
— and `restart` will not do it, because `env_file` is read when a container is
created. Until then the integrations page correctly shows the log store as
`stopped`, which is now an accurate reading rather than a silent
`not_configured`.

Not yet confirmable from data: zero alert runs have arrived since 14:21:47, so
the conclusion above is from the dispatch code and the per-container
environment, not from a restored row. The check that settles it is one
`alert_log_context` row appearing after the worker is recreated.

## The fix, which is one line and not mine to apply

    OPENSEARCH_TENANT_VALUES=wm-c00.siembiot.int

Then `docker compose up -d --force-recreate` — **not** `restart`, because
`env_file` is read at container creation. That recreates the api on a box
carrying live traffic, which is why it is written down here rather than done.

**The same value unblocks the estate lookup**, which refuses for the same
reason (backlog 17). One line fixes both.

## Two defects this exposed, worth their own fixes

**1. A missing tenant pin was silent — fixed, and the first fix was wrong.**
The platform ran for two days with log enrichment entirely off and nothing
said so.

The obvious fix was `verified_failing` on the integrations page: configured but
unusable. **That would not have caught this**, and the reason is the sharpest
part of the whole incident — *the defect removes the state that would have been
red.* An integration whose tenant pin has vanished does not read as
configured-but-broken. It reads as **`not_configured`**, and on a page listing
unconfigured tools that is invisible.

Two things were needed instead:

* **The log store was not on the page at all.** The catalogue derived only
  from `COLLECTOR_REGISTRY` entries declaring `integration = True`, and the
  log store is not a collector — so the integration carrying 154M documents
  and feeding every alert's context had no row for any state to be red on. It
  now declares itself through `opensearch_tenants.INTEGRATION_SPEC`, beside
  the thing it describes rather than in a list inside the consumer.
* **A sixth state, `stopped`, and `last_succeeded_at` beside it.** The
  distinguishing fact was already stored — `alert_log_context` rows up to
  2026-10-12 and none after — and nothing read it. A tool that is not working
  *and has a last success* is an outage; one that never worked is an absence.
  `stopped` is first in `STATES` because the overall badge is the worst
  direction, so a stopped direction cannot hide behind a healthy one.

Verified against live data, which is the only test that matters here — would
the row an operator reads on 2026-10-14 have said so?

| tool | state | stopped | silent | last success |
|---|---|---|---|---|
| falcon | `verified_ok` | False | 0.6h | 2026-10-14 13:38 |
| **opensearch** | **`stopped`** | **True** | **49.8h** | **2026-10-12 12:26:33** |

That timestamp is the forensic figure exactly, and falcon is the control: the
mechanism discriminates rather than flagging everything. The page would have
shown this red within minutes.

**And it was half-wired at first, caught by a test rather than by review.**
`continuity` was attached in `for_tenant` (the card grid) and not in
`matrix()` (the cross-tenant view), so a stopped integration still read as
`not_configured` in the view whose entire job is *who has nothing working* —
the same invisibility, surviving in the other half of the page. The join test
written the day before found it: the component reads `t.continuity`, one
payload branch did not carry it, and the test's job is exactly that the two
sides agree. Both views attach it now, and a test asserts neither builds a
tool entry without it.

**This is the fourth time this week the fix has been to split one state into
two** — checked from listed, failed from not_attempted, verified from
consulted, and now never-configured from configured-and-stopped. The general
form: an addition that does not take effect fails loudly because somebody is
watching the new thing, and a value that disappears fails silently because
nobody is watching the old one.

**2. The panel collapses the absence distinction.** "No surrounding events
were retrieved" and "log retrieval is not available for this alert" are
different claims and were shown together. Asked-and-got-nothing is not
never-asked; this is the distinction the whole absence convention exists to
hold, failing at the last surface before the reader. With no row at all the
UI should show only the second, and when a row exists with
`status='unavailable'` it should never show the first.
