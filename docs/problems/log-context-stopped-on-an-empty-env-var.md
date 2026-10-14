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

## The fix, which is one line and not mine to apply

    OPENSEARCH_TENANT_VALUES=wm-c00.siembiot.int

Then `docker compose up -d --force-recreate` — **not** `restart`, because
`env_file` is read at container creation. That recreates the api on a box
carrying live traffic, which is why it is written down here rather than done.

**The same value unblocks the estate lookup**, which refuses for the same
reason (backlog 17). One line fixes both.

## Two defects this exposed, worth their own fixes

**1. A missing tenant pin is silent.** The platform ran for two days with log
enrichment entirely off and nothing said so. `collect_for_alert` reports
`status='unavailable'` honestly, and then nothing is persisted, so the
honest status reaches no surface that anybody watches. An integration that is
*configured but unusable* needs to appear on the integrations page in the
`verified_failing` state, and `opensearch_tenant_values` being empty while
nodes and credentials are present is precisely that state.

**2. The panel collapses the absence distinction.** "No surrounding events
were retrieved" and "log retrieval is not available for this alert" are
different claims and were shown together. Asked-and-got-nothing is not
never-asked; this is the distinction the whole absence convention exists to
hold, failing at the last surface before the reader. With no row at all the
UI should show only the second, and when a row exists with
`status='unavailable'` it should never show the first.
