# `asyncio.run` under a Celery threads pool

Found 2026-10-13, after a drain loop that indexed rather than `.get()`-ed
raised `KeyError: 'materialised'` instead of reporting success.

## The fault

    RuntimeError: Task <Task pending ...> got Future <...> attached to a
    different loop

`celery_app.conf.worker_pool = "threads"` with `worker_concurrency = 8`. Every
async task wraps its work in `asyncio.run()`, which creates and destroys an
event loop per call. The async engine in `app/db/session.py` is module-level
and pooled, so a connection opened under one loop is handed to a task running
under another, and its Future belongs to a loop that has already closed.

It needs two tasks to overlap, which beat guarantees: the sweep runs every two
minutes, the stall watch every two, the schema watch hourly, the shadow run
four times a day.

## What it cost, measured

89 minutes of worker log, 06:49–08:18 on 2026-10-13, before any fix:

| task | failures |
|---|---:|
| `graph_materialise_sweep` | 36 |
| `pipeline_watch` | 21 |
| `schema_watch` | 1 |
| **total** | **58** |

Roughly 42% of graph sweeps. More seriously, **the pipeline stall watchdog was
failing 21 times in 89 minutes** — the alarm whose entire reason for existing
is that a worker dying on every task and a worker with nothing to do produce
the same queue. It had been doing so for about a month.

## Why it stayed invisible for a month

Two independent reasons, and either alone would have been enough:

1. **The failure was shaped like a success.** Tasks returned
   `{"ran": False, "error": ...}` — no `materialised`, no `remaining`. A
   caller reading `.get("materialised", 0)` saw 0 done and
   `.get("remaining")` None, which reads as "finished with nothing to do".
2. **Nothing reads these return values.** They are beat-scheduled and their
   results discarded, so the only evidence was a log line that recorded
   `type(exc).__name__` and threw away the message — which was the one thing
   that named the actual fault.

## The fix taken: NullPool for the Celery engine

`CeleryAsyncSessionLocal`, bound to an engine with `poolclass=NullPool`. It
removes the collision class rather than narrowing it: with no connection
reuse there is nothing to carry a loop affinity.

- **Cost:** one connect per task. On a box doing tens of tasks a minute that
  is acceptable; Postgres connect is a few milliseconds and the sweep already
  spends seconds on work.
- **Reversible:** one line.
- **Scope:** the five watch tasks. Request-path code keeps the pooled engine,
  where it is correct — FastAPI runs one loop for the process.

## The proper fix, not taken

**One persistent event loop per worker process**, created at worker start,
with the pooled async engine bound to it; tasks submit coroutines to that loop
with `asyncio.run_coroutine_threadsafe` instead of calling `asyncio.run`.

That restores pooling and is the right long-term shape. It was not taken on
2026-10-13 because it changes how every async task in the worker is scheduled,
on a box ingesting live alerts, at the end of a long session. It needs its own
change window and its own verification.

## How to tell whether it is fixed

Not by a test — the fault needs two real tasks overlapping under a real
threads pool. Count failures per hour in the live worker log over a stated
window:

    docker compose logs worker --since 90m 2>&1 | grep -c "_failed error="

State the window length beside the number. A test that passes proves the code
runs; only the log proves the collision stopped.
