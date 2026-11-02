# "Did the watch run?" must be answerable separately from "did it alarm?"

Design note, 2026-10-13. **Not built.**

## The gap

`watch_pipeline` is the stall alarm. It exists because a worker dying on every
task and a worker with nothing to do produce the same queue, so queue depth
alone cannot tell them apart. It fired correctly for a month — except on the
21 occasions in 89 minutes when it did not run at all, because
`asyncio.run()` under a threads pool handed it a connection from a closed
event loop.

A silent alarm and a quiet estate look identical. That is the same shape the
alarm was built to solve, one level up, and the alarm reproduces it.

## The property to get

**Absence of a heartbeat must be detectable; absence of an alarm never is.**
An alarm that does not fire produces nothing to notice. A heartbeat that stops
produces a *stale timestamp*, which something else can read.

So the signal cannot be "the watch wrote an alarm". It has to be "the watch
finished", recorded on every successful run whether or not anything was wrong.

## Shape

A row per watch task — `watch_heartbeat(task, last_ok_at, last_result)` —
written at the end of each successful run. Three properties decide whether it
works:

1. **Written only on success.** A heartbeat written in a `finally` would
   survive the failure it exists to expose. It goes after the work, on the
   path that returns a result, and `succeeded()` is what decides.
2. **Read by a different process.** The worker cannot report its own death.
   `/health` in the API already answers unauthenticated and already carries
   `code.imported_at` — the natural home. `GET /health` then answers "is each
   watch alive" in one call, from outside the thing being watched.
3. **Staleness measured against the task's own schedule.** The sweep runs
   every two minutes and the shadow four times a day; one threshold for both
   is either deaf or noisy. The beat schedule already holds each interval, so
   the threshold is derivable rather than configured — a watch is late when
   `now - last_ok_at` exceeds some small multiple of its own crontab period.

## What it would have done here

The sweep and the stall watch would have shown `last_ok_at` ages of minutes
to hours against two-minute schedules, visible in any `/health` call, for a
month. Instead the only evidence was `graph_materialise_sweep_failed
error=RuntimeError` in a log nobody greps, with the message discarded.

## Deliberately not in scope

**Alarming on a stale heartbeat.** That needs a decision about who is told and
how, and this platform's rule is that a monitor runs in shadow until its own
output has set the threshold — see the emitter freshness work. Report the ages
first; decide the alarm after a week of knowing what normal looks like.

**A watcher for the watcher's watcher.** The regress stops at the API, because
the API is observed by every request anyone makes. A heartbeat read by
`/health` is read whenever anything checks the service is up, which is
continuously.
