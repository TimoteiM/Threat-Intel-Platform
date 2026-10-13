# Changing the schema

**A rename is not a deployment.**

`alembic upgrade head` changes the database for **every** container at once.
Rebuilding a container changes the code for **one**. Between those two acts,
any container still running the old code is broken — and nothing notices,
because each half is internally consistent: the database is correct, the
rebuilt container is correct, and the un-rebuilt container fails every query
touching the changed column.

## What this cost on 2026-10-09

Migration 055 renamed `alert_body_investigation_runs.highest_risk_score` to
`indicator_risk_score`. `api` was rebuilt. `worker` and `beat` were not — both
had been up 24 hours.

    last verdict      10:17:09 UTC
    first stuck alert 10:55:09 UTC
    duration          2h 38m
    alerts affected   23 queued, analysis stopped estate-wide
    signal            none; a person noticed on a screen

Every analysis task died with `UndefinedColumnError`. A worker dying on every
task and a worker with nothing to do produce the same queue, so the outage
presented as a quiet afternoon.

## The procedure

1. Write the migration.
2. `docker compose exec -T api alembic upgrade head`
3. **Rebuild every container that runs application code, not only the one you
   are testing:**
   ```
   docker compose up -d --build api worker beat frontend
   ```
   `api`, `worker` and `beat` all import `app.models`. `frontend` only needs
   rebuilding when its own code changed, but including it costs nothing.
4. Confirm the pipeline is producing verdicts, not merely that the page loads:
   ```
   docker compose exec -T api python -c "
   import asyncio
   from app.db.session import AsyncSessionLocal
   from app.services.pipeline_health_service import check
   asyncio.run((lambda: None)()) "
   ```
   or wait for `pipeline-stall-watch`, which runs every two minutes.

## What now catches it

- **`watch_schema`** (hourly, and worth running by hand after a migration)
  compares the columns the ORM expects against the columns the database has,
  per table, and logs at error with the column names when the code is behind.
- **`watch_pipeline`** (every two minutes) alarms when alerts are waiting
  **and** nothing is completing. Both halves are required: an empty queue is
  never a stall however old the last verdict, and a deep queue that is
  completing work is not one either.

Neither existed during the outage, which is why it ran for two and a half
hours.

## A rename has a third half

Renaming a column touches more than the model:

- **Raw SQL.** 12 files import `sqlalchemy.text` and 182 lines contain
  `text(`. A regex over ORM attributes will not find those. Migration 055's
  rename left a straggler in `app/cli/case_graph.py` that took the acceptance
  CLI from 6 passes to 0, and it was found by running the CLI rather than by
  the test suite.
- **Dataclass fields and payload keys.** `alert_graph_assembly_service` held a
  field still named `rule_level` while carrying the new value — the same
  conflation one layer down.
- **Wire contracts.** `highest_risk_score` is in the outbound callback payload
  and was deliberately **not** renamed. Breaking an external contract to fix
  an internal naming problem is not a trade worth making; there is a comment
  at that boundary saying so.

After a rename, grep for the old name across raw SQL, ORM attributes,
dataclass fields, serialisers and payload builders — then run the acceptance
CLI, which exercises the endpoint's own call path.

---

## An .env change is not a restart

**The sibling of the rule at the top of this file,** and the same shape: two
things that both look like "apply the change" and neither of which does.

`env_file: .env` is read when a container is **created**, not when it starts.
So a new or edited variable in `.env` reaches a running container by exactly
one route — recreating it:

| command | effect on an `.env` change |
|---|---|
| `docker compose restart <svc>` | **nothing.** Reuses the existing container, which keeps the environment it was created with. |
| `docker compose up -d <svc>` | **usually nothing.** Compose compares its computed config and frequently sees no change, so it leaves the container alone and reports success. |
| `docker compose up -d --force-recreate <svc>` | works. |

The middle row is the dangerous one. It exits 0, prints the service as
running, and leaves the old environment in place — a command that looks like
it did the thing.

### What this cost on 2026-10-12

`ABUSECH_AUTH_KEY` was added to `.env` to fix ThreatFox, which had failed on
all 6,376 stored lookups. `up -d` was run against `api`, `worker` and `beat`
and reported all three healthy. None of them had the variable:

    api:    NOT present — needs restart
    worker: NOT present — needs restart
    beat:   NOT present — needs restart

Ten minutes were spent re-reading the application's settings plumbing, which
was correct, before checking the container's actual environment. Cheap only
because it was checked at all; the failure mode if it had not been is a key
that is "configured" and a feed that still returns nothing, which is
indistinguishable from the bug that had just been fixed.

### The procedure

1. Edit `.env`.
2. `docker compose up -d --force-recreate <services>` — every service that
   reads the variable. For a feed credential that is usually `api` (serves it
   to the page), `worker` (performs the lookups) and `beat` (schedules them).
3. **Verify in the container, not in the config file:**

       docker compose exec -T worker printenv THE_VARIABLE | wc -c

   Check the length, never the value. A variable absent from the container
   and a variable absent from the file produce the same application
   behaviour and have different fixes.
4. Check the queue is empty first (`redis-cli llen investigations`) if the
   recreate is of `worker`. `task_acks_late` and the 3600s visibility timeout
   mean an in-flight task is redelivered rather than lost, so this is about
   latency rather than safety.

### Why both rules exist

In both cases the system is left in a state where each half is internally
consistent and the join between them is wrong. A migrated database with
un-rebuilt code; an updated `.env` with un-recreated containers. Nothing
raises, every component reports health, and the only evidence is a behaviour
nobody is watching.


---

## A code change is not a running process

**The third of this family, and the one that hides best.** The other two leave
something on disk out of date. This one leaves everything on disk correct and
the *process* stale, so every check you would naturally make says "deployed".

`backend/` is bind-mounted at `/app`. The files inside the container are
always current — `ls`, `grep`, `git log`, a fresh `docker compose exec api
python` all agree. But a running Python process keeps the modules it imported
at startup, and `uvicorn` was started without `--reload`.

### What this cost on 2026-10-12

Seven backend commits, written, tested, committed and pushed, were absent from
the live API for the rest of the afternoon — including the ATT&CK technique
resolver. The symptom was that the case page kept showing bare technique ids
after a day's work on naming them. The API process had been serving code from
12:59; `worker` and `beat` from 12:38, which also meant the nightly IP refresh
would have run the ThreatFox `no_result` bug that was fixed at 12:48.

**The materialisation window was benign because of its input, not because
stale workers are harmless.** `worker` ran the graph sweep every two minutes
for three and a half hours on the pre-chokepoint extractor. 29 runs were
materialised, 15 technique nodes written, and **0** carried the malformed
`{0=T1489}` form — because none of those alert bodies happened to contain a
map-form id. The same hours with map-form ids arriving would have written
fabricated technique nodes into the graph tables, and nothing would have
flagged it. Read this as "that window's traffic was lucky", never as "a stale
worker does no damage".

The diagnosis was slowed by a check that could not have failed:

    docker compose exec api python /tmp/probe.py

That spawns a **new interpreter** which re-imports from the mount, so it
reports what the source says, never what the server is running. It is the
acceptance-CLI problem — measuring a path no user is on — reproduced inside
the diagnosis of a deployment fault.

### How to ask the process that is actually serving

| service | how to reach the live process |
|---|---|
| `api` | an HTTP request. `GET /health` is unauthenticated. |
| `worker` | enqueue through the broker (`celery_app.send_task(...)`) and read the result — the live worker executes it. |
| `beat` | its scheduled task landing in `worker`. |

Never `exec ... python`, for any of them, when the question is "what is
running".

### What makes a backend change live

| change | what makes it live |
|---|---|
| migration | rebuild **every** container running the code |
| `.env` | `up -d --force-recreate` — `restart` reuses the old environment |
| mounted Python source, **`api`** | **nothing** — `--reload` picks it up |
| mounted Python source, **`worker` / `beat`** | **`docker compose restart worker beat`** — Celery has no autoreload |

The last two rows are the live hazard and they are deliberately split. Since
`--reload` went on, writing "restart for mounted source" would teach a reflex
that is wrong for `api` and would get `worker` skipped — which is the worse
half, because the API racing ahead of the worker means two processes writing
the same tables under different rules. Both stale is at least
self-consistent; a skew is not.

Note the inversion against the `.env` row. There the files are stale and
`restart` is useless; here the files are fine and only the process is stale.

### The frontend answers the same question, as a pair

    curl -s localhost:3000/ | grep x-build-fingerprint   # from the HTML
    # and the browser console logs the fingerprint compiled into the bundle

They are **not** two readable copies of one fact. The meta tag arrives with
the HTML, which is not cached the way hashed JS is; the console line is
compiled into the bundle. **If they disagree, the HTML is fresh and the
bundle is cached**, which is the same comparison as API against worker, one
layer up — and it is the layer that would otherwise send the next person back
to elimination.

The first version put the console line in an inline `<script>` in the layout.
That ships with the HTML, so the two would always have agreed: a check
incapable of returning the bad answer, which is the failure this document
exists to stop.

### An open question: is this machine dev or prod?

**`--reload` is a hazard created by the fix, and the decision has not been
made.** This box ingests live alerts. `backend/` is bind-mounted and
WatchFiles watches it, so **any save under `backend/` swaps the running
analyser mid-ingest** — including a file someone opens to read and saves out
of habit, or an editor writing on focus-loss. Uvicorn drains in-flight
requests, but a reload during a batch is still a process boundary nothing in
the pipeline was designed around.

That is ordinary on a development box and wrong on one processing real
traffic. The two answers:

- **dev** — leave `--reload` on, keep the split restart row for `worker` and
  `beat`, and accept that an editor save restarts the API.
- **prod** — take `--reload` off and rely on the restart row for all three,
  which is the state of 2026-10-12 plus the knowledge of how to detect it:
  `/health`'s `code.imported_at` and the `code_version` task make the
  staleness visible in one call, which is what made it invisible before.

Not decided, and deliberately not changed while unresolved. Whoever decides
should also note that `--reload` is currently the only reason the API and the
worker can diverge at all.

### Container start time no longer answers anything

**Fixing this invalidated the instrument that found it.** The staleness above
was diagnosed from `docker inspect ... .State.StartedAt` — api started 12:59,
the resolver landed 14:40, therefore the process could not have it. That
reasoning was sound *because `--reload` was off*.

It is now unsound. WatchFiles replaces the server child without restarting the
container, so container start and import time diverge by an unbounded and
growing margin while looking exactly the same. Measured within half an hour of
enabling it:

    container started : 16:08:40
    process imported  : 16:28:40

The next person with a staleness symptom will reach for `docker inspect`. It
is the obvious move, it worked yesterday, and from today it answers a question
nobody is asking. Use `/health`'s `code.imported_at` for the API and the
`code_version` task for the worker. `StartedAt` now tells you only when the
container was created, which for a reloading service is almost never when its
code was loaded.

### The structural fix, and what it does not cover

`api` now runs with `--reload --reload-dir /app/app`, verified: WatchFiles
reports *"detected changes in 'app/services/technique_naming_service.py'.
Reloading..."* across the bind mount.

**It covers the API only.** Celery dropped worker autoreload, so `worker` and
`beat` still need `docker compose restart worker beat` after a backend change.
That asymmetry is its own hazard — the API can now be hours ahead of the
worker. If a graph reads correctly on the page and wrongly after
materialisation, suspect that before suspecting the code.

### Asking a process what it is running

Built. Both answers come from `app/code_version.py`, computed **at import
time**, which is the only moment that corresponds to "what this process
loaded".

    curl -s localhost:8000/health | jq .code          # the API
    celery_app.send_task("app.tasks.pipeline_watch_task.code_version")   # the worker

Two processes are on the same code when `code_fingerprint` matches. It caught
a real skew on its first use: the API and the worker disagreed because a file
had been edited between one importing and the other restarting.

Three things it avoids, each of which would have reproduced the original bug
inside the fix for it:

- **Not `git rev-parse` at request time.** That reads the bind mount and
  reports the working tree — the same thing every check that failed already
  reported. It would have said "deployed" all afternoon. It could not have
  worked here regardless: there is no `/app/.git` (the mount is `backend/`,
  `.git` is above it) and no git binary in the image.
- **Not the container's start time.** With `--reload`, WatchFiles replaces
  the server child without restarting the container, so the two diverge by
  design and permanently. Measured minutes after enabling it: container
  started 16:08:40, process imported 16:28:40.
- **Not an empty string when git is unavailable.** Blank renders as "unknown"
  and gets read as "fine", so the absence is named and says what to use
  instead.

The fingerprint rather than a SHA is the load-bearing value: it is a hash of
the bytes this process imported, so it covers uncommitted edits — which, on a
bind mount during development, is most of them.
