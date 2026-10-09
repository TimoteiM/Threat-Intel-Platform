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
