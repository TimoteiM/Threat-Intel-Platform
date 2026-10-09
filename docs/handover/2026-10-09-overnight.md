# Overnight handover — 2026-10-09

Branch `feature/email-investigation-upload`. Commits only, no pushes. Appended as each item progresses.

## Decisions waiting on you

- **Item 1 — should the cases page stop writing the spine?** I left `GET /detections/correlated-cases` materialising spine rows (now conflict-safe), because it is the de-facto case creator: of 303 live cases (`alert_case_spine`, `created_at - opened_at < 24h`, created in the 14 days to today), **224 (74%) were created outside the hourly job's :05 slot**, i.e. by page loads. Turning it off moves case creation — and so MTTD (`created_at - opened_at`) and the start of the closing job's 10-minute quiet period — onto the hourly cadence. Making the read non-writing needs `case-correlation-hourly` to run more often, and that cadence is a constant you haven't approved. Your call: a cadence (e.g. every 2–5 min, the pass skips when nothing new arrived), or accept the read as the writer.
- **Item 9 ceiling value** — mechanism built with the ceiling unset (no filtering until you approve a number). Proposed value: _pending item 8 distribution_.

## Contradictions with what we concluded today

_None yet._

## Pre-agreed scope for tonight

- Item 8: new table approved; rebuild api, worker, beat; verify watchdog.
- Item 9: build mechanism + allowlist, leave the value unset.

---

## Item 1 — a GET creates cases and can 500

**Done.** Committed (see `git log`, "Let the database decide who creates a case").

**Reproduced first, on the read path.** Scratch database (`CREATE DATABASE` on the same Postgres server, full `Base.metadata` schema, 3 alerts × 6 hosts in `alert_body_investigation_runs`). Entry point: `app.api.detections.get_correlated_cases`, the function behind `GET /api/detections/correlated-cases`, called directly with the request object left out (in-process identity). That skips HTTP and auth middleware and nothing else. 8 concurrent calls: **7 raised `IntegrityError` on `alert_case_spine_pkey`**, each one a 500.

**Fix.**
- `upsert_spine` now does `INSERT … ON CONFLICT (case_key) DO NOTHING RETURNING` and then reads the row back. Whoever loses the race refreshes the winner's row like any existing case. `case_number` comes from `nextval` inside the INSERT. A losing insert burns a number, so there are gaps; the existing `uq_alert_case_spine_case_number` keeps numbers unique.
- The `case_number IS NULL` backfill branch is now a conditional `UPDATE … WHERE case_number IS NULL`.
- Two lookups no longer write at all:
  - `case_for_run` (`GET /alert-investigations/{id}/case`, where `hours` runs 1–720).
  - `case_by_key`'s full-estate fallback, which had persisted every case at the lookup's window. The closing job calls it every minute.

**Why the cases list still writes.** See the decision at the top. It is now idempotent under concurrency, and the reason is in a comment at the call site.

**Test.** `tests/integration/test_case_read_concurrency.py` runs against real Postgres, using a scratch DB that it creates and drops. If no server is reachable it skips and says so.
- 24 concurrent reads across two windows (48h/96h) and 6 hosts must produce no exception, one row per key, unique non-null numbers, and every reader told the same number per key.
- The alert-page lookup at 5 windows must write zero rows.
- **Negative control:** with the service changes reverted, the first test fails with **23 of 24 reads raising**, and the second finds **18 spine rows** minted by the lookups.
- Two unit fakes (`test_case_store.py`, `test_correlation_sources.py`) now model the insert and read-back by query name, instead of the old check-then-insert.

**Gate.**
- Suite: 14 failed / 2152 passed. That is the same 14 as baseline (diffed), plus 2 new passing tests.
- #1440 is 6/6, checked with `app.cli.case_graph 1440` in the worker at the endpoint default (`hours=720`), path `case_by_key -> graph_for_runs`.
- api/worker/beat rebuilt. Watchdog: pipeline not stalled, schema ok. Ingest still alarms on appsec-agent (17d) and fortigate (23d), both already known before tonight.

**Unresolved.**
- `open_continuation` in `alert_case_store.py` has the same check-then-insert shape, but nothing calls it (dead code). I left it alone.
- `case_for_run` finds an alert only within the first 100 members of `case["alerts"]` (the `max_members` cap). An alert past position 100 of a large case gets "no case" on its alert page. I saw this and didn't fix it, because it's outside item 1.
