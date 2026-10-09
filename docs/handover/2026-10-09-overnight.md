# Overnight handover — 2026-10-09

Branch `feature/email-investigation-upload`. Commits only, no pushes. Appended as each item progresses.

## Decisions waiting on you

- **Item 1 — should the cases page stop writing the spine?** I left `GET /detections/correlated-cases` materialising spine rows (now conflict-safe), because it is the de-facto case creator: of 303 live cases (`alert_case_spine`, `created_at - opened_at < 24h`, created in the 14 days to today), **224 (74%) were created outside the hourly job's :05 slot**, i.e. by page loads. Turning it off moves case creation — and so MTTD (`created_at - opened_at`) and the start of the closing job's 10-minute quiet period — onto the hourly cadence. Making the read non-writing needs `case-correlation-hourly` to run more often, and that cadence is a constant you haven't approved. Your call: a cadence (e.g. every 2–5 min, the pass skips when nothing new arrived), or accept the read as the writer.
- **Item 2 / SLA — which closure kinds count as a resolution?** `/detections/sla` should presumably exclude `expired`, `merged` and `unreadable` the way `aged_out` was meant to be (`detections.py:1094` already excludes `{aged_out, expired, merged}` elsewhere, but not `unreadable`). Its `alerts_at_close or 1` also files never-counted cases as single-alert. Fixing either moves the SLA figures you report, so I left both.
- **Item 9 ceiling value** — mechanism built with the ceiling unset (no filtering until you approve a number). Proposed value: _pending item 8 distribution_.

## Contradictions with what we concluded today

1. **The member-list cap was still live on both closing writers** (item 2). The review service treated `alerts_at_close = 100` as a historical floor. But `case_closure_task` and the analyst close both recorded `len(case["alerts"])`, and `case_by_key` caps `alerts` at 100. On `alert_case_spine`, 31 closed rows read exactly 100 and **0 rows have ever recorded more than 100**. Every case that outgrew the cap was still being stored as a floor. Fixed tonight. The 31 historical rows stay floors.
2. **"All of them closed automatically" is false for one case** (item 2). #61 (judged on ≥100 of 561) has `closure_kind = analyst` with `closed_by` NULL. It and #892 were closed by a person before `closed_by` existed (`84a56b6`). The review read the missing name as "automatic" and told #61's reader "nobody's assessment is in question". Corrected: 59 automatic, 1 analyst whose name was never recorded.
3. **The disposition-review population is growing, not frozen** (item 2). It was 30, then 56 earlier today, and is **60** now (of 1,005 with a disposition). Seven of the flagged cases closed on 2026-10-09, after both close-anchor fixes: #1964 (3 of 114), #1908, #1978, #1947, #1943, #1919, #1950. The service docstring says those fixes "stop the thirty becoming thirty-one". They can't. A straggler that repeats a detection appends to a closed case by design, so a closed case's membership keeps growing after its verdict. I haven't changed this; it is a design question.
4. **`/detections/sla` excludes a closure kind nobody writes** (found during item 2, not fixed). It skips only `closure_kind == "aged_out"`, and the spine has **zero** such rows, because the expiry path writes `expired`. At the endpoint's default 30 days, 93 `expired`, 17 `merged` and 33 `unreadable` closures (143 cases never answered) are counted as resolutions. `alerts_at_close or 1` then files them all in the single-alert bucket. The agreed "aged-out cases are excluded from MTTR" holds only in name.

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

## Item 2 — the 24 "judged on 100" dispositions

**Done.** Committed ("A count taken from a capped list is a floor…").

**Measured.**
- Run as `python -m app.cli.disposition_review` in the worker. Path: `correlate_alerts(hours=17520, persist=False, max_members=100000)` joined to `alert_case_spine`.
- 60 flagged of 1,005 with a disposition. 24 read exactly 100. Contradiction 3 explains why it's 60 and not 56.
- `alert_case_spine`: 31 closed rows at exactly 100, none above it (contradiction 1). The 7 not in the 24 have a resolution outside `DISPOSITIONS`, or don't hold more than 100 today.

**What changed.**
- New absence kind `lower_bound` (`absence.py`). The floor had been filed as `unparsed`, which claims a shape-check failure. This value parsed fine and is wrong in a known direction.
- `judged_on` in the review and `alerts_at_close` in every lifecycle payload now carry the `lower_bound` absence for exactly 100:
  - the cases list, both branches;
  - the `/case/{key}` spine block.
  - `types.ts` widened to match. The frontend doesn't render either field today. `tsc --noEmit` is clean.
- Attribution reads `closure_kind`, so it no longer infers "automatic" from a missing name (contradiction 2). The CLI shows "(analyst, unrecorded)".
- **Gap closed:** both writers now record `case["alert_count"]` (the uncapped count) rather than the length of the capped list.
  - `case_closure_task.py` (the closing job);
  - `detections.py` (analyst close).
- An exactly-100 value is still reported as a floor even after the fix. No column says which writer produced a row, so the claim that is always true is the one made.

**Tests.**
- `test_disposition_review.py`: 4 new tests for the floor, the payload helper and analyst attribution.
- `tests/integration/test_case_close_count.py`: a 120-alert case on a scratch Postgres is formed by `correlate_alerts` and closed by the real `close_quiet_cases`, then must record 120. **Negative control:** with the closure-task fix reverted it records **100**.
- I factored the scratch-DB setup into `tests/integration/_scratch_db.py`, which the item 1 test also uses now.

**Gate.**
- Suite: 14 failed / 2157 passed, the same 14 (diffed).
- #1440 is 6/6 at `hours=720`.
- Rebuilt api/worker/beat. Watchdog: pipeline and schema green; ingest unchanged (the two known silent sources).

**Unresolved.**
- The SLA findings (contradiction 4, decision at top).
- `case_closure_task` still passes `len(members)` (capped) as `member_count` into the narrative fingerprint, while correlation computes the fingerprint from the full count. For a case over 100 alerts the two fingerprints can never agree, which may re-queue its narrative. I haven't measured this.
