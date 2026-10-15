# A failed ingest leaves no trace — measurement, then design

An alert that fails to ingest is never analysed and **nothing records which**.
This is the production condition, not only the migration window that surfaced
it.

**Measurement first. Nothing built.**

## The count is zero, and the window is the finding

**No ingest request returned a non-2xx.** 47 ingest POSTs — 39 to
`/api/alert-investigations/tenants/{id}`, 8 to `/api/alert-investigations` —
all 200.

Every non-2xx in the window, accounted for so none is left unexplained:

| n | status | path |
|---|---|---|
| 1182 | 401 | `GET /api/detections/correlated-cases` |
| 6 | 400 | `POST /api/integrations/c00/opensearch/verify` |
| 4 | 401 | `POST /api/api/Alert/getNewAlerts` |
| 4 | 401 | `GET /api/auth/me` |
| 3 | 400 | `PUT /api/integrations/c00/opensearch` |
| 1 each | 401 | `/api/detections/case/{uuid}`, `/api/integrations/catalogue`, `/api/integrations/matrix` |

The 400s are the Test-connection and Configure attempts on the log store from
2026-10-14/15, both now explained and the second refused by design.

### The retention window, which bounds what can ever be known

| | |
|---|---|
| log driver | `json-file`, **options empty** — no `max-size`, no `max-file` |
| window available | **2026-10-14 14:21:48 → 2026-10-15 06:51:54 ≈ 16.5 hours** |
| why that start | the container was **created** then, by the `--force-recreate` that added `OPENSEARCH_TENANT_VALUES` |
| alert runs in that window | **46** |
| alert runs in total | **17,090**, from 2026-08-05 |

So the measurement covers **46 of 17,090 runs — 0.27%** of the platform's
ingest history. "Zero failures" is true of the last 16.5 hours and says
essentially nothing about the preceding ten weeks.

**And the window is not a retention policy, it is an accident.** With no
`max-size` the log is unbounded, so it does not rotate — it is destroyed when
the container is replaced. `docker compose restart` preserves it;
`up -d --force-recreate` does not. The entire ingest history before yesterday
afternoon was discarded by a routine deploy step, and the same step will
discard this window at the next `.env` change.

**So the hole has two halves, and only one was obvious.** There is no
dead-letter record *and* there is no retained evidence that a failure
occurred. A failure today produces a 500 in a log that one deploy destroys.

### Could the historical losses be identified?

Not from this repository, and the count being zero does not make the question
go away — it is unanswerable rather than answered. The only comparison that
could settle it is **what TraceCat believes it sent against what
`alert_body_investigation_runs` holds**, joined on the `_id`/`id` field that
becomes `external_ref`. That needs, from the estate rather than the codebase:

1. TraceCat's own record of alert deliveries to this endpoint, with its
   per-delivery identifier and outcome, over the same period;
2. whether TraceCat retries a non-2xx, and how many times — which determines
   whether a failure is a delay or a loss;
3. its own retention, which bounds the comparison exactly as ours does.

If TraceCat retains delivery records longer than 16.5 hours, the comparison is
possible **in principle** for its window and is the only way to establish
whether anything has been lost. If it does not retain them, the question is
permanently closed with no answer — which is itself worth writing down rather
than leaving as an assumption that nothing was lost.

## A hole that has never been hit is still worth closing

Zero is the best possible count and it is not a reason to defer. It is
cheaper to close before the first occurrence than after, and the first
occurrence is the one that cannot be reconstructed.

### The constraint that shapes the design

**A dead-letter table lives in the same database as the insert that failed, so
it cannot be the only answer.** The case where the database *is* the fault —
connection exhausted, disk full, a constraint rejecting the row, the
`NOT NULL` window this investigation came from — is exactly the case a
same-database record would miss. Any design needs a layer that survives the
database being the problem.

**A structured log line is the floor, not the ceiling.** It survives a dead
database and nothing else: it is destroyed by the next `--force-recreate`, as
this measurement demonstrates, and it cannot be replayed automatically.

### What makes recovery rather than recording possible

`find_run_by_external_ref` already deduplicates by the caller's own
identifier, so **a replayed alert is safe** — the second delivery of the same
alert does not create a second run. That is the fact the design should be
built around: the goal can be *recovering the alert*, not merely recording
that one was lost.

A proposal that uses this would need, in layers, each surviving the failure of
the one below:

1. **The alert body persisted outside the request path before the insert is
   attempted**, so the payload still exists when the insert fails. On disk or
   in the broker — not in the database the insert is failing against.
2. **A structured log line** carrying `external_ref`, tenant and the failure
   class, as the floor: machine-readable, so a sweep can count them even when
   the body is gone.
3. **A replay path** that reads (1) and re-POSTs, relying on the existing
   dedupe for safety.
4. **A sweep that reports the backlog**, because a queue nobody reads is the
   `feeds_skipped` failure again — recorded and unconsumed for seven months.

## Log durability, now sized against the real number

This was blocked on the echo decision. Echo is off (`APP_ENV=production`,
2026-10-15), so the log is a different object and the earlier ~200MB/day
figure was half artefact.

**Measured after the flip**, grain: bytes of container stdout/stderr per
container, extrapolated from the elapsed time since each was recreated:

| | sample | extrapolated |
|---|---|---|
| api | 140,599 bytes / 2,432 s | **≈4.8 MiB/day** |
| worker | 67,358 bytes / 1,602 s | **≈3.5 MiB/day** |
| **combined** | | **≈8.4 MiB/day** |
| api *before* the flip | 148,499,273 bytes / 16.7 h | **≈213 MB/day** |

A **44× reduction**, and the honest caveats: the sample is ~40 minutes, it is
inflated by this session's own health checks and curls, and it excludes a full
business day of alert traffic (≈240 runs/day against the 46 in the preserved
window). Treat 8.4 MiB/day as the right order of magnitude, not a budget.

### The mechanism: switch the logging driver to journald

`max-size`/`max-file` bounds disk and **does not survive a container
recreate** — rotated files belong to the container and go with it. That is the
actual defect: every `--force-recreate` this week destroyed the access log,
including the one that would have answered the ingest question.

**journald is already the answer and has already proved it.** It retains from
the host's first boot (2026-07-07), survives container replacement, and is
what answered the `svc-tools` question across the host's entire life when
`auth.log`'s 32-day window could not.

    logging:
      driver: journald
      options:
        tag: "{{.Name}}"

on `api`, `worker` and `beat`. `docker compose logs` keeps working — the
driver supports read-back — and `journalctl CONTAINER_NAME=…` becomes
available.

**Cost:**

* journald currently holds 363.3 MB with **all defaults**, meaning
  `SystemMaxUse` resolves to the 4 GB cap (10% of a 124 GB filesystem, capped).
  At 8.4 MiB/day the container logs would need **~1.3 years** to add 4 GB.
* **But `/var/log` is 86% used with 18 GB free**, so set `SystemMaxUse`
  explicitly rather than relying on the cap — 2 GB gives roughly **230 days**
  of container logs at the measured rate, inside a bound that cannot surprise
  the disk.
* Access control improves: journal files are `root:systemd-journal` rather
  than a world-readable path, and `expert` reads them via `adm`.

### DECIDED 2026-10-15: journald, `SystemMaxUse` explicit — on two conditions

**Condition 1: re-measure after a full business day.** The 8.4 MiB/day above
is a ~40-minute sample, inflated by this session's own health checks and
excluding alert traffic — ≈240 runs/day against the 46 in the preserved
window. Not the number to size against, and the cap is not set until a real
day has been measured.

**Condition 2 — answered, and the premise was wrong.** "Adding a 2 GB cap to a
filesystem already 86% full is a decision, not a default" was the right
challenge, and `/var/log` turns out not to be the problem:

| | |
|---|---|
| `/var/log` is **not a separate filesystem** | it is on `/` — 123.5 G total, 99.9 G used, **17.2 G free** |
| `/var/log` itself | **384 MB**, of which 364 MB is the journal |
| **docker build cache** | **72.14 GB — 72.09 GB reclaimable (99.9%)** |
| docker images | 12.41 GB |
| docker volumes | 4.53 GB |
| `/home/expert` | 14 GB (apps 2.6 G, tenant exports 732 M, evidence 142 M, `.claude` 298 M) |

**The filesystem is not full of logs. It is full of reclaimable Docker build
cache** — largely from this session's repeated `docker compose build
frontend` runs, each adding layers. `docker builder prune` reclaims ~72 GB
and takes `/` from ~81% to roughly 23%.

So the 2 GB journald cap is not a decision taken against a full disk; it is
2 GB against 89 GB of headroom once the cache is pruned. **Prune first, then
set the cap** — in that order, so the cap is sized against the real figure
rather than against an artefact of today's work.

**One caveat to verify before committing to it:** a very high-volume burst
written to stdout goes through journald's rate limiter
(`RateLimitIntervalSec`/`RateLimitBurst`), which **drops** lines rather than
queueing them. For an access log that is acceptable; for the structured
ingest-failure line proposed below it is not, so that line needs either a
rate-limit exemption or a second sink.

### Which does not replace the layered design above

journald makes the log *survive*, and the log is still only the floor. The
body-persisted-before-insert and replay path remain the design, because a
structured line records that an alert was lost and does not recover it.
