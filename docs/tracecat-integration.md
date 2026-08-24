# Sending alerts from TraceCat

## What went wrong

```
HTTPConnectionPool(host='10.45.0.71', port=8000): Max retries exceeded with url:
/api/alert-investigations (Caused by NewConnectionError(... [Errno 111] Connection refused))
```

`Connection refused` is not a timeout and not a dropped response — nothing was
listening on port 8000 when TraceCat tried to connect. The API container was
being rebuilt at the time.

Two separate failures were happening, and only the first was visible to TraceCat:

1. **The API was down** for the seconds a rebuild takes, so the connection was
   refused outright.
2. **Runs already in flight were killed.** Rebuilding the worker sends SIGTERM
   and then SIGKILL 10 seconds later, while the median alert investigation takes
   86 seconds. Three runs were left stuck in `processing` with no worker
   executing them and nothing to notice.

Both are fixed below. The rest of this page is how to call the endpoint so that
neither a restart nor a network blip can lose an alert.

## Call it asynchronously

`POST /api/alert-investigations` defaults to `wait=true`, which holds the HTTP
connection open until the investigation finishes and returns the whole report.
Measured over 3,027 runs: median **86s**, p95 **128s**, ceiling **300s**.

A connection held open for a minute and a half is the fragile part. Any restart,
proxy idle timeout or network blip destroys the response — even though the
investigation itself is queued and completes fine.

**Send it queued instead:**

```http
POST /api/alert-investigations?wait=false
Content-Type: application/json

{
  "alert_body": "<the raw alert>",
  "title": "<rule name>",
  "external_ref": "<TraceCat's own id>",
  "callback_url": "https://tracecat.internal/webhooks/alert-report"
}
```

Returns immediately:

```json
{ "run_id": "92a8df26-…", "status": "queued", "deduplicated": false }
```

Then get the report either way:

- **Callback** — set `callback_url` and the finished report is POSTed to it.
- **Poll** — `GET /api/alert-investigations/{run_id}` until `status` is
  `completed`; add `?format=report` on `/export` for the report array.

Nothing is held open, so there is no long connection left to break.

## Retrying is safe

Ingest deduplication is on by default (`alert_ingest_dedupe`, 60-minute window),
keyed on the alert body. Re-sending an identical alert returns the original run
rather than investigating it again:

```
POST 1 → run_id 92a8df26-…  deduplicated: false
POST 2 → run_id 92a8df26-…  deduplicated: true   (X-Alert-Deduplicated: true)
```

So TraceCat should retry on `ConnectionError` without hesitation — a retry after
a refused connection costs nothing and cannot start a second investigation of the
same alert. Retry with backoff on connection errors and on 502/503/504.

Use `external_ref` for TraceCat's own identifier so a run can be found later
without storing `run_id` anywhere.

## What the platform now guarantees

- **Deploys drain instead of killing.** The worker has a 300s stop grace period
  and the API 330s, so Celery finishes in-flight investigations and uvicorn
  finishes in-flight requests before the container goes away.
- **Abandoned runs are re-queued within minutes.** `tasks.recover_stuck_alert_runs`
  runs every 3 minutes, asks the workers what they are actually executing, and
  re-queues anything claiming to be in flight that nobody is working on. It gives
  up after 3 attempts and fails the run loudly rather than looping.
  Without it, a killed task waits for Redis's visibility timeout — up to an hour.
- **Restarts no longer strand work.** `task_acks_late` plus
  `task_reject_on_worker_lost` means a lost task returns to the queue rather than
  vanishing.

## What is still worth knowing

The API is a single container. A rebuild is still a few seconds of refused
connections — the grace period protects requests already in progress, not new
connections arriving while the container restarts. With retries configured in
TraceCat this is invisible. Removing it entirely means running two API replicas
behind a proxy, which this deployment does not currently do.
