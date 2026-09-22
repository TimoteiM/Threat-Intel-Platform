# CAPEv2 sandbox integration

Detonates files from alerts and investigations on the on-premises CAPEv2
instance, and brings the result back as normalized findings. It is **off until
configured**, and the platform behaves exactly as before while it is off.

Written for whoever deploys and operates this: it assumes you can reach the
CAPE host and edit `.env`, not that you know this codebase.

---

## What it does, and what it does not

| Observable in an alert | What CAPE contributes |
|---|---|
| **File** (a stored artifact) | Submitted and detonated. Full behavioural, network and payload-extraction result. |
| **Hash** (SHA-256) | CAPE is searched for an existing analysis of that hash. If it has one, the report is ingested. If it does not, and this platform holds no copy of the file, the analysis ends as `failed` with "no sample available" — that is the correct answer, not a fault. |
| **Domain / IP / URL** | CAPE has **no endpoint** that answers "which analyses contacted this host". Instead, this platform searches *its own* stored detonations for that indicator, so a domain in an alert is matched against samples detonated here. Nothing is guessed about CAPE's API. |

Two limits worth stating plainly:

- **PDFs are accepted but not opened.** No PDF reader is installed in the guest
  image, so dynamic execution does not happen. Static and network findings are
  still collected, and the UI shows the limitation next to the verdict —
  because an empty report from a file that never opened looks identical to one
  from a file that did nothing.
- **A missing malware score is not zero.** CAPE routinely omits `malscore` from
  `tasks/view`, so the score is read from the completed report, and an unknown
  score renders as "not scored" rather than as clean.

Sandbox output is evidence for an analyst. Nothing in this platform contains,
blocks or remediates on the strength of a CAPE score.

---

## Configuration

All of it is environment, reaching `api`, `worker` and `beat` through
`env_file: .env`. The **worker** is the process that actually calls CAPE.

```bash
CAPE_ENABLED=true
# The internal HTTPS reverse proxy, including /apiv2. NOT CAPE's own port.
CAPE_API_BASE_URL=https://cape.internal.expertware.net/apiv2
CAPE_API_TOKEN=<the CAPE API token>
CAPE_VERIFY_TLS=true
CAPE_CA_BUNDLE=                      # path inside the container, for an internal CA
CAPE_CONNECT_TIMEOUT_SECONDS=10
CAPE_REQUEST_TIMEOUT_SECONDS=60
CAPE_ANALYSIS_TIMEOUT_SECONDS=180    # guest execution timeout, handed to CAPE
CAPE_POLL_INTERVAL_SECONDS=10
CAPE_MAX_POLL_DURATION_SECONDS=900
CAPE_ROUTE=internet                  # internet access is per-analysis here
CAPE_REUSE_EXISTING_ANALYSIS=true
```

Apply with `docker compose up -d api worker beat`. **`docker compose restart`
does not re-read `env_file`** — it reuses the container's existing environment,
so a restart will silently leave CAPE unconfigured.

### The token

It exists in exactly one place: the backend process's environment. It is
**not** written to Postgres, **not** returned by any API, **not** sent to the
browser, and **not** logged. Error messages and tracebacks are passed through a
redactor that strips both the literal token and any `Authorization:` header
construction before they reach a log line or an HTTP response.

Do not commit a real token. `.env` is gitignored.

### TLS

Verification is on by default. For a proxy whose certificate does not chain to
a public root, point `CAPE_CA_BUNDLE` at the internal CA bundle inside the
container. `CAPE_VERIFY_TLS=false` exists for development only and logs a
warning on every client construction — an unverified TLS connection to a
malware sandbox means the responses cannot be attributed to the configured
host.

---

## Network prerequisites

CAPE listens on `127.0.0.1:8000` on its own host and must not be exposed
directly. A restricted HTTPS reverse proxy in front of it, allowlisted to the
Threat Analyzer backend's source address `10.45.0.71`, is what this integration
talks to.

Measured from the backend container on 2026-09-22, before the proxy existed:

```
172.16.45.10:8000  ConnectionRefusedError
172.16.45.10:443   ConnectionRefusedError
172.16.45.10:80    ConnectionRefusedError
```

*Refused*, not timed out — the host is routable from the container (the backend
host has an interface on `172.16.45.0/24`), and only the listener is missing.
No firewall change should be needed on the Threat Analyzer side once the proxy
is up.

---

## Verifying the deployment

Three checks, none of which upload a sample.

**1. Anonymous must be refused.** Run from the backend container so the path
under test is the real one:

```bash
docker compose exec api python - <<'PY'
import httpx, os
base = os.environ["CAPE_API_BASE_URL"].rstrip("/")
r = httpx.get(f"{base}/cuckoo/status/", verify=True, timeout=15, follow_redirects=False)
print("anonymous:", r.status_code, "(expected 401)")
PY
```

**2. Authenticated must succeed, and the pool should be idle.** This prints no
token:

```bash
docker compose exec api python - <<'PY'
from app.config import get_settings
from app.services.cape_client import CapeClient
with CapeClient(settings=get_settings()) as c:
    s = c.status()
print("version  :", s.version)
print("machines :", s.machines_available, "/", s.machines_total, "(expected 6/6 when idle)")
print("tasks    :", s.tasks)
PY
```

**3. Or use the integrations panel.** Settings → API Health shows **CAPEv2
Sandbox** with machine availability in the quota fields. An administrator can
also call `GET /api/cape/status`.

The disabled-by-default smoke test does 1 and 2 together:

```bash
CAPE_SMOKE_TEST=1 docker compose exec api python -m pytest tests/integration/test_cape_smoke.py -v -s
```

It never uploads anything.

---

## How an analysis runs

```
queued → submitting → submitted → pending → running → processing → reported
                                                      ↘ failed / timed_out / cancelled
```

Started by an analyst pressing **Submit to sandbox** on an investigation, or by
the API. The request returns `202` immediately — no HTTP request is ever held
open while CAPE works. A Celery task then submits, polls every
`CAPE_POLL_INTERVAL_SECONDS`, fetches the completed report, normalizes it and
stores the findings. Every state change is recorded on the analysis with the
actor and a note; that record is the audit trail.

**Idempotency.** A detonation occupies one of six VMs for minutes, so submitting
is safe to repeat. Each analysis has a unique key of
`tenant | sha256 | provider | policy version | run seq`; a duplicate request —
a double-clicked button, a retried HTTP call, two workers racing — finds the
existing analysis instead of starting a second one. A deliberate re-run uses
`force_new`, which increments the run sequence.

**Ambiguous submissions are never resent.** If the POST times out, the sample
may already be detonating. The workflow searches CAPE by hash to find out what
actually happened rather than resubmitting, because resending would run the
sample twice and produce a task id nothing is tracking.

**Worker restarts.** State lives in Postgres, so an analysis outlives the worker
driving it. `cape-resume-in-flight` runs every five minutes, resumes anything
unfinished by polling the CAPE task it already recorded, and retires anything
past its polling deadline.

---

## API

| Method | Path | Who |
|---|---|---|
| `GET` | `/api/cape/status` | admin |
| `POST` | `/api/cape/analyses` | admin, analyst (human accounts only) |
| `GET` | `/api/cape/analyses` | any signed-in caller |
| `GET` | `/api/cape/analyses/{id}` | any signed-in caller |
| `GET` | `/api/cape/analyses/{id}/result` | any signed-in caller |
| `POST` | `/api/cape/analyses/{id}/retry` | admin, analyst (human accounts only) |

The ingest API key reaches this API by design and is explicitly refused `403`
on submit and retry — an ingest credential must not be able to execute malware.

No endpoint accepts a URL, host or endpoint field of any kind. Where CAPE lives
is administrator configuration; a request that could name it would make this an
SSRF gadget.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Panel says "not configured" | One of `CAPE_ENABLED` / `CAPE_API_BASE_URL` / `CAPE_API_TOKEN` is missing, or the container was `restart`ed rather than recreated. |
| `401` from CAPE | Wrong or revoked token. The token itself never appears in the error. |
| `403` from CAPE | Token valid, operation disabled server-side — commonly the report or submission endpoint. |
| TLS verification failed | The proxy's certificate does not chain to a trusted root. Set `CAPE_CA_BUNDLE`; do not disable verification. |
| "refusing to follow it" | CAPE or the proxy answered with a redirect. Redirects are refused deliberately. Fix the proxy. |
| Analyses sit in `pending` | The VM pool is busy. Check machine availability in the integrations panel. |
| `timed_out` | The task exceeded `CAPE_MAX_POLL_DURATION_SECONDS`. It may still be running on CAPE; the message says so. |
| Report too large | Raised `CAPE_MAX_REPORT_BYTES`, or the instance only exposes the `lite` report. |

Logs carry a short request id per workflow, so one analysis can be followed:

```bash
docker compose logs worker | grep -i cape
```

---

## Still to be enabled server-side

This integration calls five CAPE routes. `cuckoo/status/` is confirmed working
with a token. The other four have **not** been exercised against the live
instance, because the reverse proxy does not exist yet:

- `GET /apiv2/tasks/search/sha256/{sha256}/`
- `POST /apiv2/tasks/create/file/`
- `GET /apiv2/tasks/view/{task_id}/`
- `GET /apiv2/tasks/get/report/{task_id}/{json|lite}/`

CAPEv2 gates apiv2 routes individually in `conf/api.conf`. Confirm each is
enabled before relying on it. The report format matters most: the client tries
`json` first and falls back to `lite`, and a `lite` result is flagged in the UI
as carrying less detail.

Deliberately **not** implemented: file download, process-memory dumps, and task
deletion on CAPE. None is needed to analyse an alert, and each is a way to pull
malware back out of the sandbox or destroy evidence.
