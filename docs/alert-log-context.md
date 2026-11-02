# The logs around an alert

An alert says what a rule matched. It does not say what else the machine or the
account was doing at the time, which is the first question an analyst asks. This
reads that from the same OpenSearch cluster the alerts come from: **ten minutes
either side of the alert's own event time**, filtered to the device and the
account the alert is about.

## What runs, and when

| | |
|---|---|
| Alert ingested | `alert_body_task` calls `collect_for_alert` after the analysis, before the run is marked complete |
| Alert is historical | the whole window is read at once → `collected` / `empty` |
| Alert is live | the elapsed part is read now → `partial`, and a follow-up is scheduled |
| Follow-up | `complete_alert_log_context`, dispatched with a countdown to the window's end + `ALERT_LOG_FOLLOWUP_DELAY_SECONDS` |
| Safety net | `alert-log-context-sweep`, every minute, reads anything still owed |
| Correlated case | `attach_to_case` unions the members' stored logs; no new cluster query |

The retrieved logs and their sources are attached to the alert analysis, so any
statement in a report can be traced back to the events behind it. Each record
carries `matched_on` — `device`, `user`, or both — so "why is this log here" is
answered by the record rather than inferred.

## The client boundary

**What was verified**, against the cluster on 2026-09-24, not inferred from the
hostnames:

* `cluster_name` is `C00-Indexer`.
* **Exactly one Wazuh manager has ever written to it.** `wm-c00.siembiot.int`
  accounts for all 2,593,308,014 documents across all 120 alert indices, over
  209 distinct agents. There is no second manager, on any day.
* **There is no SIEM-level tenant field to filter on.** The mapping's
  tenant-shaped names are all vendor payload (`data.office365.*TenantId`,
  `data.ms-graph.tenantId`, `data.win.eventdata.client*`) — an Azure tenant in
  an event body, not a partition of the index.
* The OpenSearch security plugin has only `global_tenant` and `admin_tenant`,
  the Dashboards defaults — no per-client tenancy.
* No other client's indices exist. The non-Wazuh indices are the platform's own
  tooling (Shuffle, TheHive, Praeco).

So the boundary **is that the cluster is dedicated to C00**, not that anything
filters. That is a deployment property, and deployment properties change
without the code noticing.

**What now enforces it.** Every query carries a tenant pin as a `filter` clause:

```
OPENSEARCH_TENANT_FIELD=manager.name
OPENSEARCH_TENANT_VALUES=wm-c00.siembiot.int
```

A `filter`, not a `should` — a clause the entity match could satisfy instead is
not a pin. Proven load-bearing on live data: the same alert returns 297 logs
with the C00 pin and **0** with a foreign one. If the values are left empty the
query runs unpinned and `sources.tenant_filter` is `null`, so "nothing pinned
this" is visible rather than assumed.

This is belt-and-braces over a cluster that is single-tenant today. The
`tenant_id` contract and the client selector are a separate, larger change.

## Real-time alerts

The window of a live alert ends in the future. Waiting ten minutes before
analysing would be the wrong trade for every alert, including the ones that
matter, so the alert is analysed immediately and the window is read in two
parts.

What makes the second part safe is a stored high-water mark. `covered_until`
says exactly how far the window has been read; the follow-up queries from there,
never earlier, and merges on each document's own `index:id`. Running it twice
changes nothing — verified live:

```
FIRST PASS   status=partial  logs=178  complete=False  follow-up scheduled
FOLLOW-UP    attempt 1 -> 178 logs
             attempt 2 -> 178 logs      (178 unique)
```

Both a countdown task *and* a sweep exist on purpose. A Celery countdown lives
in the broker, so a Redis restart or a worker killed mid-flight drops it with no
trace; "the window usually gets read" is not a property worth having. Because
the read is idempotent, running both costs nothing.

A cluster that stays unreachable is retried with a growing gap and gives up
after `ALERT_LOG_FOLLOWUP_MAX_ATTEMPTS`, recording why on the row instead of
retrying for ever — see **Recovery** below.

### Documents indexed after they were read

A document whose event time falls *inside* the already-covered slice can be
indexed after that slice was read, and a follow-up starting exactly at
`covered_until` would step over it permanently. Measured on this cluster over
two hours, the gap between a document's event time and its indexing is:

| p50 | p90 | p99 | p99.9 | max |
|---|---|---|---|---|
| 0.53s | 0.94s | 4.20s | 11.39s | 15.83s |

So each follow-up starts `ALERT_LOG_OVERLAP_SECONDS` (default 300) *before* the
high-water mark, clamped to the window start. Five minutes is the observed
maximum nineteen times over, which leaves room for a Filebeat backlog. The
re-read costs a handful of duplicate hits, and they merge away on `index:id`.
Missing a log does not announce itself; re-reading one is free.

### Consistent pagination

`search_after` over a live index is not a consistent read: this cluster takes
about 274 documents a second, and a refresh between page 2 and page 3 shifts
everything after the cursor. Every paged read therefore opens a **Point in
Time**, pages against that frozen view, and releases it.

Two details found by testing against the cluster: `_shard_doc` is not mapped
here, so `_id` is the PIT tiebreaker; and the cluster rotates `pit_id` on every
response, so each page must use the id the previous one returned. A cluster that
declines to open a PIT is still queried — consistency is an improvement, not a
precondition — and `sources.consistent_pagination` says which happened.

## Is the analysis you are reading based on these logs?

A live alert is analysed on the half of its window that had already happened.
The rest arrives minutes later. **The analysis is not re-run for it by
default**, and the run says so rather than presenting a partial reading as a
complete one:

| `analysis_basis` | meaning |
|---|---|
| `complete` | the analysis saw every log this window holds |
| `partial` | logs arrived after the analysis ran, or the window is still open |
| `unknown` | the run predates this being tracked |

`analysis_saw_logs` and `new_logs_since_analysis` carry the numbers, and
`analysis_note` carries the sentence to show an analyst — *"7 log events arrived
after this analysis was written and were not considered in its verdict. Re-run
the analysis to include them."*

**Why not re-run automatically.** Two reasons, and the second settles it: a
model call per completed window is a real cost on a platform ingesting thousands
of alerts a day, most of them noise; and re-analysis rewrites the run payload
wholesale, which is precisely how a CAPE sandbox report written into an
investigation's evidence went missing — the second writer replaced what the
first had added. Doing that automatically to every live alert would repeat a
known failure at volume.

`ALERT_LOG_REANALYSE_ON_COMPLETE=true` turns it on for deployments that want it.

## Recovery

Once the internal CA is installed, every alert that failed while it was missing
can be retried, **including the ones that exhausted their five attempts** —
those five say nothing about whether the cluster answers now.

```
POST  app.tasks.alert_log_followup_task.retry_log_context_after_recovery
```

It checks the connection **first, with the real configuration**, and refuses to
reopen anything while the cluster is still unreachable: reopening hundreds of
rows against a dead cluster spends every one of their retries re-discovering
that. Then, per row:

* recoverable failure (TLS, CA, no node answered, timeout) → `attempts` reset to
  0, status back to `partial`, queued immediately;
* window older than `OPENSEARCH_RETENTION_DAYS` (120) → marked `expired`, not
  retried, because the indices that held those logs have rolled away and
  `expired` is distinguishable from "never tried";
* a run that had **no verified tenant** when its window was read → retried once
  it has one. Correct at the time and recoverable later: 15 contexts failed this
  way while their runs sat in the gap between the tenancy migration and the
  ingest deploy, and a backfill gave every one of them a tenant minutes
  afterwards;
* a failure retrying cannot fix (no queryable entity, a refused query) → left
  alone.

To check the deployed TLS configuration itself — as opposed to a probe run with
verification disabled, which proves nothing about it:

```
GET /api/admin/opensearch-health
```

It reports `verify_tls`, `ca_bundle`, `ca_bundle_present`, and either connects
or gives the exact reason it could not.

## Who the alert is about

Two guards, both because a wrong entity here does not merely misfile a row — it
returns someone else's logs as this alert's evidence.

**A manager-forwarded alert names the manager.** Wazuh sets `agent.id` `000` and
`agent.name` to the manager on forwarded logs. Filtering on that name returns
every forwarded log in the estate. Refused; the alert's `agent_ip` is used
instead when it has one.

**`entity_user` is sometimes the domain half.** `CORP\jdoe` is stored as `CORP`
— measured at 318 of 3,376 stored bodies carrying that form. `principal_of()`
re-derives the account from the body *for query purposes only*, and only when
the body actually shows that value as the domain half, so an account genuinely
called CORP is still queried as itself. The stored column is left alone on
purpose: correlation groups cases on it, and changing it would re-key live
cases. See the `campaign-layer-entity-user` note.

Non-principals (`system`, `anonymous`, `NT AUTHORITY\SYSTEM`, machine accounts
ending `$`) are refused. Querying `system` returns every machine's activity and
presents it as one account's.

One principal is queried in every spelling it wears — `jdoe`, `CORP\jdoe`,
`jdoe@corp.tld` — because they land in different fields of different documents.

If neither a device nor an account is usable, nothing is queried and the status
is `skipped`. An unfiltered window would return ten minutes of the whole estate.

## What was measured, and what is assumed

Measured against the live cluster (`C00-Indexer`, OpenSearch 2.19.4, three
nodes) on 2026-09-24:

* **Volume.** `wazuh-alerts-4.x-*` holds 2,592,501,441 documents across 120
  indices; one full day (`2026.09.23`) is 23,685,586.
* **Retention.** Daily indices from `2026.05.28` to `2026.09.24` — **120 days**.
  An alert older than that has no logs to find, and the query returns `empty`
  rather than failing. This is observed, not configured here; if the ISM policy
  changes, this number changes with it.
* **Timestamps.** Both `timestamp` and `@timestamp` are mapped `date` and
  present on 100% of documents. They differ by about a second — `@timestamp` is
  Filebeat's, `timestamp` is the alert's own. `timestamp` is used, because the
  event clock is what every other time question in this platform reads.
* **Device fields.** `agent.name` and `agent.id` are on 100% of documents,
  `agent.ip` on 21.2%. All are `keyword`, so the filters are exact terms.
* **User fields.** Sparse and spread across vendors, which is why the query ORs
  over several: `data.win.eventdata.subjectUserName` 11.8%, `data.dstuser` 6.7%,
  `data.win.eventdata.user` 3.7%, `data.win.eventdata.targetUserName` 3.6%,
  `data.ms-graph.userPrincipalName` 1.1%, `data.office365.UserId` 0.2%. The
  mapping exposes roughly sixty user-shaped fields; the ones queried were chosen
  by counting a full day, not by reading the mapping.

**Assumptions**, each of which degrades rather than breaks if wrong:

* Indices are named `<prefix>-YYYY.MM.DD` per UTC day. The window names the one
  or two it needs; if the rollover scheme changes, `describe_indices` falls back
  to the wildcard — a slower query, not an empty one.
* All entity fields are `keyword`. If one were re-mapped to `text`, its term
  filter would stop matching rather than start matching loosely.
* `full_log` is worth keeping and is truncated to 600 characters. The mapping
  has 1,644 leaf fields; storing whole documents would put megabytes of Windows
  event XML into every case.

## Bounds

A twenty-minute window on a busy host is six figures of logs. Reads are capped
at `ALERT_LOG_MAX_HITS` (500 per alert, 2,000 per case), paged with
`search_after` rather than `from`/`size`, and `track_total_hits` is off. Hitting
the cap is reported as `truncated: true` rather than silently returning a slice.

The logs are stored in their own table and **not** in `result_json`: that
payload is scanned whole by the detection-quality, ATT&CK-coverage and cost
rollups, and 500 log lines per run would put half a megabyte into a read those
rollups pay for on every row. The run carries a summary and a pointer; the logs
are served paged from `GET /api/alert-investigations/{run_id}/logs`.

## Failure is never the alert's problem

Every failure — no cluster, no credentials, no CA, a node down, a refused query
— comes back as a status and a reason, and the alert is analysed without its
logs. An outage in a search cluster must not stop security alerts being
processed.

Nodes are tried in a rotating order so concurrent alerts do not all land on node
1, and a node that fails is skipped for 60 seconds. A 401 is *not* retried
against the other nodes: three nodes times a wrong password is how an account
gets locked out.

## Configuration

```
OPENSEARCH_NODE1/2/3        the three cluster nodes
OPENSEARCH_USERNAME         read account
OPENSEARCH_PASSWORD         SecretStr — never logged, never returned
OPENSEARCH_CA_BUNDLE        /run/secrets/tip/opensearch-internal-ca.crt
OPENSEARCH_VERIFY_TLS       true
OPENSEARCH_INDEX_PATTERN    wazuh-alerts-4.x-*
OPENSEARCH_TIMESTAMP_FIELD  timestamp
ALERT_LOG_WINDOW_MINUTES    10
ALERT_LOG_MAX_HITS          500
```

### TLS — installed 2026-09-24

The cluster presents a certificate issued by an internal CA
(`L=Suceava, O=Expertware, OU=Siembiot`) which it does **not** include in the
handshake, so the CA cannot be recovered from the connection and has to be
supplied:

```bash
cp <the Expertware internal CA> \
   /home/expert/apps/Threat-Intel-Platform/secrets/opensearch-internal-ca.crt
docker compose up -d --force-recreate api worker beat
```

`secrets/` is mounted read-only at `/run/secrets/tip` in all three services, so
the file is picked up with no further change. A bind mount to a *file* that does
not exist would make Docker create a directory in its place, which then blocks
the real file — the directory is mounted for that reason.

**Done.** The CA is installed and verification is on in the deployed
configuration — `ca_bundle_present: true`, `reachable: true`, cluster
`C00-Indexer`, no override anywhere. The certificate arrived DER-encoded, as a
Windows `.cer` usually does, and was converted with
`openssl x509 -inform DER -in <file> -out secrets/opensearch-internal-ca.crt`;
OpenSSL will not read DER as a CA bundle. It is the self-signed root
`OU=Siembiot, O=Expertware, L=Suceava`, `CA:TRUE`, valid to 2034-03-31, and it
verifies all three nodes.

`OPENSEARCH_VERIFY_TLS=false` still exists for a one-off diagnostic, but it
sends the admin password over a connection nobody has checked and is not a
configuration to leave in place.

## The password

`opensearch_password` is a pydantic `SecretStr`. Its repr is `**********` in a
traceback, a log line and a `model_dump`, and it is unwrapped in exactly one
place — `OpenSearchClient.__init__`. That is load-bearing rather than
decorative: the first live run of this client authenticated with the literal
string `**********` and came back 401, which is a bug that looks like a
misconfiguration. A test pins the unwrap, and another pins that a connection
error carrying basic-auth in its URL never reaches a log with the password in it.
