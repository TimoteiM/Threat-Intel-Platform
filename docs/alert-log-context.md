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
retrying for ever.

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

### TLS — the one thing still outstanding

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

Until the CA is in place the status is `unavailable` and the reason says exactly
this. That is the intended failure, not a bug. `OPENSEARCH_VERIFY_TLS=false`
exists and works, but it sends the admin password over a connection nobody has
checked, so it is not the configuration to leave in place.

## The password

`opensearch_password` is a pydantic `SecretStr`. Its repr is `**********` in a
traceback, a log line and a `model_dump`, and it is unwrapped in exactly one
place — `OpenSearchClient.__init__`. That is load-bearing rather than
decorative: the first live run of this client authenticated with the literal
string `**********` and came back 401, which is a bug that looks like a
misconfiguration. A test pins the unwrap, and another pins that a connection
error carrying basic-auth in its URL never reaches a log with the password in it.
