# Phase 3 reconnaissance: the `ioc_values` ceiling, and the log store

2026-10-14. Report only, no implementation.

---

## 1. What `ioc_values` is

**It is a column, not a table.**

| | |
|---|---|
| column | `alert_body_investigation_runs.ioc_values`, type `text[]` |
| grain | **one row per alert run** — 16,960 rows |
| contents | 34,922 array elements, **mean 2.06 per run**, max 73 |
| entry point | `alert_case_linkage_service.ubiquitous_values_across_estate()` |
| index on it | **none.** Seven btree indexes on the table, none on the array |

A run carries **no `case_key`**. The run→case mapping is derived from
`(alert_source, alert_client, entity_host)` plus the session window on
`alert_case_spine` — 2,172 cases. Only 202 have frozen membership, in
`case_read_set.run_ids`.

So `ioc_values` is per-run, cases are per-case, and the conversion between
them is a merge over a derived join.

## 2. What the "ceiling" claim actually was

`UBIQUITY_HOST_LIMIT = 10` in `alert_case_linkage_service`:

```sql
GROUP BY lower(value)
HAVING count(DISTINCT r.entity_host) > :limit
```

**It is at host grain, and it is for *within*-case linkage** — deciding which
alerts on one device belong to one case. Its measured basis, from that
module's own docstring: `expertware.net` on 130 distinct hosts, `onenet.be`
on 49, a Microsoft schema URL on 47, an all-zero hash on 23; 1,984 of 2,185
distinct values on a single host, so the cut removes 19 values.

**It does not answer the Phase 3 question.** Phase 3 asks "which other
*cases* contain this indicator". That is a third grain — not per run, not per
host — and nobody has measured it. That is why it has sat as "the ceiling is
unscoped" since Friday.

## 3. The case-grain distribution

### First, the trap

The obvious join — runs to spine on source/client/host within the session
window — produces this:

| cases containing it | values | share |
|---|---|---|
| 1 | 93 | 4.4% |
| **2** | **1,305** | **61.7%** |
| 3 | 269 | 12.7% |

A mode at exactly two is the shape a **fan-out** produces, not a property of
indicators. It is:

> **90.8% of runs (12,390 of 13,639) map to more than one case** under that
> join, because **2,044 spine rows have session windows that overlap another
> case on the same (source, client, host).**

So every indicator on such a run was counted once per overlapping case. That
first table is an artefact of my own query and is reported here only so
nobody rebuilds it.

### The distribution, one case per run

Deduped to the newest session per run — 2,114 distinct values, **4,321**
(value, case) pairs rather than 9,798, so the naive join inflated by 2.3×:

| cases containing it | values | share | cumulative |
|---|---|---|---|
| **1** | **1,811** | **85.7%** | 85.7% |
| 2 | 150 | 7.1% | 92.8% |
| 3 | 53 | 2.5% | 95.3% |
| 4 | 19 | 0.9% | 96.2% |
| 5 | 24 | 1.1% | 97.3% |
| 6–10 | 24 | 1.1% | 98.4% |

Percentiles of case count: **p50 = 1, p75 = 1, p90 = 2, p95 = 3, p99 = 17,
p99.9 = 85, max = 778.**

**Control:** the derived join reproduces **567 of 575 (98.6%)** of the
frozen `case_read_set` memberships, so the derivation is sound and the 1.4%
gap is noted rather than ignored.

### The shape

A long tail and a sharp head, with almost nothing between them.

* **85.7% of indicators appear in exactly one case.** They can never pivot,
  and they are the overwhelming majority.
* **The head begins between p95 and p99 — between 3 and 17 cases.** Below 3,
  a shared indicator is a genuine coincidence worth showing. Above ~17 it is
  infrastructure.
* The head itself, top by case count:

| cases | value | what it is |
|---|---|---|
| 778 | `expertware.net` | the client's own domain |
| 85 | `onenet.be` | their ISP |
| 85 | `http://schemas.microsoft.com/win/2004/08/events/event` | a schema URL in every Windows event |
| 75 | `6.0.4.27` | **a version string**, parsed as an IP |
| 51 | `microsoft.net` | |
| 50 | `00000000000000000000000000000000` | an all-zero hash |
| 40 | `https://login.lineas.net` | |
| 33 | `7df64ae9a0def9c161dcc89b5b6cfc87` | |

**Four of the top eight are not indicators at all** — a schema URL, a version
number, an all-zero hash, and the client's own domain. Yesterday's
shared-provider apexes are the same shape one system over: `discord.com`
would pivot into every case that ever touched Discord.

## 4. What a pivot costs today

Measured with `EXPLAIN ANALYZE` on the live table (16,960 rows, 482 MB).

| query | plan | time |
|---|---|---|
| `= any(select unnest(...))` — the form in the code | Seq Scan + SubPlan | **123 ms** |
| `ioc_values @> array[...]` — same answer | Seq Scan | **23 ms** |
| `@>` for a rare value (34 rows) | Seq Scan | **30 ms** |
| full pivot: `@>` joined to the spine for case keys | Seq Scan + index join | **31 ms** |

The spine join *is* indexed (index condition on source/client/host). The
array scan is not, and **rewriting the existing `= any(unnest)` form as `@>`
is a 5× win on its own, with no index at all** — it avoids the per-row
SubPlan.

### What a GIN index buys

Built, measured and rolled back inside a transaction, so nothing persists:

| | |
|---|---|
| build time | 215 ms |
| index size | **1,376 kB** (against a 482 MB table) |
| rare indicator (34 rows) | **0.17 ms** — Bitmap Index Scan, 33 heap blocks |
| common indicator (6,903 rows) | 25 ms — **the planner correctly ignores the index** |

That last row is the finding, not a disappointment: at 41% selectivity a
sequential scan *is* the right plan, and Postgres knows it. **The index helps
exactly for the indicators that are selective enough to mean something, and
is correctly skipped for the ones that are not.** The performance question and
the meaning question have the same answer.

## 5. What Phase 3 needs that does not exist

| need | cost | note |
|---|---|---|
| `CREATE INDEX ... USING gin (ioc_values)` | 1.4 MB, 215 ms build | 180× on selective lookups; no downside measured |
| rewrite `= any(unnest)` → `@>` | one query | 5× before any index |
| a stored run→case link | migration + backfill | **the real gap.** Today every pivot re-derives membership through an overlapping-window join that fans out 90.8% of runs |
| a prevalence table or materialised view | small — 2,114 rows | needed only if the threshold is applied per query; a nightly refresh would do |
| the overlapping-session question | design | 2,044 spine rows overlap another case on the same host. Until that is resolved, "which cases contain this" has no single answer |

**The run→case link is the blocker, not the index.** The index is 1.4 MB and
fifteen minutes. The join that fans out 90.8% of runs is a correctness
problem, and a pivot built on it would report a case count 2.3× too high —
which is the number an analyst would be reading.

## 6. The threshold is a meaning number

> Two cases sharing an indicator seen in 300 cases tells an analyst nothing;
> two cases sharing one seen twice tells them a great deal.

It falls out of the distribution rather than being chosen:

* **≤ 3 cases (p95)** — a shared indicator is a real coincidence. 95.3% of
  values are here, and each pivot yields at most two other cases to read.
* **4–16 cases** — a thin band, 1.6% of values. Worth showing with the count
  attached so a reader can judge.
* **≥ 17 cases (p99)** — infrastructure. 1% of values, and the named head is
  a schema URL, a version string, an all-zero hash and the client's own
  domain.

So a pivot threshold of **"appears in fewer than 17 cases"** is where the
measured distribution breaks, not a round number. Every pivot should carry
its prevalence beside it — "also in 2 other cases" is information; "also in
778 other cases" is a statement about the estate, and the number says which
without the analyst having to know.

**And the existing host-grain ceiling is not reusable.** 10 hosts and 17
cases are different units over different populations; using one for the other
is the conversion error this report spent its first section avoiding.

---

## 7. The log store: checked, not assumed

**It is OpenSearch, not Elasticsearch, and it is reachable.**

| | |
|---|---|
| cluster | `C00-Indexer`, OpenSearch **2.19.4** |
| node answering | `os-002.c00.siembiot.expertware.net:9200` |
| TLS | verified, CA at `/run/secrets/tip/opensearch-internal-ca.crt` |
| indices | **350 total, 120 matching `wazuh-alerts-4.x-*`** |
| documents | **2,572,498,508** |
| retention | **2026-06-16 → 2026-10-14 — 120 days** |
| volume | ~25M docs and ~85 GB **per day** |

### Does it hold network, DNS or proxy logs?

Measured by field existence across the full 120 days:

| field | docs | what it is |
|---|---|---|
| `data.dstip` | **2,072,297,183** | destination IP |
| `data.url` | 54,889,070 | URL |
| `data.win.eventdata.queryName` | 4,035,557 | **Sysmon event 22, DNS query** |
| `data.srcip` | 223,270 | source IP |
| `data.win.eventdata.destinationIp` | 148,900 | Sysmon network connect |
| `data.win.eventdata.destinationHostname` | 137,055 | Sysmon network connect |
| `data.dns.question.name` | **0** | no dedicated DNS pipeline |
| `data.http.url`, `data.proxy.url` | **0** | **no proxy logs** |

### Coverage is the number that matters, not presence

Last 7 days, 8 indices, 164.6M documents:

| field | docs | **distinct hosts** |
|---|---|---|
| `agent.name` | 164,618,297 | **180** (the denominator) |
| `data.win.eventdata.queryName` | 2,599,670 | **175 — 97.2% of the estate** |
| `data.win.eventdata.destinationHostname` | 1,533 | 116 |
| `data.dstip` | 126,708,398 | **1** |
| `data.url` | 14,379,963 | **1** |

**`data.dstip` is the largest field in the store by two orders of magnitude
and it comes from a single agent** — a network appliance, not endpoints. It
answers "did the perimeter see this address", which is a different question
from "did any host touch it". The same is true of `data.url`. Reading either
as estate-wide endpoint telemetry would be the grain error again, and it is
the easiest one to make here because the document count is so large.

**The domain lookup is viable and the IP lookup needs care.** Sysmon DNS
query logging is on **175 of 180 hosts**, so "did any host resolve this
domain" is a real question with a real answer. Per-host IP egress is thin —
148,900 Sysmon `destinationIp` docs against 2.07bn perimeter records.

### Cost, measured

| lookup | result | time |
|---|---|---|
| `www.google.com` over 7 days | 44,669 docs, 5 hosts | **209 ms** |
| a domain with no hits | 0 docs | **28 ms** |

### And the field types are exact

`data.win.eventdata.queryName`, `data.dstip`, `data.url` and `agent.name` are
all **`keyword`**, so a `term` query is an exact match. This was checked
specifically because of the Falcon finding below: an analysed field would
make a `term` query silently match nothing, which is the same failure in a
different system.

---

## 8. A standing defence for third-party field names

The Falcon Alerts API returns **HTTP 200 with zero resources for an invented
FQL field name** — measured: twelve fields including `behaviors.ioc_type`,
which does not exist. A third party will lie in exactly the direction this
week has been about, and unlike our own code we cannot fix it.

**The rule: for every third-party query field this platform relies on, assert
once against the live tenant that the field can return a non-empty result.**

A field that has never returned anything is indistinguishable from a field
that does not exist, and the difference is a detection nobody will ever see.
The assertion is cheap — one query per field, run on configuration or on a
schedule — and it is the only thing that separates the two cases.

This applies to Falcon's FQL fields in the ingest pass, and it is why the
OpenSearch field types above were checked rather than assumed.
