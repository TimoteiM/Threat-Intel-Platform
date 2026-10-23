# Why lin/pov/boc alerts do not become cases — and the 18.7% that never can

Measured 2026-10-23, read-only, prompted by the Reports dropdown showing
`boc (0 cases · 1 alerts)`.

**Short answer: the incident path already exists and works. These alerts do
not take it, and the ones without a host cannot take any path at all.**

---

## 1. The incident mechanism is built and correct

`alert_correlation_service` already holds exactly the model described —
*"a payload that is already a session is a case, not a member of one"*:

```python
if str(row.alert_kind or "alert") == "incident":
    incidents.append(row)
    continue
...
for incident in incidents:
    grouped[(source, client,
             f"{incident.entity_host or 'unknown'}\x1fincident:{incident.id}")
            ].append(incident)
```

Two properties that matter here:

* each incident is **keyed on its own row id**, so it forms a single-member
  case and can never be pooled with the alerts it summarises;
* it uses **`entity_host or 'unknown'`** — an incident does **not** need a
  host.

It is also a path that has already been debugged once. The comment above it
records the previous failure in this exact shape: *"It used to be dropped here
and nowhere picked up… 18 incident rows on 8 hosts produced exactly zero
cases, with no SLA clock and nothing on the page."*

**18 runs carry `alert_kind='incident'` today**, all on the unassigned tenant.
They become cases.

## 2. lin/pov/boc carry `alert_kind='alert'`, all 81 of them

| tenant | runs | `alert_kind` |
|---|---|---|
| c00 | 16,982 | `alert` |
| pov | 41 | `alert` |
| lin | 39 | `alert` |
| boc | 1 | `alert` |
| (unassigned) | 1,027 / **18** | `alert` / **`incident`** |

The classification is made once, at ingest:

```python
alert_kind = "incident" if is_pre_correlated(alert_fields) else "alert"

def is_pre_correlated(fields):
    return bool(fields.get("entity_type") and fields.get("event_count"))
```

**It needs two specific keys, and these senders send neither.** Across all 81
lin/pov/boc runs, the extracted fields are:

| field | runs |
|---|---|
| `event_name` | 58 |
| `service` | 28 |
| `user` | 27 |
| `agent`, `agent_ip` | 23 |
| `event_id` | 15 |
| `event_log_level` | 12 |
| `body_provenance` | 11 |
| `event_severity` | 1 |
| **`entity_type`** | **0** |
| **`event_count`** | **0** |

So the statement *"lin, pov and boc are generated as incidents"* is true of the
**source systems** and is **nowhere in the payload**. Nothing we receive says
so, and `is_pre_correlated` is not wrong — it is being asked a question the
data cannot answer.

This is the same shape as the body-provenance finding: the sender knows
something we need, and it does not reach us in band. The difference is that
there the sender *did* declare it and we dropped it; here the declaration was
never made.

## 3. The bigger finding: 18.7% of all runs can never form a case

Independent of incident-ness, and not specific to these tenants.

`correlate_alerts` builds its working set with:

```python
.where(AlertBodyInvestigationRun.entity_host.isnot(None))
```

and the non-incident grouping key is `(alert_source, alert_client,
entity_host)`. So **a run with no `entity_host` and `alert_kind='alert'` is
excluded from correlation entirely** — it can never appear in a case, an SLA
clock, the case list or a report.

| tenant | runs that can never form a case |
|---|---|
| c00 | **2,545** |
| (unassigned) | 791 |
| lin | 32 |
| pov | 25 |
| boc | 1 |
| **total** | **3,394 of 18,108 — 18.7%** |

Confirmed from the other side: **`alert_case_spine.entity_host` is NOT NULL on
all 2,677 case rows.** No case without a host has ever existed.

This is why `boc` showed `0 cases · 1 alerts`: its single run has no host and
is not an incident, so it falls through both paths. It is not a boc problem.
**2,545 c00 runs are in the same position**, and nobody has noticed because
c00 has 14,435 that do have a host.

### Why it is silent

The exclusion is a `WHERE` clause. A run that is dropped there produces no
error, no status, no `absence` record and no row anywhere saying "this alert
was not correlatable". It is simply missing from every case-shaped surface —
which is the recording-a-failure-is-not-reading-it shape again, except here
the failure is not recorded at all.

---

## 4. What the options actually are

**Not a code fix to make on a guess.** Changing which runs become cases
changes case keys and therefore case numbers, and the key derivation carries
explicit warnings about re-keying renumbering the whole case list
(`_CLIENT_IN_KEY`, `CASE_KEY_VERSION`).

| option | what it does | cost |
|---|---|---|
| **A. Sender declares it** | lin/pov/boc senders include `entity_type` + `event_count`, or an explicit `kind`. The existing path then just works. | no code here; needs the connector/workflow owners — the same people as the Exabeam gap |
| **B. Per-integration declaration** | a setting on the integration: *this source emits incidents*. Classification becomes configuration rather than inference, and a tenant that later sends raw alerts too is still handled | small schema + ingest change; honest, and checkable |
| **C. Broaden `is_pre_correlated`** | infer incident-ness from what is present | **no signal exists** — there is no count, no entity_type, nothing incident-shaped in those 81 payloads. Inferring from `tenant_id` would be a fact true of every row of that tenant, which cannot discriminate |
| **D. Let hostless alerts form cases** | separate from incident-ness, and the one that addresses all 3,394 | changes correlation for c00 too; needs its own design and a predicted direction before any code |

**C is not viable** on the measurement. A and B are the real choices for the
incident question; D is a separate, larger decision about the 2,545 c00 runs.

Minimum honest step regardless of which is chosen: **make the exclusion
visible.** A run that cannot be correlated should say so — a status, a count on
the reports page, something — rather than being absent. Today the only way to
discover it is to compare two tables by hand, which is how this was found.
