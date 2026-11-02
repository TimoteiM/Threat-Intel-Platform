# Indicator-led queries, the host panel's real yield, and what Exabeam needs

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`. See [POPULATION.md](POPULATION.md).

Measured 2026-10-22. Read-only throughout.

---

## 1. The host panel's yield: 15.5% informative, 16.0% false

Across the **last 400 closed `c00` cases**, with Falcon's own alert and
device inventory:

| state | cases | share | what a "0 open detections" headline is |
|---|---|---|---|
| host carries a **non-closed** detection | 62 | **15.5%** | informative |
| host managed, none open | ~274 | ~68.5% | a real negative, worth stating as one |
| **host has NO sensor** | **64** | **16.0%** | **false** |

Supporting figures: the CID holds **1,997 alerts, 276 not closed**, across
**35 hosts**. The 400 cases cover 109 distinct hosts.

So the panel is **not** pure noise — one case in six is genuinely
informative. But one case in six is also being shown a count for a machine
the EDR has never seen, and **a zero that means "not watched" reads
identically to a zero that means "watched and clean"**. The unmanaged hosts
behind those 64 cases are led by `windows-test-device` (29),
`expgrafana001` (10) and `asiem-victim` (8).

### What changed

* `host_threat_state` is **out of `ALWAYS`** and into a new `CORROBORATING`
  tuple that runs **last**. It was the first thing a reader saw on every
  alert; it is now the last.
* `FalconSource._host_state` returns **three states, never one number**. For
  an unmanaged host it returns `open_detections: check_failed` and the text
  *"NO FALCON SENSOR on this hostname — the EDR has never seen this machine,
  so it reports no detections because it is not watching, not because it is
  clean."* There is no path that reports a count for a host with no sensor.
* Pinned by `test_the_host_panel_is_not_run_on_every_alert`. Changing
  `ALWAYS` from two templates to one **broke no existing test**, which is why
  that test now exists.

---

## 2. Indicator-led templates: what is answerable, proven by control

Each candidate was probed with a value **actually present in the estate**,
because a filter that accepts a synthetic value and returns 0 proves nothing
— and `source_ips` did exactly that on a made-up address before the control
was run.

| question | filter | control result | verdict |
|---|---|---|---|
| has this hash been seen anywhere | `sha256:'…'` | **total 1** | **usable** — `hash_prevalence`, already existed |
| has any host an alert naming this address | `source_ips:'…'` | **total 2** | **usable** — new `ip_seen_anywhere` |
| does this filename appear elsewhere | `filename:'…'` | **total 9** | **usable** — new `file_name_prevalence` |
| (bonus) by md5 | `md5:'…'` | total 8 | usable, not yet a template |
| has any host contacted this **domain** | — | — | **impossible** — no domain field |
| **how many machines carry this file** | `/indicators/queries/devices/v1` | **HTTP 403** | **blocked by credential scope** |

Field fill rates across 200 hydrated Falcon alerts: `sha256` 96.0%,
`source_ips` 96.0%, `filename` 96.0%, `cmdline` 96.0%, `md5` 93.5%, and
**`domain`, `local_ip`, `external_ip`, `dest_ips` all 0.0%**.

Two of the three questions originally asked for are therefore **not**
answerable, and for different reasons that need different fixes:

* **domain** — the field does not exist on the alerts API. The falcon-panel
  note already called this `no_field_map`; the probe confirms it at 0 of 200.
  No template exists, deliberately, rather than one that returns
  `check_failed` forever.
* **device count per hash** — `/indicators/queries/devices/v1` and
  `/indicators/aggregates/devices-count/v1` both return **403 "access
  denied, scope not permitted"**. That is a **credential scope gap, not an
  API gap**: it needs the IOC scope added to the API client in the Falcon
  console, which is a human action and a small one. Worth asking for — it is
  the single best estate-wide prevalence question.

The three usable indicator-led templates now run **before** the class row, so
on the 16.0% of cases where the host has no sensor, the loop still asks
something that can be answered.

---

## 3. Exabeam for `lin` and `pov`: what is missing, in order

The 52 runs across the two tenants match **no playbook row**. The reason is
not that they are a different event universe — that was my first reading and
it is wrong.

### The actual finding: it is an extraction gap first

`event_name = Microsoft-Windows-Security-Auditing` on **20 of 24** `lin` runs
and 9 of 28 `pov` runs. And the bodies carry the id:

| tenant | bodies containing `<EventID>N</EventID>` | of those, **no** `event_id` in `alert_fields` |
|---|---|---|
| `lin` | **20 of 24** | **16** |
| `pov` | **9 of 28** | **9** |

**25 of 52 runs carry a Windows event id in the body that the extractor
missed.** Recoverable ids, with counts:

| id | meaning | lin | pov |
|---|---|---|---|
| 4688 | process create | 5 | 1 |
| 4697 | service installed | 5 | — |
| 5140 / 5145 | file share access | 5 / 2 | — / 2 |
| 4625 | failed logon | 2 | 4 |
| 4624 | logon | 1 | 1 |
| 4768 | Kerberos TGT requested | — | 1 |

**None of those seven ids has a playbook row.** The current rows are 10, 18,
17, 18456, 4738, 1, 29, 15, 1102, 7, 11.

The rest is genuinely different and would need its own thinking: `service =
Office 365` on 8 `pov` runs, `Cloudflare` and `cifs`/`http` on `lin`, and
`event_name` values like `ResultStatusDetail`. For those, `event_id` is the
wrong key entirely and `service` + `event_name` would be the discriminator.

Also worth knowing: **3 `lin` alerts are titled
`[SYNTHETIC - Exabeam raw log unavailable; derived from…]`** — alerts
synthesised because the raw log could not be fetched. And `rule_name` is
**None on all 52 runs**, so nothing rule-keyed will work either.

### The order, with the dependency that matters

1. **Fix `event_id` extraction** for these shippers. 25 of 52 runs have a
   recoverable id sitting in the body. This is first because **no playbook
   can key on a field that is not extracted**, and it is the cheapest step —
   it needs no connector, no credential and no vendor.
2. **Playbook rows** for the ids that then appear: 4624/4625 (logon),
   4688 (process create), 4697 (service installed), 5140/5145 (share
   access), 4768 (Kerberos). Several map onto templates that already exist —
   `host_logons`, `user_sessions`, `user_risk_timeline` — so this is mostly
   rows, not new templates.
3. **Source map entries** in `config/client-sources.yaml`, which is still
   `clients: []`. Without an entry the loop cannot resolve a source for
   either tenant, whatever the playbook says.
4. **A connector** — and **this is the blocker, and it may not be
   resolvable**. The Exabeam client authenticates and searches, but measured:
   `lin` returns rows that are **empty objects** and `pov` returns rows
   carrying **only `time`**; `host`, `user` and `dest_host` come back absent.
   A connector that authenticates and retrieves no fields gathers nothing.
   That has to be answered with whoever administers those Exabeam instances
   before steps 1–3 are worth finishing.

**Do not start at step 4 or step 2.** Step 1 is cheap, independent and
improves those tenants' alerts whether or not the connector ever works.

---

## 4. Visible proof per investigation: the SOURCES block already does this

Rendered from a real run — an **unmanaged** host, class 29, selectors
`hash`, `host`, `ip`, `user`:

```
SOURCES
------------------------------------------------------------
  READ         crowdstrike-falcon: 3 quer(ies), 2 of which held nothing, 1 event(s) kept
  NOT READ     wazuh-opensearch: wazuh-opensearch could not be read (SourceUnavailable)
              asked for: this account's risk timeline
              This is unknown, not absent — treat it as a gap in the evidence rather than a clean result.
  NOT ASKED    file_name_prevalence: no filename on this alert
  NOT ASKED    process_tree: no process on this alert

QUERIES
------------------------------------------------------------
  From the playbook — fixed for this event class, no model involved:
    hash_prevalence        empty        +0 — how many hosts have executed this image hash
    ip_seen_anywhere       empty        +0 — whether any host in the estate has an alert naming this address
    user_risk_timeline     check_failed +0 — this account's risk timeline
    host_threat_state      collected    +1 — this host's current threat state

  Chosen by the agent: none — the playbook covered this alert with the keys it carried.
```

That is all three things asked for: **which sources were queried** (READ /
NOT READ, named), **what each answered** (query counts, how many held
nothing, events kept), and **what was skipped with the reason** (NOT ASKED,
with the missing selector named). The QUERIES section adds per-template
status and the purpose in words.

Note the ordering is the change from §1 and §2: the two indicator-led
templates run first and `host_threat_state` last.

**It is tenant-agnostic by construction** — the block is rendered from the
record, and the record is per-run. So it works for `lin` and `pov` today.
What it would *show* for them is both sources `NOT READ`, because there is
no source map entry and the Exabeam search returns no fields. That is the
honest output rather than a gap in the mechanism, and it is exactly the
picture §3 says needs fixing from step 1.
