# A context-gathering stage for the alert pipeline

**Status: design note. Nothing here is built.** Written 2026-10-19 after reading
the pipeline rather than the description of it, and every claim below about
what exists was measured in this repository or this database on that date.

## 0. The brief against the code

The brief described the pipeline as: *Tracecat sends an incident, we sanitise,
extract indicators, run collectors, produce a verdict and report; what is
missing is gathering more log context from SentinelOne and Exabeam.* Checked
clause by clause, because the week's lesson is that a design built on an
unverified architecture is a design of something that does not exist:

| the brief said | what the code says | consequence for this design |
|---|---|---|
| Tracecat sends an incident | Tracecat is **inbound only**: it POSTs to `/api/alert-investigations/tenants/{tenant_id}` with an ingest API key after a `/health` preflight, and receives a signed callback. **There is no outbound Tracecat client and no Tracecat URL in config.** Measured over the last 30 days: **0 of 7,516 runs were `incident` kind** — every one was a single `alert`. | "call back through Tracecat actions" is a *build*, not a reuse. And the incident shape (`entity_type` + `event_count`) is designed for and has not arrived in a month. |
| we sanitise | Two layers, in a fixed order: `log_secret_sanitizer` (secrets → non-reversible HMAC placeholders, **by design**), then `assistant_sanitizer_service` (identifiers → reversible `[HOST_1]`-style tokens with a persisted map). | Two-way sanitisation half exists. §4. |
| extract, collect, verdict, report | `run_alert_body_investigation`: extract → exclusions → 7-day prior reuse → per-indicator collectors → deterministic log digest (6,000-token budget) → **one single-shot model call** → ATT&CK → summary. | There is **no tool loop anywhere**. An "agent" is a new construct. |
| gathering more log context is missing | **It exists for OpenSearch.** `_collect_log_context` runs *before* the analysis, persists a row per run, and schedules a bounded follow-up when the store was partial or down. | The stage is not new. It is the existing one generalised from one source to N. §1. |
| from SentinelOne and Exabeam | Both exist in this repo only as **alert channels in ingested data** and in frontend mock data. **No client for either.** | Two new connectors, each registered through the contract Falcon already uses. |

One more fact that gates everything: on 2026-10-16 the Falcon tenant this
platform had been analysing as a customer's turned out to be **our own estate**
(README rule 24). Before a SentinelOne or Exabeam client is built, resolve
whose tenant each one is. It is two API calls and it changes the audience of
every finding the stage will produce.

---

## 1. Where the stage slots in, and the contracts it must fit

### The slot already exists

```
run_alert_body_investigation_task                 (Celery, hard limit 1800s)
  │
  ├─ _collect_log_context(run)   ◄── THIS IS THE STAGE. Today: one source.
  │     collect_for_alert(tenant_id, event_time, entity_host, entity_user,
  │                       alert_body, alert_fields) -> LogContext
  │     store.save(run_id, context)                -> alert_log_context row
  │     schedule_followup(row) if partial/unavailable
  │
  ├─ run_alert_body_investigation(alert_body, log_context=…, tenant_id=…)
  │     extract → exclusions → prior reuse → collectors
  │     → _build_log_digest(log_context)  (deterministic, 6,000 tokens)
  │     → one model call (AssistantService, alert_analysis mode)
  │     → ATT&CK → summary
  │
  ├─ _finalise_log_context  (mark analysed; new_logs_since_analysis later)
  ├─ _record_alert_investigation  (the investigation record, slice 2)
  └─ deliver_alert_callback  (alert.completed | alert.failed → Tracecat)
```

The ordering comment in the task is the design rule: *"Before the analyst, not
after. Retrieving the window afterwards is what left every verdict written
without the logs beside it."* A second and third source go in the same place,
for the same reason.

### What it receives

Exactly what `collect_for_alert` receives today, which is everything the run
holds at that point:

| input | source | populated on (last 30 days, 7,516 runs) |
|---|---|---|
| `tenant_id` | the run | required; the credential vault keys on it |
| `event_time` | the run | — |
| `entity_host` → `Device(name, ip)` | the run / `alert_fields.agent`, `agent_ip` | `agent` 96% |
| `entity_user` → `Principal(account, domain, upn)` | the run / `alert_fields.user` | **25%** |
| `alert_fields.rule_id`, `rule_name` | ingest | 94% |
| `alert_fields.event_id` (`"10 \| ThreatHunting"`) | ingest | 95% |
| `alert_body` | the run | — |

`Device` and `Principal` both carry a `rejected_reason` — the join key the
stage would pivot on can already say *why* it is unusable, and a source must
honour that rather than query on a rejected key.

### What it returns

One `LogContext` **per source**, in the shape the pipeline already consumes:

```
status      collected | partial | empty | unavailable | skipped
reason      why, when not collected
window      {start, end, covered_until, complete}
logs        [ normalised events ]
sources     what was asked, of what, with any consistency absence
selectors   the keys it pivoted on
truncated   bool            # and `read_until` for the follow-up
```

The **event shape is fixed** and it is the scorer's, not the vendor's. A
SentinelOne or Exabeam event has to be mapped *into*:

```
key, id, timestamp, agent{…}, rule{id, level, description, groups,
mitre_technique}, event_id, channel, domain, users, process{image,
command_line, parent_image}, network{src_ip, dst_ip}, full_log, matched_on
```

because `score_record` reads `agent`, `rule`, `network`, `process` and a
casefolded `full_log`, and `AlertPivots` keys on `hosts, users, ips, hashes,
processes, domains, rule_ids, channels, event_ids, agent_ips`. An event that
does not land in that shape is invisible to the selection, the digest and the
model — it would be gathered and never read. Unmapped vendor fields go to
`fields` and are quarantined, never inferred (the Falcon `no_field_map` rule).

### The one storage change this forces

`alert_log_context` is **one row per run** with one `status`, one `attempts`
and one `next_attempt_at`. Two sources cannot share that row: "OpenSearch
collected, SentinelOne unavailable" has no single status, and the follow-up
state machine (5 attempts, 120 s, per row) would retry the wrong one. This is
the *two directions, never one badge* rule from `integrations.md`, one level
down.

**One row per `(run_id, source)`.** The follow-up task, the sweep and
`record_attempt` then apply per source unchanged, and `merge_logs` already
merges across reads. The run's summary (`_finalise_log_context`) reports the
**worst** source status as the headline and lists each beneath it, the way
the integrations badge does.

---

## 2. Direct platform APIs, or back through Tracecat actions

### The trade-off, honestly

| | **direct clients** | **via Tracecat actions** |
|---|---|---|
| what exists today | the whole connector stack: per-tenant encrypted vault, `open_for_tenant_sync`, `verify()`, derived status model, per-direction health, field control (four axes), `Page(rows, total, complete)`, variance axis, answer-rate check. **All paid for with Falcon.** | nothing — no outbound client, no credential, no action contract. Equal build to two direct clients, before either query runs. |
| credentials | we hold one per tenant per platform, read-only, encrypted, rotatable, verified by `verify()` | we hold **one Tracecat credential that can invoke any action** — a broader capability than any single platform key. Same shape as `admin`/`all_access` on OpenSearch: one token, every system. |
| audit | **the investigation record** — every query, its cost, its result, its step in the chain, and the verdict it fed. Tracecat's log would not have the reasoning. | Tracecat's action log has the call. It does not have why it was made or what was concluded from it. |
| the false-exculpation controls | apply: field control, nonsense probe, `Page.complete`, variance, tenant-pin verification, `claim_excludes` | **bypassed.** An action returns what it returns; a zero from an ignored filter or a page read as a population arrives as a clean answer, and every control would have to be rebuilt on the far side of the hop. |
| latency and bound | one hop, our timeouts, our `total` | two hops, Tracecat's queue, and no total unless the action exposes one |
| availability coupling | ours | **the sender's** — and the sender has delivered 0 incidents in 30 days while we are still investigating why Falcon went quiet. Routing enrichment through a system whose delivery is itself under investigation couples the stage's uptime to the thing it is meant to compensate for. |

### Recommendation

**Direct clients**, registered through the existing connector contract
(`app/integrations/<tool>_client.py` exposing `verify`), with
**the investigation record as the audit log** — it already records more than
Tracecat's log could.

The credential concern is real and is answered the way it is already answered
for Falcon: a per-tenant, read-only key in the vault, rotated, and *verified*
rather than assumed working — the five-state model exists because "enabled"
cost seven months once.

And the audit concern has a cheap answer that keeps both halves: **we already
call Tracecat back.** Add a `queries` block to the completed-run callback —
source, template, tokenised arguments, cost, status — and every query lands
in Tracecat's record **without a platform credential ever passing through
it.** That is the trade: Tracecat gets the audit, we keep the controls.

If a tenant's security policy forbids us holding its EDR key at all, that is
a per-tenant decision and the connector model already has a state for it:
`not_configured`, with the stage recording `skipped` for that source and the
verdict saying so.

---

## 3. Playbook or agent — measured, not guessed

### The key is the event class, and it is concentrated

Before deciding what a model should decide, measure what arrives. Over the
last 30 days, 7,516 runs:

| candidate playbook key | distinct values | top 10 cover | note |
|---|---|---|---|
| `rule_name` | 744 | 41% | a long tail — 744 rows to cover everything |
| **`event_id` + channel** | **144** | **81%** | **three Sysmon classes (10, 18, 17 ThreatHunting) alone are 62%** |
| `alert_source` | 2 | 100% | "Siembiot" 94%, "unknown" 6% — not a discriminator |
| `detection_rule_name` | 0 | — | **absent on 100%**; the rule lives under `rule_id`/`rule_name`. A playbook keyed on this field is keyed on nothing (rule 19). |

So a fixed table keyed on **(source channel, event class)** covers four alerts
in five with ten rows, and the three biggest rows cover three in five.

### What is predictable enough to be a lookup

A playbook row is a set of **query templates over the join keys the stage
already has**, each with a declared cost. None of these needs a model to
decide that it should run:

| event class (measured share) | fixed queries | sources | declared cost |
|---|---|---|---|
| Sysmon 10 — process access (26%) | the source and target process trees for the window; the same image hash on other hosts (the E2 shape, already measured at 43 ms) | SentinelOne deep visibility; OpenSearch | 2 + 1 |
| Sysmon 18/17 — named pipe (36%) | the process that opened the pipe, its parent, its hash elsewhere | SentinelOne; OpenSearch | 2 + 1 |
| 18456 — SQL logon failure (5%) | the source address's other logons in the window; the account's sessions | OpenSearch; Exabeam user timeline | 1 + 1 |
| 4738 / account change (1%) | the actor account's session and the changed account's risk timeline | Exabeam | 2 |
| 1 / 29 — process create, file (2%) | hash prevalence, parent chain | SentinelOne; OpenSearch | 1 + 1 |
| *any* | this host's SentinelOne threat state and this user's Exabeam risk score, if the key is present | per source | 1 each |

Every row is a lookup with a known number of calls. The 25% of runs that
carry a `user` get the user queries; the rest record `skipped — no principal`,
not nothing. A row that is not in the table records `no_playbook` for the
event class, which is a measurable gap rather than a silent one.

### What genuinely needs a decision

Three things, and only three:

1. **The second hop.** When a fixed query returns an indicator that was *not*
   in the alert — a parent process on a different host, a hash seen on four
   machines, a second account — whether to pivot on it. The playbook cannot
   enumerate what it has not seen yet. **Bound: depth 1.** A pivot on a pivot
   is the runaway loop in §5.
2. **The stop.** Whether what was gathered is enough. This is better as a rule
   than a judgement — stop when the record holds ≥ N linked events across ≥ 2
   sources, or the budget is spent — and the model only decides inside that
   envelope.
3. **The long tail.** The 19% of alerts in no top-ten row, and incidents (0 in
   30 days). Here the playbook has nothing and the model picks which
   templates to run from the same fixed set — choosing from the table, never
   composing a query from nothing.

**A model never composes a query string.** It selects a template and fills
its arguments with tokens (§4). That is what makes the detokenisation
boundary tractable and the cost bounded: the template declares its calls, the
model only picks it.

### The order to build in

Playbook first, instrumented. The investigation record already counts
`external_calls` per step; run the top-ten table for a week and *measure* how
often its results change a verdict before paying for a model to extend it.
Given this corpus — three event classes, 62% — the agent's marginal value is
in the tail, and the tail should be measured before it is served.

---

## 4. Two-way sanitisation: what exists, what does not

### What exists, and is reusable as-is

| piece | where | reusable for a query? |
|---|---|---|
| reversible identifier tokens: `[HOST_1]`, `[ACCOUNT_1]`, `[IP_1]`, `[EMAIL_1]`, `[SID_1]` | `assistant_sanitizer_service.sanitize_entries` | **yes** — the grammar is typed, numbered, and fixed |
| a persisted token → original map, shared across a batch | `token_map_json` per assistant-session entry; `existing_token_map` carries it forward | **yes** — and `existing_token_map` is exactly how the map *grows* when a query returns a new host mid-loop |
| the restore | `_restore_tokens` — longest-first, bracket-escape- and case-tolerant, callable replacement (the `\d`-in-`DOMAIN\user` bug is already fixed there) | **mostly** — see below |
| guards against tokens the model invents or leaks | `_scrub_token_leakage`, `_replace_unresolved_tokens`, `_UNRESOLVED_TOKEN_LABELS` | **partly** — the prose behaviour is wrong for a query |
| the map is reachable from a run | the run carries `assistant_session_id` | yes |
| the secret layer | `log_secret_sanitizer` — HMAC placeholders, **non-reversible by design** | **must stay non-reversible** |
| order | secrets first (`sanitize_records` on `full_log`, `message`, `process.command_line`, then `fence`), identifiers second | the same order applies to every result the stage brings back |

### Built 2026-10-19 on branch `query-agent`

`app/services/token_boundary.py` closes items 1-6 below, with migration 069
(`investigation_token_maps`) for the scoped, expiring map. What it still
misses is enumerated in
[token-boundary-gaps.md](token-boundary-gaps.md) — measured, not estimated,
and pinned by a test that asserts the gaps are still open.

One finding changed the design: **bare `[HOST_1]` tokens are textually
identical across investigations**, so a token from one tenant does not fail
under another's map — it resolves to a different host and answers
confidently about the wrong estate. The scope therefore lives *in* the token
(`[HOST_a3f9c1_1]`), which turns that into a refusal.

### What did not exist before it

1. **Restoration is applied to the report, after the model.** There is no
   mid-flight, because there is no loop. For an agent the map has to exist
   *before* the first model call — tokenise the alert and the playbook
   results, then loop — and be extended as results arrive. The service's
   `existing_token_map` parameter supports that; nothing calls it that way.

2. **`_restore_tokens` is prose restoration, not query detokenisation.** It
   replaces tokens anywhere in a string. A query needs *structural*
   detokenisation: a token in an argument slot becomes the exact value; a
   token anywhere else — in a template name, an operator, a field — is a
   refusal, not a substitution. And it is private to `AssistantService`; it
   needs lifting into a boundary function with one job.

3. **An unresolved token is handled wrongly for a query.** In prose, a token
   the model invented becomes "the affected host" and the sentence survives.
   In a query, an invented token means **the query cannot be executed** and
   the step is `check_failed` with the token named — never a stripped
   argument sent to the platform, which would search for the literal string
   `[HOST_7]` and return a clean zero. That is the `behaviors.sha256` shape
   with a model choosing the field.

4. **A secret placeholder must be refused, not detokenised.** `<SECRET:…>` is
   one-way on purpose. A model that puts one in a query argument is asking us
   to search a platform for a password; the boundary refuses and the step
   records why.

5. **The detokenised query must never be stored.** The investigation record's
   `query` column holds our own OpenSearch query today, which is fine. A
   detokenised SentinelOne query carries real hostnames and accounts, and that
   column is read by the model-safe report path. So the record stores the
   **tokenised** form, the boundary returns the executable form to the
   caller only, and nothing logs it — the same rule the recorder already
   applies to excerpts via `sanitize_text`.

6. **Results need the same two layers, in the same order, with the same map.**
   Secrets first, because a SentinelOne command line is exactly where a
   `-Password` argument lives; identifiers second with `existing_token_map`,
   so the host the alert called `[HOST_1]` is `[HOST_1]` in the result too.
   A result tokenised with a fresh map is a result the model cannot join to
   the alert.

7. **Vendor fields are untyped until converted** (backlog 35). The secret
   layer's default field list is `full_log`, `message`, `process.command_line`
   — the Wazuh shape. A SentinelOne event's secrets live elsewhere, and a
   field the layer has no rule for passes through untouched. Each connector's
   normaliser declares which of its fields carry free text, or the layer
   misses them silently.

---

## 4b. Built against a mock, 2026-10-20

`app/services/context_gathering/` — playbook, agent, loop, mock source. No
connector and no credentials: the loop, the budget, the stop rule and the
record are what needed building, and a real platform would have made every
test cost somebody's quota.

**Measured on the mock corpus, weighted to the real class shares:**

| event class | share | playbook | hop | total | events | from the hop |
|---|---|---|---|---|---|---|
| Sysmon 10 process access | 26% | 3 | 0 | 3 | 6 | 0 |
| Sysmon 18/17 named pipe | 36% | 3 | 0 | 3 | 5 | 0 |
| Sysmon 18, no hash on the alert | 5% | 2 | 1 | 3 | 5 | **3** |
| 18456 SQL logon failure | 5% | 4 | 0 | 4 | 4 | 0 |
| 4738 account change | 1% | 2 | 1 | 3 | 4 | **2** |
| tail — no playbook row | 19% | 0 | 3 | 3 | 4 | **4** |
| a host that answers nothing | 8% | 3 | 0 | 3 | 0 | 0 |

**3.05 queries per investigation**, 79% playbook and 21% hop.

**The hop never fires on 75% of the corpus** — every class the playbook
covers with the alert's own keys. Where it does fire it is the only thing
that runs (the tail) or it recovers a query the playbook had to skip for a
missing selector. That is §3's prediction holding: the agent's marginal value
is in the tail.

**What is real here and what is not.** The class shares are measured over
7,516 runs. The *shape* of the finding is structural — the hop is defined to
act only on indicators the alert did not carry, so it cannot fire where the
playbook already has them. The **event counts are my mock's invention** and
say nothing about what a real platform returns.

Three defects the mock caught before any of this touched a real platform, all
of them in the agent rather than the plumbing:

1. it pivoted on `agent.ip` — on every record by construction, so true of
   every row and able to discriminate between none;
2. it could not see a **hash at all**, because it looked for token-shaped
   values and the boundary deliberately leaves a SHA-256 alone;
3. it required an indicator to appear on two hosts before pivoting, which can
   never fire on the single-host result that pivoting exists to widen.

And two in the boundary's use, caught by tests rather than by a leak: a bare
selector like `EXPDC001` has no key beside it so `tokenize()` returned it
unchanged — `tokenize_value(value, kind)` was added for callers that know the
class — and a vendor's composite `key`/`id` carries a hostname that no
detector can see, so those fields are digested rather than tokenised.

---

## 5. Failure modes

### Runaway query loops

Bounded by **construction**, not by a counter the model is asked to respect:

* the model selects templates; it never composes queries;
* pivot depth ≤ 1, and a pivot's own results are never pivoted on;
* a per-investigation ceiling on **distinct** `(source, template, arguments)`
  — distinct, because a retry storm against a slow platform is also a loop,
  and a count of calls would not see it;
* per-source `max_hits` (the 500 precedent) and `Page.complete`, so a loop
  cannot chase a population it never finished reading;
* the follow-up's state machine for anything partial: 5 attempts, then
  `failed`, with the countdown and the once-a-minute sweep as they are.

And the invariant that makes a breach visible: the record's `external_calls`
header equals the sum over its steps, asserted — the same test that now holds
the model-call counter to its steps.

### Cost per investigation

What is measured today: **one** model call per run; OpenSearch 43 ms median;
Falcon **5 calls and 1.44 s per host**; a 6,000-token digest budget. There is
no per-investigation money budget anywhere, and the only two cost counters are
the record's.

* **Playbook rows declare their call count**, so the cost of a run is known
  before it starts from its event class.
* **The agent adds `1 + k` model calls** for `k` pivots, `k ≤ depth × fan-out`,
  and the fan-out is the thing to cap — a hash seen on 113 hosts (measured) is
  one query, not 113.
* **Per-source timeouts must sum to less than the task's `soft_time_limit`**
  (1740 s). The stage runs sources **concurrently** — the recorder already
  takes a lock for exactly that — so the stage's wall clock is the slowest
  source, not the sum, and a slow platform costs its own timeout and nothing
  else's.
* Every constant here is `calibrated_on_self` until it is measured on a real
  corpus — the same label the escalation spec carries.

### A platform slow or down mid-investigation

The precedent is exact and it is the right one: **enrichment never fails an
alert.** `collect_for_alert` returns `unavailable` with its reason; the row
is saved; the follow-up is scheduled; the analysis runs over what was
gathered; and the verdict says *"SentinelOne could not be read"* — `check_failed`
with the source named — **never** *"SentinelOne found nothing."* That is
slice 3's `unknown`-is-not-`clean`, and it is the single most important
property of the stage.

Three additions for multiple sources:

* **One source's timeout never blocks another's answer.** Concurrent, each
  with its own deadline, each with its own row.
* **A source answering late**, after the model has already reasoned: the
  follow-up already defines `new_logs_since_analysis` and marks the row.
  Reuse it — a late answer **offers** a re-analysis and is counted; it is
  never appended silently to a verdict formed without it.
* **A source that is quiet for a tenant** is caught by the answer-rate check
  the catalogue registers for free — which means a SentinelOne that stops
  answering is noticed by the machinery, not by someone wondering why the
  panels went blank. That is the control that was missing when Falcon went
  quiet for eight days.

---

## 6. What this does not decide, and what gates the build

* **Whose tenants SentinelOne and Exabeam are.** Resolve before a client is
  written (rule 24).
* **Where the event-class table lives** — a declared module like
  `ALERT_HASH_FIELDS`, with the registry test the templates module already
  has, so an event class with no row is visible rather than silent.
* **Vendor normalisers** (backlog 35) as the only way a SentinelOne or Exabeam
  payload enters, with raw access made impossible by the type.
* **The agent at all**, until the playbook has run for a week and the record
  says how often its results moved a verdict.
