# Client separation in Alert Body Investigation

Thirteen thousand runs existed in one undifferentiated list. `alert_client` was
already there and could not be the boundary: it is self-declared by the payload,
and 13,060 of 13,079 stored runs said `unknown`. This adds a tenant the platform
*verifies*, and scopes every read and write to it.

## Where the boundary is enforced

One place, because isolation re-implemented per endpoint holds only on the
endpoints someone remembered.

| Surface | How |
|---|---|
| list, count, search, verdict filter, pagination | `tenant_scope.apply()` on **both** the page query and the count |
| run detail, logs, case, export, cancel, sandbox, delete | `_get_run_scoped()` — the single loader every per-run route uses |
| correlated case members | filtered individually; hidden members are counted, not silently dropped |
| ingest | `tenant_scope.resolve_for_ingest()` before the row exists |
| OpenSearch | per-tenant integration, no shared default |

`test_every_run_route_is_tenant_scoped` walks the router source and fails if a
per-run route reaches a run without going through the scoped loader, so a route
added next month is caught rather than assumed.

**A tenant you may not see is 404, never 403.** A 403 confirms the run exists,
which is exactly the fact a client-restricted caller is not entitled to —
enumerating ids against a 403 counts a competitor's alerts.

**An account with no tenants matches nothing, not everything.** The SQL says
`WHERE false` rather than omitting the filter; an empty `IN ()` is the classic
way a scoped query quietly becomes an unscoped one.

Verified against live data:

```
internal, all clients : 13,099     c00 analyst : 12,453
internal, unassigned  :    646     lin analyst :      0
opening a c00 run as a lin analyst    -> 404 Alert investigation not found
lin analyst filtering ?tenant=c00     -> 403 You do not have access to tenant 'c00'
```

## The historical migration

Measured against the 13,079 stored runs *before* writing the rule:

```
alert_source='Siembiot'            12,443   ALL carry 'Manager: Siembiot'
alert_source='unknown'                630   NONE carry it
alert_source='wm-c00.siembiot.int'      5   the C00 manager naming itself
alert_source='probe'                    1   carries it
```

The marker and the source agree exactly, and — the check that mattered — the
marker never contradicts a declared client: the 18 runs declaring `LIN` do not
carry it. Two rules, each recorded on the row it assigned:

| Rule | Condition | Assigned |
|---|---|---|
| `marker` | `Manager: Siembiot` **and** no other client declared | 12,448 |
| `manager_source` | `alert_source` is the C00 manager hostname | 5 |
| — | everything else | 631 left unassigned |

Migration **031** re-runs those same two rules over anything still unclassified.
It exists because 030 classified what existed when it ran, while the code that
classifies an alert *at ingest* went live a few minutes later — 15 alerts
arrived in that gap, all `alert_source='Siembiot'` carrying the marker, and
nothing assigned them. They are deploy timing, not legacy data. It touches only
rows where `tenant_id` **and** `tenant_assignment` are both NULL, so a run the
ingest path deliberately filed as `unassigned` is never swept up, and it is safe
to run again. The gap cannot recur: every ingest now records an assignment,
including `unassigned`.

The unassigned 631 are Cloudflare, Office 365, Skyformation, SentinelOne,
Exabeam and raw Windows event XML — a TraceCat-shaped mix of **channels**, and a
channel is not a tenant. 22 of them mention "siembiot" somewhere and 9 mention
"wm-c00"; that is suggestive and is not verification, because a hostname can
appear in a log forwarded from anywhere. They sit in a labelled *Unassigned
(legacy)* view that only internal users can select.

The single run declaring `Codex Desktop` *does* carry the marker. The rule
refuses it rather than resolving the contradiction silently.

### Why the selector showed no client

An all-tenants identity carries an **empty** `tenant_ids` — "everything" is not
a list — so a selector built from the scope offered internal staff only *All
clients* and *Unassigned*, and no way to pick C00. The options are named by the
server instead, which is the only side that knows what exists, and their counts
go through the same scoped query as the list so the selector cannot leak another
client's volume after the list itself was locked down.

## Two ingest paths, and only one of them has a credential

| Path | Credential | Tenant decided by |
|---|---|---|
| API key | `Authorization` header, with `tenant_ids` | the credential — `tenant_id` authorised against it |
| Trusted source address | **none** — admitted by CIDR | the marker rule, the same one migration 030 used |

NiFi delivers over the second: the appliance cannot carry a header, so it is
admitted by source address and presents nothing to authorise a tenant against.
That path is therefore the legacy one by definition, and it **must never
refuse**. Requiring a tenant grant from it returned 400 to every POST for four
hours while NiFi reported success, so nothing upstream noticed until the alert
list stopped moving.

A C00 alert over that path is filed `c00` by the marker; a Cloudflare or Office
365 alert from the same sender is filed unassigned rather than mislabelled,
because TraceCat shares the path and a channel is not a tenant. A payload that
claims a different client is left unassigned rather than overridden.

The trusted path may name the legacy tenant — that is what the marker would
have decided anyway — and naming any other gets a 403 saying an API key granted
that tenant is required. **Onboarding a second client over NiFi therefore means
giving NiFi an API key**, which is a thing to arrange with the dev team, not to
impose by rejection.

## The request contract

`tenant_id` is mandatory under the new contract and is authorised against the
**credential**, never taken on trust. It is read from the request body only —
never from the alert text, which is attacker-influenced content and must not
choose its own tenant.

```
existing C00 key, no tenant_id   -> c00   via legacy_fallback   (today's flow, unchanged)
C00 key declaring c00            -> c00   via declared
C00 key declaring lin            -> 403
a LIN key declaring lin          -> lin   via declared
a new key, no grant, no tenant   -> 400 tenant_id is required
```

The fallback is confined to a credential holding **exactly** the one configured
legacy tenant. A key holding two tenants and naming neither is ambiguous, and
guessing which it meant is how one client's alerts land in another client's
list. Setting `ALERT_INGEST_LEGACY_TENANT=""` ends the transition and makes
`tenant_id` mandatory for every sender.

## OpenSearch follows the verified tenant

The cluster read today is C00's, pinned to `manager.name: wm-c00.siembiot.int`.
Running that query for another tenant would not error — it would return C00's
logs under someone else's alert.

So there is **no shared default**. The global `OPENSEARCH_*` block *is* the C00
integration and is reachable only by tenant `c00`; every other tenant needs its
own block, and a tenant without one reports *unavailable* rather than falling
back. An unassigned run has no cluster it is entitled to read at all.

```
OPENSEARCH_TENANT_<ID>_NODES / _USERNAME / _PASSWORD
OPENSEARCH_TENANT_<ID>_INDEX_PATTERN / _MANAGER / _CA_BUNDLE / _VERIFY_TLS
```

An integration is only "configured" when it has a tenant pin as well as nodes
and credentials: nodes without a filter would query the whole cluster, and on a
shared cluster that is the boundary gone. Nothing about the connection is ever
taken from an alert request — `integration_for()` takes a tenant id and a
settings object, and there is no parameter a request could arrive through.

## The analyst log view

The default is **Around the alert**: the alert highlighted in place, five events
either side, and a *Load N newer / older documents* control at each end — the
shape Discover uses for surrounding documents, because starting at the thing
that fired is how a window is actually read. A flat page makes you find the
alert before you can begin.

The anchor is the alert's **own OpenSearch document**, matched on
`external_ref`, which is the sender's `_id` and is one for 12,450 of 12,470
stored C00 runs. Where it is missing, or the entity filter excluded that
document from the window, the anchor is synthesised at the alert's event time
and labelled as such — the view is never anchorless and never quietly presents a
neighbouring event as the alert.

Columns: time, offset from the alert, agent, agent IP, domain, system channel,
rule description. *All retrieved events* remains one click away with the search
and filters.

`data.win.system.channel` was added to the stored projection for that column.
Retrieval keeps a fixed subset of each document — 1,644 mapped fields is far too
many to store whole — so anything already stored lacked it, and
`refresh_log_context` re-read all 111 existing contexts to fill it in. It
replaces rather than merges, because the merge keeps the record it already has,
which is the poorer one here.

### What an expanded row shows

The event's **own** fields, whatever they are for its event id — a Document
summary in the shape OpenSearch shows one.

This replaced an enumerated projection, and the enumeration was a class of bug
rather than a missing entry. The list named Sysmon's `image`, `commandLine` and
`parentImage`; Security event 4688 calls the same three things
`newProcessName`, `commandLine` and `parentProcessName`, so every 4688 row came
back blank — and so did every event type nobody had thought to add. The number
of blanks was a function of how many event ids had been considered, not of
anything real.

So `data.win.system.*` and `data.win.eventdata.*` are taken whole. It costs
nothing: measured over 300 recent documents, `eventdata` is 467 bytes at p90
and 743 at its largest, with at most 21 fields. The enumeration was not buying
size, only omissions. Non-Windows vendors stay enumerated — an Office 365 or
AWS `data` object runs to hundreds of fields, and `data.*` would be a different
mistake.

Three details that are easy to get wrong:

* **The fields are a list of pairs, not an object.** JSONB normalises key order
  by length then bytewise, so a mapping came back with `data.win.system.task`
  above `data.win.eventdata.newProcessName` — the reverse of what a reader
  wants. `eventdata` leads, because it is what the event is *about*.
* **They are sanitised.** These are whatever the event happens to carry, so they
  are exactly where an unanticipated secret lives; sanitising only the fields we
  had named would repeat the mistake that made the capture necessary.
* **`data.win.system.message` is dropped.** It restates every field below it,
  runs to hundreds of characters, and truncating it cuts mid-sentence.
  `full_log` keeps the raw event.

A machine account is no longer shown ahead of a person: `EXP-47VD864$` in the
user column says nothing the device column has not already said, while
`dnechita` on the same event is the answer.

Adding fields to the projection does not reach what is already stored, so
`refresh_log_context` re-reads existing contexts. It has been run; all stored
events carry their own fields.

### The searchable list

Every retrieved event, not only the ones the model saw. The two sets are kept
visibly distinct because conflating them is how an analyst comes to trust a
verdict more than it deserves:

* **retrieved** — everything in the ±10-minute window, listed and paged;
* **sent to AI** — a ranked subset, marked with an `AI` chip, and an *opt-in*
  filter rather than the default view.

The alert is a marker drawn between two rows, so events before and after it read
as one chronological chain. Columns: time, offset from the alert, device, user,
rule/event id with level, message, and the AI marker. A row expands to the
command line, process, network, rule groups, why it matched, the raw log, and
its `index:id`.

## What goes to the model, and why

Deterministic and explainable — `alert_log_selection.explain()` prints the whole
score. Not a second AI call: asking a model which logs to send a model costs the
thing it is meant to save and makes the decision unexplainable.

* **Exact links first**: same device, same account, shared IP, file hash from
  the alert, same process image, a domain the alert named.
* **Significance as a ranking signal, never proof**: Wazuh rule groups and
  Windows event ids (4672, 4720, 7045, 1102, Sysmon 1/3…). `rule.level`
  contributes at most 3 points and is capped deliberately — level 3 noise is
  where a chain hides and level 12 is frequently a misconfigured scanner.
* **Reserved lanes**: 35% before the alert, 35% after, 15% near it, 15% open,
  so one burst cannot consume the context an analyst needs from the other side.
* **Near-duplicates grouped**: a representative plus a count, span and member
  refs. Measured on a real run, 500 identical registry events collapsed to one
  entry — a naive top-N would have spent the budget on twenty copies of one fact.
* **Analyst picks come first**, ahead of anything the ranking chose.

A low rank is not a verdict. `events_found`, `events_selected`,
`events_represented` and `events_omitted` travel with the analysis, and the
prompt says in words that omission is not exoneration.

### Token budget

`ALERT_LOG_AI_BUDGET_TOKENS`, default **6,000**. Measured over eight real C00
investigations the selection saturates at about 3,400, so the default has
headroom; at 2,000 it degrades gracefully to 11 entries covering 63 of 297
events rather than failing.

## Sanitisation

Server-side, before the request is constructed. UI redaction protects a
screenshot; the request is where the data actually leaves.

`log_secret_sanitizer` runs first over the free-text fields — passwords,
password flags, bearer tokens, JWTs, API keys, vendor keys (AWS/GitHub/Slack/
OpenAI/Google), cookies, session ids, private keys, connection strings, NTLM
hashes, payment cards (Luhn-checked), IBANs, national ids. The existing
`assistant_sanitizer_service` then tokenises hosts, accounts, IPs and SIDs.

Replacement is **consistent, not blanket**: the same secret becomes the same
`<SECRET:label:hash>` placeholder, derived from an HMAC, so the model can still
say "the same session appears in both events" without the session id ever
reaching it. Only the secret is replaced, so `net user svc-sql <SECRET:…> /add`
survives as evidence that a password was set.

Two false positives it deliberately avoids: a 16-digit process id is not a
payment card (Luhn), and a 13-digit epoch-millisecond timestamp is not a
national id.

The tests assert on the **constructed request text**, not the UI and not the
stored record.

### Log text is evidence, never instruction

The block is fenced and prefaced: anything inside that looks like a directive is
attacker-controllable content written into a log, and is itself a finding. The
injection attempt is still delivered — that someone wrote it into a log is worth
reporting.

## Real-time alerts and re-analysis

The log window is now read **before** the analyst runs, not after. Reading it
afterwards is what left every verdict written without the logs beside it.

For a live alert the elapsed half is read immediately and the prompt says its
picture is incomplete. When the follow-up brings later events, the run records
`analysis_basis`, `analysis_saw_logs` and `new_logs_since_analysis`, and the log
view shows *"N log events arrived after this analysis was written and were not
considered in its verdict."*

Re-analysis is a button, never automatic, and `POST /{run_id}/reanalyse` keeps
the previous verdict under `previous_analyses` rather than replacing it. Two
reasons, and the second settles it: a model call per completed window is a real
cost at this volume, and re-analysis rewrites the run payload — which is exactly
how a CAPE sandbox report written into an investigation's evidence was lost.

## Measured cost

Over eight real C00 investigations, estimated input tokens:

| | median | mean | max |
|---|---|---|---|
| alert body only | 792 | 805 | 1,101 |
| + selected log context | 1,251 | 2,332 | 4,546 |
| **added by log context** | **446** | **1,527** | **3,525** |

Against recorded usage — 22,982 calls, 135,315,423 input tokens, $55.77 over 14
days, at $0.20/Mtok in and $1.20/Mtok out — the mean call carries 5,888 input
tokens and costs $0.001177 in input. Adding a mean 1,527 tokens of log context
raises that to about **$0.001482 per call, +26% on input cost** and roughly
**+$0.0003 per investigation**. At the current ~549 runs/day that is on the
order of **$5/month**. Output is unchanged.

The token figures are estimates at 4 chars/token; the recorded totals are the
ground truth to correct them against as real runs accumulate.
