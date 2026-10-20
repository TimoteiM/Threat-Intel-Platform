# Token boundary: risk register

**For a reviewer.** Every identifier class that can reach a model through
`app/services/token_boundary.py`, with a disposition for each. Measured on
2026-10-19; nothing here is estimated.

Three dispositions, and they are the point of the document:

| | meaning |
|---|---|
| **Closing before lab testing** | work that is understood and will be done. Nothing is in this column today. |
| **Accepted** | left open on purpose, with the reason. These are what a reviewer argues with. |
| **Needs a decision** | cannot be settled by engineering alone. All three were decided on 2026-10-19; the decisions and what was built for each are at the end. |

The *Accepted* rows that are testable are pinned by
`test_the_known_gaps_are_still_these`, which asserts they are **still open**.
Closing one fails that test, which is how this document is prevented from
quietly becoming a lie.

---

## Closed on 2026-10-19

Listed because a reviewer should see what moved, and because each was a real
leak rather than a theoretical one.

| class | example | how |
|---|---|---|
| **Single-label hostname, keyed** | `computer="FILESERVER"`, `MAILGW`, `EXCHANGE` | A **deny-list**, not an allow-list. Everything in a host or account position is tokenised except a short list of built-ins. An allow-list from an asset inventory would make coverage depend on the inventory being complete, and the machine nobody registered is the one worth tokenising. |
| **Bare `DOMAIN\user` in prose** | `User INT\jdoe ran it` | A pattern requiring the candidate not be preceded by a backslash, which is what separates it from a UNC share and from `C:\Users\jdoe`. |
| **UNC server name** | `\\EXPFS01\finance\q3.xlsx` | The server is tokenised; the share and file are left, because they are not identifiers and removing them costs the reader what happened. |
| **IPv6** | `fe80::…`, `2a00:1450:…` | Candidates are validated with `ipaddress`, not matched by shape. |
| **Account as a command-line switch** | `powershell … -User jdoe` | Found by re-measuring the corpus *after* the other closures. The separator is a space, so no `key=value` pattern reached it. |
| **Secrets outside the default field list** | `vendor_detail="password=…"` | The boundary walks every string instead of taking `log_secret_sanitizer`'s field list, with one shared placeholder map. |
| **Record fields whose key gives the value meaning** | `{"agent": {"name": "EXPREU002"}}` | `DECLARED_FIELDS` for our own normalised shape, synthesising the context the existing detector needs. |
| **The map was readable in the database** | `token_map` JSONB | Sealed with `app.security.secret_box` — MultiFernet under `INTEGRATION_ENCRYPTION_KEY`, which lives in the environment and not in the database. See *Encryption at rest* below: this was asked as a question and turned out to be small. |

### Two measurements worth keeping

**IPv6 was nearly dismissed on a bad number.** A shape-matching regex said
**89.5%** of 4,000 alert bodies contained IPv6. Validating the candidates with
`ipaddress` said **1.2%** — the difference was timestamps, which look exactly
like three-group IPv6 runs. The 1.2% is 47 bodies carrying **162 global
addresses**, which are routable and identifying, so it was closed. Had the
estates been v4-only it would have stayed open with that as the reason, rather
than shipping a pattern nothing exercises.

**A bare `SecretBox()` is never configured.** `_seal` called it and the
constructor takes its keys as an argument, defaulting to none — so sealing
raised `TokenBoundaryError` on *every* call and no boundary could be opened at
all. Both halves were correct; the call between them was not, and only a test
that patched *settings* and let the real `from_settings()` run caught it
(`test_sealing_goes_through_the_deployment_s_configured_key`). The defect was
inside the fix it belongs to, which is now the sixth time.

**The deny-list had to run before the detectors, not after.** The existing
account pattern stops at a space, so `user="NT AUTHORITY\SYSTEM"` was already
two fragments — `NT` tokenised, `AUTHORITY\SYSTEM` left — before any later
pass could consult a list, and neither fragment is a built-in. Built-ins are
now protected with a NUL-delimited sentinel before the pipeline runs and
restored after.

---

## Accepted, with reasons

| # | class | example | why it is accepted |
|---|---|---|---|
| 1 | **Bare hostname with no key** | `EXPREU002 reported` | A single-label token with nothing saying it is a host is indistinguishable from an ordinary word. Tokenising it means tokenising nouns. The **keyed** form is closed, and in the measured corpus hostnames arrive keyed or in `agent.name`. |
| 2 | **MAC addresses** | `00:1A:2B:3C:4D:5E` | Identifying and persistent across re-imaging, but absent from the alert bodies measured. Cheap to add if a reviewer disagrees — one pattern, same validation shape as IPv6. |
| 3 | **Identifiers inside encoded payloads** | `powershell -enc <base64>` | One opaque string. Decoding it means running an attacker-controlled decoder over untrusted input to find identifiers, which trades a disclosure risk for an execution one. |
| 4 | **Semantic identification** | "the domain controller in the Bucharest office" | A model can describe a host from tokenised input without naming it. No tokeniser addresses this; the prompt and the reviewer do. |
| 5 | **Identifiers with no class** | ticket ids, asset tags, serial numbers, licence keys, phone numbers, personal names as free text | The boundary covers host, account, email, IP and SID. Everything else has no class and no pattern, and inventing classes without measuring their prevalence is how a pattern nobody exercises gets shipped. |
| 6 | **The map is the reverse index** | — | `investigation_token_maps` holds the real values; reversibility requires it. Narrowed since 2026-10-19 — the rows are ciphertext, so database read access alone no longer yields identifiers — but **not eliminated**, and the reason is worth stating precisely rather than comfortably. Reading an identifier now takes both the table and `INTEGRATION_ENCRYPTION_KEY`. The role split separates the table from the rest of the platform — `tip_app` has no privilege on it — but it does **not** separate the two secrets from each other: `tip_sanitizer`'s credentials and the encryption key are in the same `.env`, read by the same container. So anyone who can execute code in the api or worker container still has both. What the split buys is that a SQL defect in any other query, and a database read on its own, no longer do. |
| 12 | ~~**Role separation is not enforceable in this cluster**~~ | — | **CLOSED the same day, 2026-10-19.** It read as accepted for about an hour. `tip_sanitizer` is now the only role with any privilege on `investigation_token_maps`; `tip_app` — what the API, worker and beat connect as — has none, cannot do DDL, and cannot call `pg_read_file`. `threatintel` is kept for migrations alone. `scripts/check_db_privileges.sql` asserts the matrix by introspection and `scripts/liveness.sh` runs it, because the test suite cannot see a grant: run against a database it could not reach at all, the unit suite produced ONE extra failure out of 3,281 tests. Backlog 40 has the detail. |
| 13 | ~~**The completion purge has no caller**~~ | — | **CLOSED 2026-10-20.** The gathering loop owns the investigation lifecycle and calls `purge_investigation` when it finishes, so the 24-hour ceiling is a backstop again rather than the only thing that deletes a map — and its warning means what it says: a map that reaches the ceiling is one an investigation failed to purge. The test that pinned the absence now asserts the opposite, which is what it said it would do. A purge failure is logged and does not fail the investigation; the ceiling catches it. |
| 7 | **Fingerprint collision** | — | 12 hex characters = 48 bits. The bound is the **birthday** bound, because a collision makes the cross-tenant check pass: 50% at ~20 million scopes. It was 6 characters until 2026-10-19, where the same bound was **~4,800 scopes** — about a month of investigations. A collision still requires the token index to exist in the other map, but that is a second lock, not the argument. |
| 8 | **A caller's own traceback** | `b.tokenize("host EXPDC002")` | A traceback renders each frame's source line, so a literal written at the call site is leaked by the caller's code. The boundary cannot reach into its caller. It holds values only in locals, which Python does not render. **Callers pass values by variable.** |
| 9 | **`restore()` is forgiving** | `[HOST_9]` in a report | Unlike `detokenize_query`, it leaves an unknown token standing rather than raising, because a narrative with a stray token is a visible defect while a refused report is no report. A query has the opposite trade and refuses. |
| 10 | **Detector exclusions** | file names, field names, code identifiers, SIEM field paths | `_is_redactable_host` rejects these deliberately — added after a .NET crash report had 35 stack-trace namespaces tokenised as hostnames. Each exclusion is a place a real host shaped like one of those passes. |
| 11 | **Two sanitisers, and the closures are in only one of them** | — | Its own section below. It is the largest accepted gap in this document and was previously a closing note, which understated it. |

## Row 11 in full: two sanitisers, and which one got the closures

There are two model-facing sanitisation paths in this platform, and **every
closure listed above is in one of them.**

> **Narrowed 2026-10-20, for one path, and widened in the same measurement.**
> The SIEM log digest — `alert_log_prompt.build`, the block analysts' pinned
> events are sent in — now tokenises with the boundary before the layer below
> sees it, so none of the six apply to it. But measuring that also found the
> row had been **understating** the shipped path, because the row's table was
> measured on raw log text and this digest is JSON. See
> "The log digest" below. The row stands for everything else.

| | the boundary | the shipped alert pipeline |
|---|---|---|
| module | `app/services/token_boundary.py` | `AssistantService` → `assistant_sanitizer_service` |
| used by | the query agent, and the SIEM log digest since 2026-10-20 | **every real alert analysed today** |
| single-label keyed host (`computer="FILESERVER"`) | tokenised | **left in the clear** |
| bare `DOMAIN\user` in prose | tokenised | **left in the clear** |
| UNC server name (`\\EXPFS01\…`) | tokenised | **left in the clear** |
| IPv6 | tokenised | **left in the clear** |
| account as a command-line switch (`-User jdoe`) | tokenised | **left in the clear** |
| secrets outside the default field list | tokenised | **left in the clear** |
| keyed multi-label host, keyed account, email, IPv4, SID | tokenised | tokenised |
| token scope (tenant + investigation) | in the token | none — `[HOST_1]` is unscoped |
| unknown token on the way back | refusal | left standing |

So the honest summary is: **the closures protect the query agent, which no
customer traffic reaches yet, and the SIEM log digest, which is off by
default — while the alert body and the findings digest, which every real
alert goes through this afternoon, still have all six gaps.** A reviewer
should read the "Closed" table above with that in mind.

(Until 2026-10-20 this paragraph said the closures protected "a consumer that
does not exist yet" and that the shipped path "still has all six gaps", full
stop. The first clause is now wrong for one block and the second needs the
qualifier above. Corrected rather than appended to, because the sentence was
quotable and would have been quoted.)

Why it is deliberate rather than an oversight: widening detection in the
shipped path changes the text of every report the platform has produced, and
the detector exclusions in row 10 were themselves added in response to a real
over-tokenisation incident (35 stack-trace namespaces read as hostnames).
Moving them needs its own measurement against the corpus and its own
before/after on existing reports. That is a change, not a tidy-up.

Why it is nonetheless the largest gap: a deliberate divergence that nothing
measures is a divergence that widens silently. Two tests hold it still:

* `test_the_shipped_alert_pipeline_still_has_the_gaps_the_boundary_closed`
  asserts the shipped path **still leaks** each of the six, and names this
  document when it fails. If someone closes one there, the test fails and
  this table must be corrected — the failure is the notification.
* `test_the_two_paths_agree_on_what_they_both_cover` asserts the divergence
  is **additive**: everything the shipped path tokenises, the boundary
  tokenises too. A boundary that quietly stopped covering something would
  otherwise hide inside the difference.

### The log digest: the row was measured on the wrong shape

The table above is measured on **raw log text**. The SIEM log digest is
**JSON lines** — one `json.dumps` per event — so `user="jdoe"` reaches the
shipped detectors as `user=\"jdoe\"`, with a backslash between the key's
separator and the value. The shipped account pattern does not expect it and
does not match. Only the **context-free** classes — a dotted FQDN, an IPv4,
an email, a SID — need no key beside them, so only those were ever caught in
this block. The boundary's separator admits the escaped form.

That makes the row's `keyed account | tokenised` cell **false for this path**,
and it was never a cell about a shape. Measured against the text
`sanitize_entries` actually produces, with one sentinel per class:

| class | before 2026-10-20 | after |
|---|---|---|
| keyed single-label host (gap 1) | leaked | tokenised |
| bare `DOMAIN\user` (gap 2) | leaked | tokenised |
| UNC server name (gap 3) | leaked | tokenised |
| IPv6 (gap 4) | leaked | tokenised |
| account as a command-line switch (gap 5) | leaked | tokenised |
| secret in a field off the old list (gap 6) | leaked | redacted |
| **keyed account inside JSON** (not in the six) | **leaked** | tokenised |
| keyed multi-label host, IPv4, email, SID | tokenised | tokenised |

Gap 6 is reachable here only because an analyst can add any document field as
a column and have it projected into `extra`; a credential in a field nobody
projects never reaches the digest at all. `tokenize_records` walks every
string, so the field list is gone rather than longer.

Token scope narrows too: this path's tokens are `[HOST_<fingerprint>_1]`,
scoped to a tenant and a run, where the shipped path mints an unscoped
`[HOST_1]`. The inbound row does **not** narrow — the digest path restores
with `restore()`, which leaves an unknown token standing on purpose.

Held by `test_no_identifier_sentinel_reaches_the_outgoing_payload` and
`test_the_boundary_and_not_the_layer_below_is_what_removes_them` in
`tests/unit/test_services/test_alert_log_ai_context.py`. The second exists
because the first would pass for the wrong reason if the boundary call were
removed and the layer below happened to improve.

**What this says about reading this register:** a row that names a detector
is a claim about a pattern, and a pattern only acts on text in a particular
shape. The first version of this investigation read `build`'s return value,
found hostnames in it, and concluded that nothing sanitised identifiers on
this path — wrong, because a layer below was doing part of the job. The
second read the outgoing payload and got the answer. Measure where the data
leaves, not at the nearest convenient surface.

### The separator, measured on ingest — and what the alert body still leaks

Asked whether alert bodies reach the shipped detectors already escaped, the
way the digest does. **They do not**: zero escaped quotes from either the
SentinelOne or the Exabeam workflow. `_flatten` stringifies with
`str(value)`, and `_clean_message` actively un-escapes a JSON-quoted message.

But the same family of fault is there under a different separator. Ingest
flattening emits `key: value` with a **colon**, and the shipped account
detector misses that too:

| text as the detector sees it | shipped | boundary |
|---|---|---|
| `user="sentuseralpha"` | tokenised | tokenised |
| `user: sentuseralpha` | **CLEAR** | tokenised |
| `user=sentuseralpha` | tokenised | tokenised |
| `user=\"sentuseralpha\"` | **CLEAR** | tokenised |

So `keyed account | tokenised` in the row-11 table holds for exactly one of
the three shapes this platform produces. The consequence is visible per
shipper: a **SentinelOne** alert leaks the account, because a structured post
is flattened to a colon; the **same alert from Exabeam** does not, because it
arrives as raw log lines carrying `user="…"`. The shipper's format decides.

**And the alert body leaks every class the digest now protects.** Measured at
the wire — `(system, user_text)` as `_call_with_fallback` receives it — all
six gap classes and the keyed-account class reach the model in the clear from
the alert text, while the digest half tokenises all seven at the boundary.
The 2026-10-20 change is **one field short**: it closed the half that is off
by default and left the half that runs on every alert.

Full tables, probe point and method:
`docs/measurements/outgoing-payload-identifier-states.md`, re-runnable with
`scripts/measure_outgoing_payload.py`.

### Not an identifier, found while measuring: `--token=VALUE`

`log_secret_sanitizer` recognises `password=`, `-Password`, `api_key=` and
`Authorization: Bearer`, and does **not** recognise `--token=VALUE`. That is
a pattern gap in the secret sanitiser rather than an identifier gap, it
affects **both** paths equally, and nothing here changes it — the boundary
runs the same secret patterns. Recorded so it is not re-found as new.

## Decisions, not gaps

| class | decision |
|---|---|
| **Case variants of one host** | `EXPDC002` and `expdc002` get two tokens. Not normalised, and this is a decision rather than an omission: normalising the key means choosing which casing is substituted back into a query, and that is wrong for any case-sensitive backend. The cost is that a model may see two machines and run two queries; the cost of the alternative is a query that silently matches nothing. |

## Decided on 2026-10-19

The three rows that needed a decision, with the decision and what was built.
Nothing is left in "needs a decision".

### A. No asset inventory

**Decided: no.** Everything in a host position is already tokenised, so an
inventory buys no additional safety — it would only confirm, for names it
happens to contain, what the deny-list already does for all of them. What it
*adds* is a staleness dependency: coverage would start depending on the
inventory being current, and the machine nobody registered is the one worth
tokenising.

**Revisit only if** lab testing shows over-tokenisation measurably degrades
analysis quality — i.e. the model loses the thread because too many ordinary
words became tokens. That is a measurement on output quality, not a security
argument, and it has not been made.

### B. Lifetime: purge on completion, 24-hour ceiling as the backstop

**Decided.** The six-hour TTL is gone. It was a number chosen for an agent
loop that does not exist yet, so it could not have been measured.

* The lifetime is **until the investigation completes** —
  `purge_investigation(reason="completed")`.
* **24 hours wall-clock** is a backstop for the abandoned and the crashed, not
  the lifetime — `purge_expired(reason="ceiling")`, swept hourly by
  `token_map_purge_task`.
* Every purge **records which of the two fired**. A single `deleted: int`
  would make routine housekeeping and a leak indicator the same number.
* A ceiling purge that deleted anything is surfaced as a **WARNING** naming
  the scopes, because it means one of exactly two things: the ceiling is too
  short for a real investigation, or investigations are finishing without
  purging. Both want a person.

The real duration gets measured in lab, and the ceiling is a candidate to
change once there is a distribution to change it against.

**The caveat that matters:** nothing calls the completion purge yet — row 13.
So in deployment today every map will reach the ceiling and warn, and the
warning will be correct.

### C. Access to the map, and encryption at rest

Two halves, with different answers.

**Encryption at rest: asked as a question, and it was small, so it is done.**
`app/security/secret_box.py` already seals integration credentials —
MultiFernet, a `key_id` per row, rotation that re-encrypts without the
plaintext passing through twice, under `INTEGRATION_ENCRYPTION_KEY`, which
lives in the environment and not in the database. The map was already read and
written whole and never queried by key, so losing SQL visibility into it costs
nothing. Migration `071` adds `token_map_ciphertext` / `token_map_key_id` and
drops the JSONB column. No new primitive, no new key, no new dependency — that
is what made it small rather than a project. Existing rows are deleted rather
than migrated: they are plaintext under a column that is about to stop
existing, and sealing them would mean reading every identifier back out first.

If no key is configured, sealing **refuses**. The only other honest option is
storing the reverse index for every identifier in the investigation in
readable form, and an outage and a breach must not share a code path.

**Role separation: done, after being written up as impossible.** The first
version of this document said it could not be done here, and the measurement
behind that was right — the app connected as `threatintel`, superuser and
owner and the only non-system role in the cluster, so there was no second role
to revoke from. What was wrong was treating "no second role exists" as a
property of the cluster rather than as the work. The roles now exist:

| connection | role | may |
|---|---|---|
| `DATABASE_URL` / `DATABASE_SYNC_URL` | `tip_app` | DML on the application tables. No DDL. **Nothing** on `investigation_token_maps`. |
| `DATABASE_SANITIZER_URL` | `tip_sanitizer` | DML on `investigation_token_maps` **and nothing else in the database**. |
| `DATABASE_MIGRATION_URL` | `threatintel` | everything; Alembic only, never a serving process. |

Verified against the running platform rather than argued: as `tip_app`,
`SELECT` on the token map, `CREATE TABLE` and `pg_read_file` are all
`InsufficientPrivilege`; as `tip_sanitizer`, every other table is too. The
matrix is asserted by `scripts/check_db_privileges.sql`, which
`scripts/liveness.sh` runs — not by a test, because the suite cannot see a
grant at all. Backlog 40 carries the three consequences of the old
arrangement, including that a SQL injection on that connection used to be a
host takeover rather than a data read.

The clause that *is* enforced today is the other one: no API or report path
can reach the table. `InvestigationTokenMap` is referenced from exactly three
modules — the boundary, the model, and the ceiling sweep — and
`test_no_api_or_report_path_can_reach_the_token_map_table` fails if a fourth
appears.

---

## What the boundary does and does not promise

**It is a reduction, not a guarantee.** It removes the classes it knows about
from model-facing text and refuses to resolve anything it did not issue. It
does not promise that no identifier reaches a model, and the tests do not
assert that — `test_no_covered_identifier_survives_the_corpus` asserts that
*covered* classes do not survive, with a companion assertion that the pass was
earned rather than produced by tokenising nothing.

**The strongest property is the return path.** An invented token, an unscoped
token, a token from another scope and a secret placeholder are each a refusal,
and detokenisation is all-or-nothing: a query is fully resolved or it does not
run. That is what prevents a confident answer about the wrong estate, and it
is enforced by the token grammar rather than by a convention a caller has to
remember.
