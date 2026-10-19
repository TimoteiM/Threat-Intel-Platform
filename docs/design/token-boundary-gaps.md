# Token boundary: risk register

**For a reviewer.** Every identifier class that can reach a model through
`app/services/token_boundary.py`, with a disposition for each. Measured on
2026-10-19; nothing here is estimated.

Three dispositions, and they are the point of the document:

| | meaning |
|---|---|
| **Closing before lab testing** | work that is understood and will be done. Nothing is in this column today. |
| **Accepted** | left open on purpose, with the reason. These are what a reviewer argues with. |
| **Needs a decision** | cannot be settled by engineering alone. |

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

### Two measurements worth keeping

**IPv6 was nearly dismissed on a bad number.** A shape-matching regex said
**89.5%** of 4,000 alert bodies contained IPv6. Validating the candidates with
`ipaddress` said **1.2%** — the difference was timestamps, which look exactly
like three-group IPv6 runs. The 1.2% is 47 bodies carrying **162 global
addresses**, which are routable and identifying, so it was closed. Had the
estates been v4-only it would have stayed open with that as the reason, rather
than shipping a pattern nothing exercises.

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
| 6 | **The map is the reverse index** | — | `investigation_token_maps` holds the real values; reversibility requires it. Mitigated by the tenant scope and the TTL, **not eliminated**. Anyone with read access to that table has every identifier in it. |
| 7 | **Fingerprint collision** | — | 12 hex characters = 48 bits. The bound is the **birthday** bound, because a collision makes the cross-tenant check pass: 50% at ~20 million scopes. It was 6 characters until 2026-10-19, where the same bound was **~4,800 scopes** — about a month of investigations. A collision still requires the token index to exist in the other map, but that is a second lock, not the argument. |
| 8 | **A caller's own traceback** | `b.tokenize("host EXPDC002")` | A traceback renders each frame's source line, so a literal written at the call site is leaked by the caller's code. The boundary cannot reach into its caller. It holds values only in locals, which Python does not render. **Callers pass values by variable.** |
| 9 | **`restore()` is forgiving** | `[HOST_9]` in a report | Unlike `detokenize_query`, it leaves an unknown token standing rather than raising, because a narrative with a stray token is a visible defect while a refused report is no report. A query has the opposite trade and refuses. |
| 10 | **Detector exclusions** | file names, field names, code identifiers, SIEM field paths | `_is_redactable_host` rejects these deliberately — added after a .NET crash report had 35 stack-trace namespaces tokenised as hostnames. Each exclusion is a place a real host shaped like one of those passes. |
| 11 | **The alert pipeline is unchanged** | — | These closures are in the boundary. `AssistantService`'s own path still uses the detectors as they were, so the single-label and `DOMAIN\user` gaps remain **in the shipped alert analysis**. Deliberate: widening detection there changes what every existing report says, which is a separate change with its own evidence. |

## Decisions, not gaps

| class | decision |
|---|---|
| **Case variants of one host** | `EXPDC002` and `expdc002` get two tokens. Not normalised, and this is a decision rather than an omission: normalising the key means choosing which casing is substituted back into a query, and that is wrong for any case-sensitive backend. The cost is that a model may see two machines and run two queries; the cost of the alternative is a query that silently matches nothing. |

## Needs a decision from you

| # | question | why it is not mine |
|---|---|---|
| A | **Should an asset inventory force-tokenise generic-looking names?** The deny-list covers universal built-ins. A host genuinely named `BACKUP` or `PRINT` is tokenised today — correctly — but a host named `REPORT` or `MONITOR` is too, and so is any ordinary word in a host position. An inventory used *only* to force-tokenise (never as the gate) would catch names the deny-list cannot reason about. It needs someone who knows whether that inventory is trustworthy. |
| B | **Is the TTL right at 6 hours?** It bounds how long real identifiers sit in `investigation_token_maps`. Shorter is safer and risks a long investigation losing its map mid-flight; the agent loop's real duration is unmeasured because the loop does not exist yet. |
| C | **Who may read the token map?** No access control beyond ordinary database access exists today. It is the one table whose rows are, by construction, the identifiers everything else is protecting. |

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
