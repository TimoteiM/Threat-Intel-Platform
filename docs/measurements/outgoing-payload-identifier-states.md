# The whole outgoing payload: which identifiers reach the model, and from where

Measured 2026-10-20. Re-run with `scripts/measure_outgoing_payload.py`.

## The headline

**The alert body leaks every class the log digest now protects.** All six
register-row-11 gap classes, plus the keyed-account class the register did not
have, reach the model **in the clear from the alert text**, on both ingest
shapes. The digest half protects all seven.

So the 2026-10-20 boundary change is **one field short**. It closed the half
that is off by default and left the half that runs on every alert. That is not
a reason to undo it — the digest is the half an analyst explicitly sends, and
it was the half with no identifier handling at all — but nobody should read
"the log digest goes through the boundary" as "identifiers do not reach the
model".

## Where the probe is taken

`(system, user_text)` as handed to `AssistantService._call_with_fallback`.
That is the wire. Three earlier surfaces each give a different and wrong
answer:

| surface | why it is not the payload |
|---|---|
| `alert_log_prompt.build`'s return | the shipped detectors have not run yet |
| `sanitize_entries(...).sanitized_text` | `_build_user_payload` wraps it in another `json.dumps`, and the prompt builder also receives `raw_entries` and the token map |
| the stored `AssistantEntry.raw_text` | that is the pre-sanitisation text, by design |

Every transform in the chain is the real function: `normalize_alert_payload`,
`_build_log_digest`, `_analyse`'s join (captured by intercepting
`_run_assistant`, so it is the genuine assembly and not a restatement of it),
`strip_resolved_identifiers`, `sanitize_entries`,
`build_alert_analysis_prompt`. The database round trip is not executed; it
stores `raw_text` in a column and reads it back unchanged.

Probes test each sentinel in **every encoding it could arrive in** — plain,
`json.dumps`-escaped, and backslash-doubled — because the wire is
double-encoded and a plain-form-only probe reports a leak as clean.

## The three states

* `BOUNDARY` — `[HOST_<12hex>_n]`, scoped to a tenant and a run.
* `SHIPPED` — `[HOST_n]`, unscoped, from `assistant_sanitizer_service`.
* `CLEAR` — verbatim on the wire.

### SentinelOne workflow — structured JSON to `POST /api/alert-investigations`

Alert body 746 chars, digest 3,060, wire 20,626. Nine scoped tokens on the
wire and four unscoped.

| class | alert half | digest half |
|---|---|---|
| gap 1 keyed single-label host | **CLEAR** | BOUNDARY |
| gap 2 bare `DOMAIN\user` | **CLEAR** | BOUNDARY |
| gap 3 UNC server name | **CLEAR** | BOUNDARY |
| gap 4 IPv6 | **CLEAR** | BOUNDARY |
| gap 5 `-User` switch | **CLEAR** | BOUNDARY |
| gap 6 secret off the old field list | **CLEAR** | BOUNDARY |
| keyed account (not in the six) | **CLEAR** | BOUNDARY |
| keyed multi-label host | SHIPPED | BOUNDARY |
| public IPv4 | SHIPPED | BOUNDARY |
| email | SHIPPED | BOUNDARY |

### Exabeam workflow — flattened lines to `POST /api/alert-investigations/raw`

Alert body 325 chars, digest 3,060, wire 20,216. Nine scoped, five unscoped.

Identical, with **one** difference: keyed account is `SHIPPED`, not `CLEAR`.

## Why the two shapes disagree, and the answer on escaping

The alert body is **not** escaped when the shipped detectors see it. Measured:
**zero** escaped quotes from either workflow. `_flatten` stringifies values
with `str(value)`, and `_clean_message` actively *un*-escapes a JSON-quoted
message. So the JSON mechanism found in the digest does **not** apply on
ingest, and row 11's inbound measurement was not taken on the wrong shape in
that respect.

A sibling defect of the same family is real there, though, and it is what
makes the two workflows differ. Ingest flattening emits `key: value` — a
**colon** separator:

```
agentDetectionInfo.agentComputerName: SENTFILESERVER
sourceProcessInfo.user: sentuseralpha
```

| text as the detector sees it | shipped | boundary |
|---|---|---|
| `user="sentuseralpha"` | tokenised | tokenised |
| `user: sentuseralpha` | **CLEAR** | tokenised |
| `user=sentuseralpha` | tokenised | tokenised |
| `user=\"sentuseralpha\"` | **CLEAR** | tokenised |
| `hostname="SENTFILESERVER"` | **CLEAR** | tokenised |
| `hostname: SENTFILESERVER` | **CLEAR** | tokenised |
| `hostname=\"SENTFILESERVER\"` | **CLEAR** | tokenised |

So the shipped account detector fails on **two** shapes: `key: value`, which
is what our own ingest produces from any structured post, and
`key=\"value\"`, which is what `json.dumps` produces in the digest. It
matches `key="value"` and `key=value`. The boundary matches all seven.

That is why a SentinelOne post leaks the account and an Exabeam post does
not: SentinelOne arrives structured and is flattened to a colon, Exabeam
arrives as raw log lines that already carry `user="…"`. **The same alert, the
same account, two different outcomes decided by the shipper's format.**

The host rows are `CLEAR` in every separator because that sentinel is
single-label — gap 1, which is about the value, not the separator. The
multi-label host tokenises, consistent with register row 1.

## What this does not say

* It does not say how often these shapes occur in the real corpus. Every
  value here is a synthetic sentinel. Counting `key: value` lines carrying an
  account against real alerts is the next measurement, and it bounds how much
  the colon gap is worth.
* It does not say the alert-body leak is new. It is the state the platform
  has always been in; this is the first measurement that reads it at the wire
  and attributes each class to a half.
* It does not propose widening the shipped detectors here. That changes the
  text of every report the platform has produced, which needs its own
  before/after — the reason row 11 gives for the divergence being deliberate,
  and the detector exclusions in row 10 exist because a widening went wrong
  before (35 stack-trace namespaces read as hostnames).
