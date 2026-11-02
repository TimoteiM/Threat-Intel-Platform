# Per-verdict source coverage

Built 2026-10-13, because every failure found that day was already written
down and nothing read it. `meta.status` is on every collector's output on
every row; `feeds_checked`/`feeds_skipped` on every threat-feeds row;
`sources_checked`/`sources_skipped` on every intel row. Four separate
multi-month outages hid behind that, and an analyst holding a case had no way
to see any of it.

This is `checked and not listed` generalised from one precondition to the
whole verdict.

## What it answers

> "4 of 8 sources unavailable" on a verdict from 15 September.

Read from a real row, today, with no backfill:

```
http://www.delicitate.ro/tmp/phpinfo.php/js/chunk-vendor
2026-09-15 18:27   suspicious / medium

  9 of 18 sources unavailable when this verdict was reached:
  brave_osint, SURBL, Spamhaus DBL, URLhaus (abuse.ch), Spamhaus SIA,
  threatfox, otx, vt, whois

  brave_osint          HTTPError: 402 Client Error: Payment Required
  SURBL                The intel collector did not complete, so SURBL was
                       never asked
  threatfox            threatfox (error: HTTPError)
  otx                  otx (error: HTTPError)
  vt                   VirusTotal API rate limit exceeded on all keys
  whois                (collector failure)

  Not asked (outside this run's selection, so not a gap):
  asn, cape, hybrid_analysis
```

Not four of eight. **Nine of eighteen.**

## Three design decisions, each with a measurement behind it

### Read time, never stored

Derived from the stored evidence on each read, per the layer contract at the
top of the README. It therefore works for every historical verdict with no
backfill — the inputs were always there — and it cannot drift from the
evidence it describes.

### The expected set is derived from `COLLECTOR_REGISTRY`

Not a hand-kept list. `otx` was missing from `source_answer_rate_service`'s
`SOURCES` while being 70% dead, which is the check built to find dead sources
failing to cover one — the third hand-maintained list to swallow an entry on
2026-10-13, after `NOT_INSTRUMENTED` and the tolerated-failure set.

The derivation paid for itself immediately. Three sources nobody had measured:

| collector | failed | rows | rate | cause |
|---|---|---|---|---|
| intel | 2,184 | 2,184 | 100% | known — Spamhaus SIA 401 |
| **brave_osint** | **746** | 1,773 | **42.1%** | HTTP 402 Payment Required, 2026-08-20 → 09-22 |
| **whois** | **236** | 2,184 | **10.8%** | unmeasured until now |
| vt | 203 | 2,218 | 9.2% | rate limit under load |
| **opencti** | **61** | 2,190 | 2.8% | 45 are `AttributeError: 'NoneType'` — a collector defect, not an outage |

`source_answer_rate_service` now also reports `collectors_not_covered`,
derived the same way, in its own output. A test registers a fake collector
and asserts the guard notices — because a guard that passes for want of a
failure mode is decoration, and three such checks reported "fine" on
2026-10-12.

### Only failures count as gaps

The first version counted everything that was not an answer and reported
**"13 of 21 sources unavailable" on an ordinary March verdict** — a mean of
47–50% on *every* day in the window, so the two days the VirusTotal quota
blew did not stand out at all. A field that cries wolf on every case is a
field analysts learn to skip. That is the exact failure this service's own
test warns about, committed inside the fix for it — the fourth time in two
days.

So four states, and only one is a gap:

| state | meaning | counted? |
|---|---|---|
| `answered` | ran and returned | the numerator |
| `failed` | asked, did not answer | **the gap** |
| `not_attempted` | `meta.status = "skipped"`, or no block at all — not in the run's selection | reported, not counted |
| `unknown` | collector ran but recorded nothing about this sub-feed (pre-dates the flag) | reported, not counted |
| `not_applicable` | observable type outside `supported_types` | excluded entirely |

`not_attempted` and `unknown` still carry an `Absent` with a sentence,
because "nobody asked" must not read as "asked and clean" even when it is not
a fault.

With that correction the two bad days become the worst high-volume days in
the window — 33.3% and 35.2% mean unavailability against a ~30% chronic
baseline. The baseline itself is the larger finding: three of the four
failures are load-independent and had been down for months, so VirusTotal was
the *marginal* contribution on top of an evidence base that was already a
third missing.

## New exposure, and what was done about it

`meta.error` has always been stored and was never returned by an application
API before this. The standing rule applies: never return a credential through
an API response.

All **774** distinct stored error strings were scanned before shipping; none
contained a key-shaped name/value pair. That is a fact about today's corpus
and not about the next collector to put a signed URL in an exception, so the
redaction is unconditional: key-like query parameters, `api-key`/`token`/
`secret`/`authorization` assignments, and `Bearer <token>` are replaced, and
the detail is bounded at 300 characters (the longest stored error is 2,321 —
a page is not a log). Four parametrised tests assert a secret cannot reach
the payload, and a fifth asserts an ordinary message survives intact, because
a redactor that mangles everything would pass the first four and destroy the
field's only purpose.

The `Bearer` form was missed by the first regex, which required `=` or `:`
immediately after the name. The test caught it.

## What is verified, and what is not

* **verified** — the computation, against real stored rows inside the api
  container; the endpoint body and its exact payload, by calling
  `get_evidence` with a real session; the redaction, by test; TypeScript
  compiles.
* **not verified** — the HTTP route end to end, and the browser render.
  `GET /api/investigations/{id}/evidence` sits behind the default-deny
  middleware and there is no dev account, so a request returns 401. This is
  the same limit that made the case-graph work unverifiable, and "verified"
  stays narrower for anything session-bound until there is a dev account.

## The rule

**A platform that records its own failures and never reads them is
indistinguishable from one that does not record them.** Every outage found on
2026-10-13 — ThreatFox's 401, the intel collector's 2,198 consecutive
failures, OTX at 70%, VirusTotal under load, brave_osint's lapsed
subscription — was already in the evidence, on every affected row, in a field
written for exactly this purpose. The defect was never the recording. It was
that nothing consumed it, and no surface showed it to the person making the
decision.
