# How many identifiers reach the model today, per alert

Measured 2026-10-20 over every alert-body run in the database. Re-run with
`scripts/measure_corpus_identifier_leak.py`.

## The number that sizes the work

**4.41 identifiers per alert reach the model**, as distinct entities, averaged
over all 17,550 runs. Median 4, p95 13, max 69. **66.2% of alerts leak at
least one**; over the leaking runs alone the mean is 6.67 and the median 6.

Set that beside what the shipped sanitiser does catch: **3.39 tokens minted
per run**. So on this corpus the sanitiser removes fewer identifiers than it
leaves — roughly 43% of the entities present. That is the single sentence for
a reviewer.

## Method, and why it measures what reaches the model rather than what could

Each stored `alert_body` is run through the **real shipped sanitiser**, and
then the **boundary's own extra detectors are applied to that output**.
Whatever those patterns find in the sanitised text is, by construction, what
survived to the model. That makes the delta a measurement rather than a diff
of two tokenisations.

Guards are the boundary's real ones — `is_builtin_principal` and a token
check — so `SYSTEM`, `localhost` and an already-tokenised value are not
counted. Without them the deny-list would be reported as a finding.

An instrument control runs first: a synthetic body containing all six classes
must register in all six, and the secret probe must register. A corpus of
zeros is otherwise indistinguishable from a broken detector, and a zero here
would read as good news.

**Stated bound.** `sanitize_entries` is superlinear — 0.94 M chars/s on
bodies under 10k, 0.05 M chars/s on a 1.22M body, ~19× worse per character.
Twelve bodies are ≥100k chars and carry **30% of the corpus's characters**;
they are excluded from the table below and measured separately. See
"Superlinear sanitisation" at the end — that behaviour is itself a finding,
because those bodies go to the model in production too.

## By class

Over 17,550 runs, 72.9M characters:

| class | occurrences | runs | % runs | distinct entities |
|---|---|---|---|---|
| gap 3 UNC server name | 78,510 | 8,795 | 50.1% | **734** |
| gap 2 bare `DOMAIN\user` | 34,956 | 10,530 | 60.0% | **1,320** |
| colon-keyed account | 30,389 | 10,405 | 59.3% | **325** |
| gap 1 keyed single-label host | 10,174 | 4,096 | 23.3% | **75** |
| gap 4 IPv6 | 1,468 | 342 | 1.9% | 199 |
| other keyed account | 312 | 146 | 0.8% | 29 |
| gap 5 `-User` switch | 0 | 0 | 0.0% | 0 |

**1,320 distinct accounts and 734 distinct hostnames** have been named to the
provider in the clear. That is the figure with a person attached to it.

**The prediction was the wrong way round.** Gap 1 was expected to be more
common than the colon gap. Measured, the colon gap affects 59.3% of runs
against gap 1's 23.3%, and both are behind bare `DOMAIN\user` at 60.0% and
UNC at 50.1%. Gap 1 is also the smallest by distinct entities — 75 — so even
closing it perfectly would name 75 fewer machines.

Two scope notes on gap 1, both of which make 23.3% a **floor**:

* it is counted with `KEYED_HOST_LAX_RE`, which requires a key beside the
  value. A bare single-label hostname with no key is register row 1 — a
  deliberate non-closure, because tokenising it means tokenising nouns — and
  is not counted here and could not be;
* `-User` switch values are zero in this corpus. The pattern was added from a
  measured leak in log text, not alert bodies. It costs nothing to keep and
  buys nothing here.

## Secrets: nothing strips them from an alert body

`log_secret_sanitizer` is applied to log *records* in the digest.
`sanitize_entries` is identifier-only. So the alert body's secrets are not
redacted at all.

**13,443 occurrences across 3,792 runs — 21.6% of alerts.**

| label | occurrences |
|---|---|
| iban | 5,154 |
| session | 5,137 |
| card | 2,274 |
| cookie | 434 |
| password_flag | 314 |
| password | 126 |
| bearer | 3 |
| connection_string | 1 |

**Treat `iban` and `card` as unverified.** These are detector counts, not
confirmed financial data, and a long alphanumeric identifier in a SOC alert
is exactly the shape that trips an IBAN pattern. The `card` detector applies
a Luhn check, which makes 2,274 harder to dismiss; `iban` at 5,154 in a SOC
corpus is more likely enriched with false positives. **Validating these two
labels against a sample is the first thing to do with this table** — not
because the fix differs, but because "card numbers are going to the provider"
is a sentence that must be true before anyone says it.

`password`, `password_flag`, `bearer` and `connection_string` total 444
occurrences and need no such caveat.

## By shipper, and by tenant

Occurrences per run, not distinct-per-alert — a different and larger metric
than the 4.41 headline.

| shipper (`alert_source`) | runs | leaked occurrences | per run |
|---|---|---|---|
| Siembiot | 16,476 | 132,516 | 8.04 |
| unknown | 1,068 | 23,253 | **21.77** |
| wm-c00.siembiot.int | 5 | 40 | 8.00 |
| probe | 1 | 0 | 0.00 |

| tenant (`tenant_id`) | runs | leaked occurrences | per run |
|---|---|---|---|
| c00 | 16,481 | 132,549 | 8.04 |
| (unassigned) | 1,033 | 22,619 | **21.90** |
| pov | 20 | 269 | 13.45 |
| lin | 15 | 371 | 24.73 |
| boc | 1 | 1 | 1.00 |

**"Per shipper" barely divides this corpus.** One shipper is 93.8% of it, and
one tenant is 93.8% of it. **Neither SentinelOne nor Exabeam has ever
delivered an alert here** — they exist as channel names in ingested data and
as frontend mock data, and nothing else. So the SentinelOne/Exabeam shape
comparison in
[outgoing-payload-identifier-states.md](outgoing-payload-identifier-states.md)
is a statement about the *code paths* those workflows would take, built from
synthetic payloads, and not an observation of their traffic. The same
one-tenant caveat that applies to every isolation claim on this platform
applies here.

`alert_client` is **not** used to group anything: it is self-declared and
17,540 of 17,562 runs say `unknown`.

The unassigned runs leak 2.7× as much per run as c00's. They are the 1,045
legacy runs with no tenant — worth noting, not worth acting on separately.

## The colon gap, by field name

Field *names* only; a key is a diagnostic, a value is not mine to print.

| field name | occurrences |
|---|---|
| `User` / `user` | 10,327 |
| `SourceUser` / `sourceUser` | 8,346 |
| `TargetUser` / `targetUser` | 8,346 |
| `ParentUser` / `parentUser` | 1,371 |
| `targetUserName` | 560 |
| `subjectUserName` | 555 |
| `Account` / `Account:` | 497 |
| `accountName":"` | 82 |
| `user:"` | 77 |
| `processUser":"` | 35 |
| `agentLastLoggedInUserName":"` | 21 |

These are Sysmon and EDR field names, arriving through our own ingest
flattening as `key: value`.

Note the last four. `accountName":"` and `processUser":"` show that some
alert bodies carry **embedded JSON with real quotes** — `"key":"value"` —
which is a third separator shape, and the shipped account detector misses it
too. It is not the escaped `\"` form measured as absent earlier; that
measurement stands. Real-quoted JSON inside a body is simply a shape nobody
had enumerated.

## Superlinear sanitisation, found while measuring

`sanitize_entries` on one 1,224,087-char body: **25.71 seconds**, against
0.58s for 544,145 characters spread over 120 small bodies. Per character
that is ~19× worse, and it is the shipped sanitiser, on the path that runs.

Ten bodies in the corpus exceed 1M characters and average 3.08M.
`MAX_ANALYSED_ALERT_BODY_CHARS` is 10,000,000, so they are not truncated to
anything smaller before analysis, and the Celery task has a 1,800s hard
limit. Extrapolating quadratically from one data point is not a measurement,
so the honest statement is narrower: **one 1.2M body costs 26 seconds of
sanitisation, and there are ten bodies between 2.5× and 9× that size.**
Whether any of them has ever timed out is a question for the run records, not
for this file.

The individual regexes are all fast on the same body (0.02–0.19s), so the
cost is inside `sanitize_entries`, not in the boundary's added patterns.
