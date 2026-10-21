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

**The bound is closed.** The first pass excluded twelve bodies ≥100k chars
carrying 30% of the corpus's characters, because `sanitize_entries` is
superlinear (0.94 M chars/s under 10k, 0.05 M chars/s on a 1.22M body).
The full scan then ran: **17,562 of 17,562 runs, 104.0M characters, 2,379
seconds.** Both the bounded and the full numbers are below, because the
difference between them is the most useful thing in this file.

### What closing it changed: occurrences are not the metric

| | bounded (17,550 runs) | full (17,562 runs) |
|---|---|---|
| identifiers per alert, mean | 4.41 | **4.42** |
| runs leaking at least one | 66.2% | **66.2%** |
| gap 1 **occurrences** | 10,174 | **120,174** |
| gap 1 **distinct entities** | 75 | **76** |
| gap 2 distinct | 1,320 | 1,353 |

Twelve bodies added **110,000 gap-1 occurrences and one distinct host.** One
multi-megabyte alert repeats the same hostname tens of thousands of times.

So **every per-alert and per-entity figure is stable to three significant
figures, and the occurrence counts are not a measurement of anything** — they
are a measurement of how often a handful of enormous bodies repeat
themselves. Rank by *runs affected* and *distinct entities*; ignore the
occurrence column except as a cost signal. The conclusions below were drawn
from runs-affected and did not move.

Figures in the tables are from the **full** scan unless marked.

## By class

All 17,562 runs, 104.0M characters, ordered by **runs affected** — see above
for why not by occurrences:

Ordered by **runs affected**, with the corrected built-in guard:

| class | % runs | distinct entities | occurrences |
|---|---|---|---|
| **colon-keyed account** | **59.4%** | **332** | 30,535 |
| gap 3 UNC server name | **50.1%** | **744** | 79,027 |
| gap 2 bare `DOMAIN\user` | **44.6%** | **1,326** | 25,716 |
| gap 1 keyed single-label host | **23.3%** | **75** | 10,190 |
| gap 4 IPv6 | 2.0% | 203 | 1,478 |
| other keyed account | 0.8% | 29 | 322 |
| gap 5 `-User` switch | 0.0% | 0 | 0 |

**1,326 distinct accounts and 744 distinct hostnames** have been named to the
provider in the clear. That is the figure with a person attached to it.

The built-in correction moved gap 2 from 60.0% of runs to 44.6% while barely
touching its distinct count (1,320 to 1,326) — `AUTHORITY\SYSTEM` appeared
in thousands of runs and contributed one value. **The colon gap is now the
most common class**, which strengthens rather than weakens the conclusion
below.

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
`sanitize_entries` is identifier-only. So the alert body's secrets were not
redacted at all. (Closed by change 2 of b-2, 2026-10-21.)

### The quotable number is 6,023, not 23,293

The raw detector total over the full corpus is 23,293 occurrences across
21.6% of alerts. **Validated 2026-10-21, and 74% of that total is false
positives from two shape-only patterns.** Re-run with
`scripts/validate_secret_labels.py`.

| label | occurrences | runs | % runs | detector kind |
|---|---|---|---|---|
| iban | 13,778 | 2,587 | 14.7% | **shape-only — 0 valid** |
| session | 5,137 | 2,585 | 14.7% | key-anchored |
| card | 4,515 | 1,209 | 6.9% | **shape-only — ~0 valid** |
| cookie | 434 | 434 | 2.5% | key-anchored |
| password_flag | 322 | 88 | 0.5% | key-anchored |
| password | 126 | 89 | 0.5% | key-anchored |
| bearer | 3 | 3 | 0.0% | key-anchored |
| connection_string | 1 | 1 | 0.0% | key-anchored |

**Credible: 6,023 occurrences across 3,179 runs — 18.1% of alerts**, every
one from a pattern that requires a key beside the value.
**Unvalidated: 18,293 occurrences across 20.1% of alerts**, from the two
patterns that match on digit shape alone.

#### IBAN: 0 of 13,778

ISO 13616 gives IBAN a mod-97 checksum and a per-country length. **The
detector pattern checks neither** — it is `[A-Z]{2}\d{2}` followed by
alphanumeric groups, which is also a GUID fragment, a base32 token and any
number of vendor identifiers. Against the real standard:

| outcome | count |
|---|---|
| country code does not issue IBANs at all | 13,417 |
| wrong length for its country | 324 |
| mod-97 fails | 37 |
| **valid IBAN** | **0** |

Not "mostly false positives" — **all of them**, on 359 distinct candidate
strings.

#### Card: no evidence of payment data

Every hit already passes Luhn, because `_is_real_secret` applies it. Luhn
alone is weak: a random 16-digit string passes about 1 in 10. Adding the
registered issuer prefix and the length that brand uses:

| outcome | occurrences |
|---|---|
| no registered issuer prefix | 4,413 |
| visa / mastercard / diners / discover prefix | 102 |

Of those 102 (32 distinct strings), **86 contain a run of 6 or more
identical digits**, leaving **16 occurrences with no obvious tell**. The
context key immediately before the match is `(no key)` on 99, `hll_key` on 2
— a HyperLogLog key — and `id` on 1. None is a payment-shaped field.

So: **no evidence that payment card data reaches the provider.** Sixteen
unexplained occurrences out of 23,293, under no payment-shaped key, is
consistent with coincidence at this corpus size. The pattern is almost
certainly matching 13-digit epoch-millisecond timestamps and similar
identifiers.

#### What to say, and what not to

* **Say:** "6,023 credential occurrences reach the model across 18.1% of
  alerts, and 5,137 of them are session identifiers."
* **Do not say:** 23,293, or anything about IBANs or card numbers.

`session` at 14.7% of alerts is the real finding in this section and it was
buried under the false positives.

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

**And it is content-dependent, not size-dependent** (measured 2026-10-21):
one 2,244,098-char body costs 86.1s while a 2,329,280-char body costs 7.5s,
an 11× difference at the same size. Not proportional to tokens minted
either — 6 against 31. See backlog 43; the open question is which input
shape triggers it.
