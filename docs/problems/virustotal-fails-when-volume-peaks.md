# VirusTotal fails when volume peaks, which is when it is needed

Measured 2026-10-13, after the answer-rate check started reporting collector
status. The aggregate had buried it: the check said `virustotal` answered
**100%** of 2,203 rows, because `evidence_json->'vt'` is present and
non-empty on the failure path too — it still carries `meta`.

## The shape

201 of 2,218 runs in the 90-day window (9.1%) carry
`ValueError: VirusTotal API rate limit exceeded on all configured keys`.
Those 201 are not spread across the window:

| | |
|---|---|
| hours containing at least one run | 431 |
| hours containing at least one rate limit | **20** |
| share of active hours | 4.6% |
| share of runs | 9.1% |

Per-hour failure rate against that hour's own volume:

| runs in the hour | hours | runs | rate-limited | share |
|---|---|---|---|---|
| 1 | 144 | 144 | 1 | 0.7% |
| 2–5 | 157 | 460 | 5 | 1.1% |
| 6–20 | 120 | 1,359 | 174 | **12.8%** |
| 21–50 | 10 | 255 | 21 | 8.2% |

And 199 of the 201 fall on two consecutive days:

| date | runs | rate-limited | share |
|---|---|---|---|
| 2026-09-15 | 212 | 97 | 45.8% |
| 2026-09-16 | 266 | 102 | 38.3% |
| 2026-09-17 | 98 | 2 | 2.0% |

**Those are the two busiest days in the entire 90-day window.** The next
highest is 2026-09-03 at 95 runs — so the two days that exhausted the quota
carried 2.2× and 2.8× the volume of the third-busiest day.

Within them, whole hours are total losses rather than degraded: 21 of 21,
20 of 20, 18 of 18, 17 of 17, 17 of 17, 15 of 15, 10 of 10, 10 of 10, 9 of 9.

## Why this is not a quota problem

`vt_malicious >= 5` leads the escalation clause in `decision_engine`.
VirusTotal is the heaviest term in the ladder, and it is the term most likely
to be absent precisely when submission volume is highest.

Stated plainly: **anyone who can generate volume degrades this platform's
primary enrichment as a side effect.** That does not require intent — a bulk
batch does it — but it means the property is reachable deliberately, and the
two days that demonstrated it were ordinary operational load, not an attack.

## What it cost, and what it did not

Verdicts reached with no VirusTotal answer at all:

| classification | confidence | count |
|---|---|---|
| suspicious | medium | 195 |
| suspicious | low | 6 |
| benign | medium | 1 |
| malicious | high | 1 |

Not false-benign. `observable_clean` requires `vt_found`, which is false on a
rate limit, so those runs could not reach the high-confidence benign branch —
the one guard that worked as designed. They fell to *suspicious, investigate*
instead.

So the cost is **201 extra analyst tickets on the two busiest days of the
quarter**, which is the worst possible time to add triage load, and a
corresponding loss of any escalation that only VirusTotal would have found.

Compounding: on **201 of those 203 runs the intel collector had already been
dead for weeks**. During that burst the platform was deciding on Google Safe
Browsing, abuseipdb, phishtank and openphish alone — with threatfox 401-ing
and OTX erroring on 70% of runs. Four of its eight external sources were
unavailable at the moment of peak load, and nothing reported it.

## Status

Dormant since 2026-09-17, 26 days ago. It is load-dependent, not a dead
credential, so it will recur at the next burst of comparable size and nothing
currently in the platform would say so. The answer-rate check now carries
`collector_failed` beside each rate, which makes it visible after the fact;
there is no signal that fires during one.

## Two open decisions, neither taken here

1. **Should the rate's denominator exclude collector failures?** Today
   `virustotal` reads 100% answered with 203 collector-failed beside it. Both
   numbers are true and the headline is the misleading one.
2. **Should a run that lost VirusTotal be re-queued rather than concluded?**
   201 cases were decided on a partial evidence set and recorded as finished.
   Nothing marks them as having been judged without the heaviest source.

## The rule

**An aggregate over a window hides a failure that is concentrated in it.** 9.1%
of runs across 90 days reads as a tolerable background rate. The same failures
expressed per hour are entire hours of total loss, on the two days when the
platform was busiest. The grain that matters is the one the failure has, and
for a load-dependent failure that is never the window.
