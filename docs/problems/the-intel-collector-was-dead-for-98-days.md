# The intel collector was dead for 98 days, and the instrument said "0%"

Found 2026-10-13, while checking `intel_blocklists` — the half of the
answer-rate finding that had not been chased.

## What the instrument said, and why it was the wrong conclusion

`source_answer_rate_service` reported `intel_blocklists` answering **0% of
2,286** rows and named it alongside ThreatFox as a source that had stopped
delivering. The number was correct. The conclusion drawn from it was not.

The check counts a row as an *observation* when its JSONB path is non-null.
`IntelEvidence.blocklist_hits` is a Pydantic field defaulting to `[]`, so the
key is present whenever an `IntelEvidence` was serialised — **including on the
failure path, where nothing ran.**

What had actually happened:

| | |
|---|---|
| `meta.status = "failed"` | 2,198 consecutive runs |
| first | 2026-07-07 |
| last | 2026-10-13 (today) |
| last `completed` run | 2026-05-04 |
| distinct causes | one |
| `meta.error` | `RuntimeError: Spamhaus SIA login failed: HTTP 401` |

Not a source that stopped answering. A collector that stopped running, on
every single run, for 98 days.

`meta.status` recorded this on all 2,198 rows and nothing read it. That is the
same shape as `feeds_skipped` carrying `threatfox (error: HTTPError)` for
seven months — the truth written down beside the value, and no consumer. One
layer out this time, and inside the instrument built to tell absence from
zero.

## The cause: one unguarded line

```python
# ── 4. Spamhaus Intelligence API ──
spamhaus_token = self._get_spamhaus_sia_token(settings)   # raises
```

Steps 1–3 of `_collect` had already queried crt.sh, both DNS blocklists and
URLhaus. Step 4's token call sat outside any `try`, so a `RuntimeError` from a
**fourth source's credential** propagated out of `_collect` and discarded the
other three with it. The Spamhaus SIA step landed 2026-05-12; the collector
has never once completed since.

Cost of the blast radius: certificate transparency, subdomain enumeration and
four blocklists, lost to one 401.

## Four more defects behind it, each independently sufficient

Measured before writing anything, which is the only reason the second of them
did not ship inside the fix.

1. **URLhaus had never once answered, in 400 days.** `POST /v1/host/` with no
   `Auth-Key` returns **HTTP 401**; with one, HTTP 200. The body was
   `if resp.status_code != 200: return []` — a 401 read as "this host is in no
   blocklist". Third abuse.ch caller with the same defect, after
   `ip_lookup_service` and `threat_feeds_collector`.

2. **SURBL's refusal code would have become a hit on every domain.**
   `127.0.0.254` is SURBL for "query refused"; the error table covered only
   Spamhaus's `127.255.255.*` family. While the collector was crashing this
   was unreachable. Fixing only the crash would have marked the entire estate
   as listed — a mass false positive created by the fix for a mass false
   negative, which is the third time in two days the bug has been inside the
   fix.

3. **`socket.gaierror` meant two different things and was read as one.** The
   comment said `NXDOMAIN = not listed (good)`, and the same exception covers
   SERVFAIL, timeouts and a dead resolver. Only `EAI_NONAME` is an answer.

4. **The cache path discarded the cached URLhaus hits.**
   `evidence.blocklist_hits = blocklist_hits` *replaced* the list the cached
   hits had just been appended to, so on the cache path — the common path — a
   host URLhaus had flagged came back with nothing.

## Damage bound, from this collector's own consumers

Not transferred from ThreatFox. `intel.blocklist_hits` is read at 14 sites;
by direction:

* **dangerous** (an empty list unlocks a benign branch) — two:
  `observable_clean` and `anyrun_label_contradicted`, both in `decision_engine`;
* **missed escalation** (an empty list fails to raise) — the rest:
  `worth_escalating`, `sig_blocklisted`, the findings builder, the 60-point
  body-investigation signal, four corroboration limbs.

Verdicts reached with the collector dead:

| | |
|---|---|
| benign, domain/url | **583** across **374** distinct domains |
| suspicious | 1,366 |
| malicious | 23 |
| inconclusive | 2 |

### What the re-query found

URLhaus answers now, so the question could be put. All 259 distinct hosts
behind those 583 benign verdicts, asked 2026-10-13:

| | |
|---|---|
| listed | **4** |
| not listed | 255 |
| refused / unrecognised | 0 |

And all four are shared platforms: `github.com` (9,654 URLs),
`raw.githubusercontent.com` (22,665), `discord.com` (4), `www.google.com` (4).
**Not one carried a listing for the path this platform had investigated.**

So URLhaus's 400 days of silence cost zero wrong verdicts — and restoring it
at host granularity would have escalated every GitHub, Discord and Google
observable in the estate, which is most of them. Exactly the ThreatFox
conclusion, reached independently on a different feed: see
`threatfox-seven-months-of-no-answer.md`.

The DNSBL half **cannot** be re-queried. Both zones rate-limit this
deployment's resolver, and the measurement that shows it is that each zone
refused its own permanently-listed test point while answering ordinary names
in the same minute. Listings are being lost; the number lost is not knowable
from here. That is now recorded per query in `sources_skipped` rather than
silently becoming a clean result.

## What changed

* the SIA token call is guarded — a fourth source's credential cannot discard
  the other three;
* `IntelEvidence` carries `sources_checked` and `sources_skipped`, so an empty
  `blocklist_hits` says *which* of the four answered. It was eight different
  claims expressed as one value;
* `observable_clean` requires `intel_checked`, the same correction as the
  threatfox limb — and unlike that one, the flag had to be built, not merely
  consumed;
* URLhaus sends the `Auth-Key`, makes no request without one, treats a non-200
  as an absence and an unrecognised `query_status` as `unrecognised_absence`;
* URLhaus hits are scoped to the observable's **path**, and its host-level
  `url_count` is recorded as context under `malware_hosted_on_host`, deciding
  nothing;
* SURBL's refusal family is recognised; `EAI_NONAME` is separated from every
  other `gaierror`; the cache path extends instead of assigning;
* `source_answer_rate_service` consults each source's collector `meta.status`
  first and reports `never_asked` separately from `never_answered`. A rate
  over runs that never happened is not a rate.

## What did not change, and is a decision rather than an oversight

Two pre-existing properties of the verdict ladder, now pinned by
`xfail(strict=True)` tests in `test_intel_clean_requires_checked.py` so they
cannot drift unnoticed:

1. **The precondition closes the high-confidence benign branch, not benign.**
   Measured after the fix, on a payload clean on every other axis:

   | state | verdict |
   |---|---|
   | everything asked, nothing listed | benign, high, 15, monitor |
   | intel collector dead | benign, **medium**, 15, monitor |
   | threatfox never answered | benign, **medium**, 15, monitor |
   | both dead | benign, **medium**, 15, monitor |

   The ladder's final `else` is `benign, medium, 15, monitor`, reached
   whenever nothing escalated and consulting no feed at all; its only guard is
   `reputation_available`, which any non-empty `feeds_checked` satisfies. Risk
   score and recommended action do not move. Where a payload also carries a
   weak-signal score of 3 or more, closing the branch *does* reach
   suspicious — so the consequence is "benign/high becomes benign/medium, or
   suspicious if anything else was already pushing".

2. **One listing in a reputable blocklist is not an escalation.** Escalation
   needs `len(intel_hits) >= 2`, so a single Spamhaus DBL listing yields
   benign/medium/monitor. The threshold also counts **list entries rather than
   sources**: one URLhaus listing used to produce up to eleven entries while
   one DNSBL listing produces one, so the unit was never a count of anything.
   Changing it is a detection-policy decision, not a correctness fix.

## The rule

**An absence convention protects only the layers that consult it.** `absence.py`
has existed for weeks, and the three places that most needed it — the
enrichment payload, the clean precondition, and the answer-rate instrument —
each expressed "nobody asked" as an empty collection. The convention cannot
reach a field that does not call it, and a check that reads the payload will
never see the collector's own status.

**And an aggregate over a merged list cannot name what broke.** `blocklist_hits`
is four sources in one array. The aggregate said "0% of 2,286" and the grain
that mattered was per source and per run status: two sources rate-limited, one
never authenticated, one never configured, and a collector that raised before
any of them could be read.
