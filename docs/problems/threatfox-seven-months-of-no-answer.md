# ThreatFox answered nothing for seven months, and the code reported "no hits"

> **Measured value, so nobody spends an afternoon on this again.** Over
> seven months of total silence ThreatFox would have changed **zero**
> verdicts: 25 of 25 knowable positives were already caught as
> malicious/high by other sources, and the one non-redundant case
> postdates its own verdict. Chasing it found the dead intel collector,
> OTX at 70% failure and the VirusTotal load collapse — which *do*
> matter. The feed itself earns almost nothing at host granularity here.

Audit, 2026-10-13. Prompted by a 401 in the worker log a day after the feed
was declared fixed.

## What happened

`threat_feeds_collector._query_threatfox` sent `headers={"API-KEY": ""}` —
wrong header name, empty value — so abuse.ch refused every request. It then
did this:

    if data.get("query_status") != "ok":
        return []

An empty list, which downstream means **"this domain is not in ThreatFox"**.
So a feed that was never once asked reported, on every investigation, that it
had looked and found nothing.

The same two defects were fixed in `ip_lookup_service` on 2026-10-12. This
call site was missed, and the fix was reported as complete.

## The population

    evidence rows carrying a threat_feeds block : 2,400
      with a non-empty threatfox_matches        : 0
      with an empty threatfox_matches           : 2,400
    period                                      : 2026-03-02 .. 2026-10-13
    distinct domains checked against it         : 1,827

Zero non-empty results in seven months is the signature of a feed that never
answered, not of an estate with no ThreatFox hits.

## Did it cost anything?

**How the value is used matters.** Every consumer reads `threatfox_matches`
in a *positive* condition:

    if vt_malicious >= 5 or abuse_score >= 80 or tf_matches:
        classification = "malicious"

An empty list never produces a benign verdict; it fails to produce a
malicious one. So the risk is **missed escalation**, not false exculpation —
a weaker claim than it first appears, and the right one.

**Sampled re-query, now that the key works.** 60 distinct domains, 59 queried
successfully (one is not a valid search term):

| domain | ThreatFox holds | verdict it received |
|---|---|---|
| adserverworkshub.com | ClearFake | malicious / block |
| ajnfqs.com | IClickFix, ClearFake | malicious / block |
| arrowwoodmemoir.org | SmartApeSG | malicious / block |
| amazonaws.com | IClickFix, php.shin_webshell | benign ×2, suspicious ×1 |

**4 of 59 (6.8%) were in ThreatFox.** Three were already classified malicious
and blocked on other evidence — the feed would have added corroboration, not
changed an outcome. The fourth is `amazonaws.com`, where ThreatFox is holding
*hosted content* on a shared provider domain; escalating the apex domain on
that basis would have been wrong, so the benign verdict stands on its merits.

**On this sample, no disposition was wrongly benign because of the missing
feed.**

## Correction: the bound above was wrong, and so was the one before it

**The "missed escalation, not false exculpation" bound does not hold.** It
was reached by reading three call sites that use `tf_matches` inside an `OR`,
and never searching for the others. `decision_engine` has two more:

    observable_clean = (... and not tf_matches and not intel_hits and ...)
    anyrun_label_contradicted = (... and not tf_matches and not intel_hits ...)

    elif observable_clean:
        classification, confidence, risk_score, action = "benign", "high", 15, "monitor"

An empty `tf_matches` is a **precondition for a benign verdict**, not merely
a failure to escalate. With both feeds silently empty, `not tf_matches` and
`not intel_hits` were permanently true for seven months, so that branch was
reachable on evidence two working feeds could have blocked. The second
expression downgrades a malicious sandbox verdict to suspicious on the same
basis.

**206 investigations since 2026-04-01 carry the `observable_clean` signature**
(benign / high / 15 / monitor), out of 2,365.

This is the scope error for the third time in a day, in the analysis that was
specifically about scope — a completeness claim ("no consumer treats absence
as exculpatory") made from a search that was never run.

## The full pass

All 1,829 distinct domains re-queried. **45 are in ThreatFox**, 7 errored:

    investigations on those 45 domains : 83
      malicious                        : 31
      benign                           : 34
      suspicious                       : 16

**Almost every benign verdict is correct.** The domains are shared platforms —
`live.com`, `discord.com`, `cloudflare.com`, `sharepoint.com`, `github.io`,
`githubusercontent.com`, `amazonaws.com`, `zoom.us`, `linkedin.com`,
`telegram.org`, `eu.org`, `b-cdn.net`, `comcast.net`, `telenet.be`,
`iana.org`. ThreatFox lists them because malware is *hosted* on them; the
apex domain is not malicious and a hit there would have been a false
positive. A working feed would have made those verdicts worse, not better.

**One domain is not shared infrastructure and warrants a human look:**

| domain | ThreatFox holds | verdict | date |
|---|---|---|---|
| `grupobiopar.com.br` | IClickFix | benign / medium / risk 19 / monitor | 2026-08-24 |

That is the whole list. Against 2,224 investigations concluded benign or
suspicious over seven months with two feeds silent, one case where a working
ThreatFox would plausibly have changed the answer.

`corp.com` (ClearFake, Cobalt Strike, Remcos, Remus — benign/high) and
`tenderly.co` (Unknown malware — already suspicious) are judgement calls for
the same reviewer, but both are widely-used infrastructure.

## The instrument error inside the audit

The first run of that audit reported **0 hits**. The harness built the
collector with `__new__`, skipping `__init__`, so `_artifacts` was unset and
the code path that runs *after a hit* raised `AttributeError` — counted as a
query error. A harness that turns a hit into an error cannot report hits, and
it produced the most dangerous possible answer: an all-clear.

Fourth instance this week of a check that could not return the bad answer,
and the one with the worst failure direction. The fix was to construct the
object properly rather than to read the error message, which named the
missing attribute and not the lost result.

---

## The invariant, which matters more than the bug

**Any enrichment source returning 100% empty over a meaningful window is
broken, whatever it claims about itself.** Zero non-empty results in 2,400
rows over seven months is not a quiet estate; it is a signature, and nothing
was watching for it.

That generalises past ThreatFox, so it is now a check —
`source_answer_rate_service`, run by `python -m app.cli.source_answers`. It is
the companion to the watch heartbeat: that answers *did the task run*, this
answers *did the source answer*. A collector can run on schedule, succeed, and
record nothing from a provider that refused every request.

### It found a second one on its first run

    source                 answered       of   rate
    threatfox                     0     2174     0.0%   NEVER ANSWERED
    abuseipdb                  1961     2174    90.2%
    phishtank                  2168     2174    99.7%
    virustotal                 2203     2203   100.0%
    urlscan                    2168     2168   100.0%
    intel_blocklists              0     2168     0.0%   NEVER ANSWERED

`intel_blocklists` is not a feed that is merely quiet. It worked and stopped:

    2026-03    107 rows    23 with a blocklist hit   (21.5%)
    2026-04     87 rows     0
    2026-05      1 row      0
    2026-07     81 rows     0
    2026-08    426 rows     0
    2026-09   1398 rows     0
    2026-10    293 rows     0

23 hits in March, then **0 across 2,286 rows over seven months** — the same
window as ThreatFox. The worker log names a likely cause, 15 times in 24
hours: `Collector [intel] failed: Spamhaus SIA login failed: HTTP 401`.
Another credential, another feed reporting an empty list rather than a
failure. Not investigated further here; it is a finding, not a fix.

### Design notes

The rate carries its denominator, always: "0%" and "0 of 2,174" are different
claims when the denominator might be 3. Below 50 observations it reports
`too_little_history` rather than 0%, which is why `subdomains` shows an
absence instead of a damning zero.

It reports and does not alarm. A source legitimately at 0% over a short window
is ordinary — most domains are in no blocklist — so the threshold for anything
short of total silence has to come from a week of this check's own output,
under the same shadow-first rule as the emitter freshness work.

**It is a CLI, not an endpoint.** It takes about 98 seconds: a 90-day
aggregate extracting nested paths from large JSONB documents. Collapsing seven
queries into one changed the runtime by nothing, because the cost is per-row
extraction rather than per-scan — a hypothesis worth recording as refuted. The
right home is a scheduled task storing its result, exactly as `watch_heartbeat`
does. Not built.


---

## Addendum, 2026-10-13: the listing dates, and a claim corrected

The audit above concluded that no verdict rested on ThreatFox's silence.
That was true and it was true for a reason the audit had not established.
Without comparing each listing's `first_seen` against our own verdict date,
"no wrong verdicts" cannot distinguish **we did not miss it** from **it was
not knowable then** — and those are different claims about the audit, not
about the domains.

So the comparison was run over the whole silent period: every observable that
reached a verdict on a row whose `feeds_skipped` carries
`threatfox (error: HTTPError)` — 1,824 observables across 517 distinct hosts
— each asked again today and each match scoped with `about_observable`.

| | |
|---|---|
| scoped ThreatFox hits | **26** |
| listing **predates** our first verdict (knowable at the time) | **25** |
| listing postdates our last verdict (not knowable then) | 1 |
| listing between first and last verdict | 0 |
| listing undated | 0 |
| hosts refused as `illegal_search_term` | 7 |

So the answer is the opposite of the comfortable one: **25 of 26 were
knowable when we judged them.** ThreatFox had the listing, sometimes for
months — `dntds.shop` since 2026-04-03 against a 2026-07-24 verdict,
`purerawk.com` since 2026-06-03 against 2026-08-24 — and we never asked.

And every one of those 25 was classified **malicious at high confidence
anyway**. Not one benign, not one suspicious. Something else caught all 25:
ClearFake, SmartApeSG, FAKEUPDATES and Nanocore infrastructure that
VirusTotal, urlscan or the HTTP signals reached independently.

The single exception that postdates its verdict is `grupobiopar.com.br`,
listed 2026-09-23 against a 2026-08-24 benign verdict — see
`docs/outbound/grupobiopar-now-listed.md`.

### What this changes

* the conclusion stands, and now rests on evidence: ThreatFox's silence
  changed **zero** verdicts, because on all 25 knowable cases other sources
  independently reached malicious/high — not because the listings came too
  late;
* it is also a measurement of ThreatFox's **marginal** value on this estate:
  25 of 25 knowable positives were redundant. That is worth weighing before
  anything is built that treats it as decisive;
* and it narrows the earlier "45 positives, 44 shared-provider apexes" figure,
  which was counted **before** scoping. Scoped to the observable, over the
  population that actually lost the feed, the number is 26.

### A side finding

7 of 517 "hosts" were rejected by ThreatFox as `illegal_search_term`:
`02.id`, `b.bo`, `e.ga`, `n.net`, `nc.de`. These are not domains. They are
extraction artefacts of the delimiter-boundary family, and the platform
opened investigations on them. `illegal_search_term` is correctly recorded as
`unrecognised_absence` today, since it is not in the measured refusal set —
but it is now measured, and it means something specific: the question was
malformed, not refused.
