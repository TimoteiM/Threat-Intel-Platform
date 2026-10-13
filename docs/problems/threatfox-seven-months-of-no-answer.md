# ThreatFox answered nothing for seven months, and the code reported "no hits"

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

## What this audit does not establish

The sample is the first 60 distinct domains in alphabetical order, not a
random draw, and 1,827 distinct domains were checked against the broken feed
across 2,224 investigations concluded benign or suspicious. A full audit is a
loop over those 1,827 at roughly one request a second — about half an hour of
wall clock and well inside abuse.ch's limits. It was not run here. Anyone
wanting certainty rather than a sample should run it; the script is
`tf_audit.py` in the session scratch, and the only change needed is dropping
the `limit`.

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
