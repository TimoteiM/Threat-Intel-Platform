# grupobiopar.com.br — concluded benign in August, listed in ThreatFox since September

**To:** the SOC analyst on duty / whoever owns re-evaluation of concluded cases
**From:** Threat Intel Platform, measured 2026-10-13
**Ask:** look at this domain again, and tell us whether a concluded verdict
should be reopened when a feed lists the domain afterwards. The second half is
the more important question.

## The domain

| | |
|---|---|
| domain | `grupobiopar.com.br` |
| our verdict | **benign**, medium confidence, risk 19, action `monitor` |
| concluded | 2026-08-24 15:06 UTC |
| client | none recorded |
| domain age at the time | 2,769 days |
| hosting | Unified Layer |
| VirusTotal then | 1 malicious of 91 |

## What ThreatFox says now

Asked today, with a working credential:

| | |
|---|---|
| IOC | `grupobiopar.com.br` (type: `domain`) |
| threat | `payload_delivery` |
| malware | **IClickFix** |
| confidence | 50 |
| reporter | `varysz` (single reporter) |
| first seen | **2026-09-23 15:25 UTC** |
| last seen | 2026-10-06 13:49 UTC |

URLhaus has nothing for it. Of the 26 scoped ThreatFox listings across the
whole silent period, this is the **only one** whose listing postdates our
verdict: the other 25 were already listed when we judged them, and every one
of those 25 we called malicious at high confidence anyway on other evidence.
It is also the one listed domain that is not a shared-provider
apex — the other 44 were Discord, Cloudflare, Microsoft and similar, where a
listing describes somebody else's content on shared infrastructure rather
than the domain.

## What this is not

**It is not a verdict we got wrong.** The ThreatFox listing is dated
2026-09-23 — thirty days *after* we concluded. On 2026-08-24 ThreatFox had
nothing on this domain, so no working credential would have changed the
answer. We checked that before writing this, because the obvious reading of
"we said benign and a feed says malware" is that we missed it, and here that
reading is false.

Two things about that run were genuinely broken, and neither affected this
verdict:

* ThreatFox was never asked — `feeds_skipped` recorded
  `threatfox (error: HTTPError)`. It would have answered "nothing" if asked.
* the whole intel collector had failed — `meta.status = "failed"` — so SURBL,
  Spamhaus DBL, URLhaus and Spamhaus SIA were all silent. Asked today,
  URLhaus has nothing for this domain either.

Both are fixed. Neither is the reason this document exists.

## What it is

A concluded case whose subject became malicious afterwards, and nothing in
this platform noticed or ever would have. The verdict was written on
2026-08-24, the domain was listed on 2026-09-23, and the record still says
benign/monitor today.

**That is the finding, and it is structural rather than about this domain.**
A verdict is a statement about the evidence on a date. Our storage treats it
as a standing conclusion. There is no mechanism that revisits a concluded
investigation when a feed later lists its subject, so the gap is as wide as
the archive.

## One sentence for the related policy question

If the `len(intel_hits) >= 2` threshold comes to you in the same sitting:
**one decisive source cannot escalate, but two entries from the same zone
can — the threshold counts verbosity, not corroboration.** One Spamhaus DBL
listing produces one entry and does not escalate; one URLhaus listing used to
produce up to eleven and did.

## The two questions

1. **This domain.** Is `IClickFix`, confidence 50, one reporter, last seen a
   week ago, enough to act on? We are deliberately not deciding that: a
   single-reporter listing at middling confidence is exactly the case where a
   feed should inform an analyst rather than a verdict. Treat the ThreatFox
   entry as evidence requiring review, not as a finding.

2. **The policy.** Should a concluded benign verdict be reopened when a feed
   lists the domain afterwards, and if so, on what trigger — any listing, a
   confidence floor, more than one reporter? We can build the re-evaluation
   sweep; we cannot pick the threshold, and picking one here would be the
   platform quietly setting SOC policy.

## Why you are reading this instead of being paged

This platform has no outbound channel. Three documents now sit in
`docs/outbound/` with a named owner and no way to reach them — see
`technique-disagreements.md` and `silent-endpoints.md`. Someone has to carry
them by hand, which is a gap worth closing separately.
