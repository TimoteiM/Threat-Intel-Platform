# A domain-level feed must not sit in a clean-precondition

Design conclusion, 2026-10-13. This is the most useful thing the ThreatFox
audit produced — more useful than the damage figure, and it will apply again
the next time someone proposes wiring a domain feed into a benign test.

## The shape

`decision_engine` reaches a benign verdict through:

    observable_clean = (... and not tf_matches and not intel_hits ...)
    elif observable_clean:
        classification, confidence, risk_score, action = "benign", "high", 15, "monitor"

An enrichment result is being used as a **precondition for cleanliness**:
absent evidence permits a benign conclusion. That is a legitimate pattern —
but only for a signal whose absence actually means something about the
observable.

## Why a domain feed fails that test

ThreatFox search is substring-based and the feed catalogues *payload
locations*. Re-querying all 1,829 domains the feed had silently failed on:

    domains in ThreatFox        : 45
    apex domains of shared providers : 44

| asked about | returned |
|---|---|
| `discord.com` | `https://discord.com/api/webhooks/<id>/<token>` ×10 |
| `cloudflare.com` | `ranked-accordingly-ab-hired.trycloudflare.com` ×20 |
| `grupobiopar.com.br` | `grupobiopar.com.br` |

The first is a webhook *on* Discord. The second is not even under
`cloudflare.com` — `trycloudflare.com` merely contains the string. Only the
third says anything about the domain investigated.

So at domain granularity the signal is close to noise, and noise in a
precondition is worse than noise anywhere else: **it does not add false
positives, it removes true negatives.** Restoring the credential with
substring matching intact would have stopped the benign branch firing for
every case touching Microsoft, Cloudflare, Discord or GitHub infrastructure —
most cases. Seven months of under-escalation would have become drowning on
the first day.

## The rule

**Before putting a feed in a clean-precondition, ask what its absence means
for a shared provider.** If the feed answers "is anything bad hosted here",
absence is about the provider's whole tenancy and says nothing about the
observable. Only a feed answering "is *this thing* bad" belongs there.

Granularity is the fix, not a provider allowlist. `threatfox_match_scope`
counts a hit only when the IOC's host **is** the observable and the IOC is
host-shaped — read from the data, so it needs no hand-curated list of
offenders, which would not generalise and whose fifth instance looks
different anyway.

Two related tests already in the codebase, neither sufficient alone:

- `hosting_platform_service.is_platform_apex` asks whether a name is a public
  suffix. True for `github.io` and `eu.org`; **false** for `discord.com`,
  `cloudflare.com`, `live.com` — registrable domains that are shared
  providers all the same. Narrower, and complementary.
- The Google Safe Browsing handling nearby gets this right already and is
  worth copying: it tracks `checked` separately from `listed`, so "asked and
  not listed" is a real negative and "never asked" is not. A feed with no
  such flag cannot distinguish them, which is exactly how ThreatFox reported
  seven months of silence as cleanliness.

## The failure direction, which decides the fallback

When the observable is unknown, **keep every match**. Not knowing what hits
are about is not knowing they are irrelevant, and in a clean-precondition the
two have opposite consequences: dropping unscopable matches unlocks the
benign branch, keeping them only blocks it.

The first version of the scope filter returned nothing for an unknown
observable, and the existing decision-engine suite caught it — a fixture with
no `domain` key lost its match and a malicious verdict became suspicious. The
absence-as-value bug, committed inside the fix for a different one.
