"""
Reading OpenCTI's `hygiene` label for what it means.

OpenCTI's Hygiene connector checks every observable against the MISP warning
lists — public DNS resolvers, top-visited domains, CDN ranges, well-known
hashes — and labels a match `hygiene`. The label exists to say "this appears in
threat data, and it is infrastructure everyone uses". It is a false-positive
marker.

The platform was reading the score beside it instead, where >= 70 meant high
severity and a risk signal of 65-90. So OpenCTI saying "ignore this" was the
single highest-severity finding on the alert, and it decided the verdict:

    8.8.8.8                        score 90  high   Google DNS
    example.com                    score 80  high   IANA reserved
    www.google.com/bot.html        score 80  high   Googlebot's own page
    da39a3ee5e6b4b0d3255bfef95…    score 80  high   SHA-1 of an empty file

A tempting refinement is "hygiene only counts when no threat labels accompany
it". That gets it exactly backwards. Threat labels next to a hygiene label are
the normal case for this kind of indicator — 8.8.8.8 carried `apt27`,
`darkcomet` and `njrat`, because malware really does resolve against Google DNS.
Overriding those labels is the connector's whole purpose, so the presence of the
label is decided on its own.

This does not make an indicator benign. It removes OpenCTI's vote. VirusTotal,
AbuseIPDB and the sandbox still score it on their own evidence — which is what
should decide a public resolver, not its appearance in someone's feed.
"""

from __future__ import annotations

from typing import Any

# `hygiene` is the observable's own match; `hygiene_parent` is set when the
# parent domain matched instead. Both mean warning-list infrastructure.
HYGIENE_LABELS = frozenset({"hygiene", "hygiene_parent"})


def is_hygiene_match(opencti: Any) -> bool:
    """True when OpenCTI flagged this observable as warning-list infrastructure."""
    if not isinstance(opencti, dict):
        return False
    labels = opencti.get("labels")
    if not isinstance(labels, (list, tuple)):
        return False
    return any(str(label).strip().lower() in HYGIENE_LABELS for label in labels)


def hygiene_note(opencti: Any) -> str:
    """The sentence to show instead of a threat summary."""
    score = int((opencti or {}).get("score") or 0)
    return (
        f"Known observable (score {score}) — OpenCTI labels this as hygiene: it matched a "
        "known-good warning list (public resolvers, top sites, common infrastructure), "
        "so its presence in threat data is not evidence against it."
    )
