"""Which ThreatFox hits are evidence *about this observable*.

ThreatFox search is substring-based, so asking it about a domain returns
every IOC whose value contains that string. For a shared provider that is
almost entirely other people's payloads:

    discord.com      -> https://discord.com/api/webhooks/<id>/<token>  x10
    cloudflare.com   -> ranked-accordingly-ab-hired.trycloudflare.com  x20
    grupobiopar.com.br -> grupobiopar.com.br

The first is a specific webhook *on* Discord. The second is not even under
`cloudflare.com` — `trycloudflare.com` merely contains the string. Only the
third says anything about the domain that was investigated.

Why this matters more than the credential
-----------------------------------------
44 of the 45 ThreatFox-positive domains in the 2026-10-13 audit were apex
domains of shared providers, and `decision_engine` consumes the result as:

    observable_clean = (... and not tf_matches and not intel_hits ...)
    elif observable_clean: -> benign, high, 15, monitor

A boolean "ThreatFox knows about this string" against an apex is close to
noise, and it sits in a *precondition for benign*. Restoring the credential
with substring matching intact would stop that branch firing for every case
touching Microsoft, Cloudflare or Discord infrastructure — which is most
cases. The pipeline would go from under-escalating for seven months to
drowning the day the key landed.

So the raw matches stay in the evidence, because "malware is hosted here" is
real context an analyst may want, and the *decision* uses only the matches
that are about the observable itself. Recording what the feed said and
deciding what it means are two statements, and this codebase does not
collapse them.

Deliberately not a list of known shared providers. A hand-curated blocklist
of the specific offenders does not generalise, and the fifth instance looks
different — the discriminator is in the data, so it is read from the data.
"""

from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlparse


def _host_of(value: str) -> str:
    """The host an IOC refers to, whether it is a bare domain or a URL."""
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    # ThreatFox writes `ip:port` for network IOCs.
    if raw.count(":") == 1 and not raw.startswith("["):
        raw = raw.split(":", 1)[0]
    return raw.rstrip(".")


def is_about(observable: str, match: Any) -> bool:
    """Whether this hit is evidence about `observable` itself.

    True only when the IOC's host **is** the observable. A URL hosted on it is
    not: `https://discord.com/api/webhooks/...` says a webhook is malicious,
    not that Discord is. A sibling or unrelated domain that merely contains
    the string is not either.
    """
    target = _host_of(observable)
    if not target:
        return False
    ioc_value = match.get("ioc_value") if isinstance(match, dict) else getattr(match, "ioc_value", "")
    ioc_type = match.get("ioc_type") if isinstance(match, dict) else getattr(match, "ioc_type", "")
    host = _host_of(ioc_value)
    if host != target:
        return False
    # The host matches. A `url` IOC still describes a path on that host
    # rather than the host, so it only counts when the observable was itself
    # that URL — which `_host_of` cannot tell us, so require a host-shaped
    # IOC type.
    return str(ioc_type or "").strip().lower() in {"domain", "ip:port", "ip", ""}


def about_observable(observable: str, matches: Iterable[Any]) -> list[Any]:
    """The subset of `matches` that is evidence about `observable` itself.

    **When the observable is unknown, every match is kept.** Not knowing what
    the hits are about is not the same as knowing they are irrelevant, and
    the two must not produce the same answer — which is the absence-as-value
    bug, here in the code written to fix a different one.

    The direction matters because of where this is consumed. `tf_matches`
    feeds `and not tf_matches`, a precondition for a benign verdict: dropping
    unscopable matches would unlock that branch, while keeping them only
    blocks it. An existing test caught this — a fixture with no `domain` key
    had its ThreatFox match silently discarded and a malicious verdict
    became suspicious.
    """
    matches = list(matches or [])
    if not _host_of(observable):
        return matches
    return [m for m in matches if is_about(observable, m)]
