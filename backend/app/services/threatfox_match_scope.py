"""Which feed hits are evidence *about this observable*.

Written for ThreatFox, and now used by URLhaus too, because the two share a
granularity: both are asked about a **host** and answer with **paths**. The
module keeps its name and gained a general primitive rather than acquiring a
near-copy next door — the second implementation is always the stale one, and
this codebase has paid for that with nine membership consumers, two parsers
and three ATT&CK copies.

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

import ipaddress
from typing import Any, Iterable
from urllib.parse import urlparse


def _address_of(value: str) -> ipaddress._BaseAddress | None:
    """The IP address an IOC refers to, or None if it is not one.

    An IP needs its own rule and it is **stricter** than the domain rule, not
    a special case of it. A domain has label structure to anchor equality on;
    an IP is a bare token, so `1.2.3.4` is a substring of `11.2.3.40` with
    nothing in the string itself to say they are different addresses.
    ThreatFox's `search_ioc` is a substring search and its network IOCs are
    written `ip:port`, so the only safe comparison is: parse both sides as
    addresses, strip the port, and compare the parsed values.

    Parsing is what makes substring matching **impossible** rather than
    filtered afterwards — `11.2.3.40` and `1.2.3.4` are different
    `IPv4Address` objects and no amount of string overlap can make them
    equal. A value that does not parse is not an address and gets no
    equality at all.
    """
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return None
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    if raw.startswith("["):
        # [2001:db8::1]:443
        raw = raw[1:].split("]", 1)[0]
    elif raw.count(":") == 1:
        # ThreatFox writes `ip:port` for network IOCs.
        raw = raw.split(":", 1)[0]
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


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


#: The category on a hit that describes a **host** rather than the observable
#: itself: URLhaus's `url_count` for a shared platform, which on 2026-10-13
#: was 9,654 for github.com and 22,665 for raw.githubusercontent.com. Named
#: here rather than in the collector because it is the decision layer that
#: must drop it, and the collector that must keep it in the evidence.
HOST_AGGREGATE = "malware_hosted_on_host"

#: Where an indicator sits relative to the observable.
SAME_HOST = "same_host"        # the indicator IS this host
PATH_ON_HOST = "path_on_host"  # a URL hosted on it, which is a different claim
ELSEWHERE = "elsewhere"        # a different host that merely contains the string
UNKNOWN = "unknown"            # the observable could not be read


def _path_of(value: str) -> str:
    raw = str(value or "").strip()
    if "://" not in raw:
        # A bare `host/path` form. Anything before the first slash is the host.
        return ("/" + raw.split("/", 1)[1]) if "/" in raw else ""
    parsed = urlparse(raw)
    return (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")


def scope_of(observable: str, indicator: str) -> str:
    """How `indicator` relates to `observable`. One of the four above.

    IP observables are decided by parsed-address equality before any string
    comparison happens, because an IP has no label structure to anchor on and
    a substring test on `1.2.3.4` matches `11.2.3.40`.

    This is the primitive both feeds need. A host-level listing on a shared
    platform is `PATH_ON_HOST` relative to any specific URL we were asked
    about, and that is the distinction seven months of silence hid: the
    2026-10-13 re-query found URLhaus listings on github.com,
    raw.githubusercontent.com, discord.com and www.google.com, and **not one**
    of them was for the path this platform had actually investigated.
    """
    # ── IP observables: parsed equality, never string containment ──
    target_ip = _address_of(observable)
    if target_ip is not None:
        indicator_ip = _address_of(indicator)
        if indicator_ip is None:
            # A domain IOC cannot be evidence about an IP, and a value that
            # does not parse as an address gets no equality at all.
            return ELSEWHERE
        if indicator_ip != target_ip:
            return ELSEWHERE
        # Same address. A URL on it is still a path, not the address.
        return SAME_HOST if not _path_of(indicator).rstrip("/") else PATH_ON_HOST

    target = _host_of(observable)
    if not target:
        return UNKNOWN
    # An IP indicator cannot be evidence about a domain observable either:
    # the only way `_host_of` could equate them is if the domain *is* the
    # address, which the branch above already handled.
    if _address_of(indicator) is not None:
        return ELSEWHERE
    host = _host_of(indicator)
    if host != target:
        return ELSEWHERE
    ind_path = _path_of(indicator).rstrip("/")
    obs_path = _path_of(observable).rstrip("/")
    if not ind_path:
        return SAME_HOST
    # The indicator names a path. It is about our observable only if it is
    # our observable's path, or sits under it.
    if obs_path and (ind_path == obs_path or ind_path.startswith(obs_path + "/")):
        return SAME_HOST
    return PATH_ON_HOST


def is_about(observable: str, match: Any) -> bool:
    """Whether this hit is evidence about `observable` itself.

    True only when the IOC's host **is** the observable. A URL hosted on it is
    not: `https://discord.com/api/webhooks/...` says a webhook is malicious,
    not that Discord is. A sibling or unrelated domain that merely contains
    the string is not either.
    """
    ioc_value = match.get("ioc_value") if isinstance(match, dict) else getattr(match, "ioc_value", "")
    ioc_type = match.get("ioc_type") if isinstance(match, dict) else getattr(match, "ioc_type", "")
    scope = scope_of(observable, ioc_value)
    if scope in {UNKNOWN, ELSEWHERE, PATH_ON_HOST}:
        return False
    # The host matches and no foreign path narrows it. A `url` IOC still
    # describes a path on that host rather than the host, so it only counts
    # when the observable was itself that URL — which a bare host comparison
    # cannot tell us, so require a host-shaped IOC type.
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


def intel_hits_about_observable(observable: str, hits: Iterable[Any]) -> list[Any]:
    """The `intel.blocklist_hits` that are evidence about `observable` itself.

    Two kinds of hit arrive in that list and they need different treatment:

    * a **DNSBL** hit (SURBL, Spamhaus DBL) is the answer to a query for this
      exact name, so its indicator is the observable by construction and it
      always counts;
    * a **URLhaus** hit comes from the `/v1/host/` endpoint, which answers a
      host question with a list of URLs. Asked about `github.com` it reports
      22,665 other people's payloads. Scoped, because restoring that feed at
      host granularity would escalate every GitHub, Discord and Google URL in
      the estate — which is most of them.

    Unknown observable keeps everything, for the same reason as
    `about_observable`: these hits are read as `and not intel_hits`, a
    precondition for benign, so dropping what cannot be scoped would unlock
    that branch while keeping it only blocks it.
    """
    hits = list(hits or [])
    if not _host_of(observable):
        return hits
    kept = []
    for hit in hits:
        indicator = (
            hit.get("indicator") if isinstance(hit, dict)
            else getattr(hit, "indicator", "")
        )
        category = (
            hit.get("category") if isinstance(hit, dict)
            else getattr(hit, "category", "")
        )
        if str(category or "") == HOST_AGGREGATE:
            # "N malicious URLs exist under this host" is not a statement
            # about the host. It stays in the evidence as context and decides
            # nothing.
            continue
        if scope_of(observable, indicator) != PATH_ON_HOST:
            kept.append(hit)
    return kept
