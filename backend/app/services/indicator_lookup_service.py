"""One indicator, asked of every source that can answer it — and only those.

This is the bounded form of "let me search the logs". The caller supplies a
**value**; this module decides the question. It never accepts a query body,
an index, a field name or a filter: see `ROUTING` and the route's docstring.

What makes it worth building rather than a search box
-----------------------------------------------------
Several sources, asked at once, is useful. Reporting a source's
*inapplicability* as its *answer* is the defect that makes it dangerous.
Falcon has no alert field that holds a domain — measured 2026-10-15, every
candidate returns HTTP 200 with zero rows — so a panel that renders an empty
Falcon section for `evil.com` tells an analyst the EDR has nothing, when the
truth is it has nowhere to look. That is false exculpation with a search box
on it (`docs/problems/false-exculpation.md`).

So the contract is: **per source, exactly one of three things.** An answer, a
named absence, or "this source cannot be asked about this kind of indicator,
because ⟨reason⟩". Never an empty result where the third applies.

Detection is shown, not assumed
-------------------------------
A mistyped hash is the case that motivated it. `d41d8cd98f00b204e9800998ecf8427`
is 31 characters: one short of an MD5, and a perfectly well-formed hostname.
Routed as a hostname it asks Falcon "is a machine called this?", gets a true
negative, and renders as "not found" — the wrong question answered correctly.
So anything digest-shaped but not a digest *length* is `unparsed` with the
lengths named, and the detected kind travels in the response for the reader to
check.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.services import absence

# --- kinds ----------------------------------------------------------------

SHA256, SHA1, MD5 = "sha256", "sha1", "md5"
IP, URL, DOMAIN, HOSTNAME = "ip", "url", "domain", "hostname"
UNPARSED = "unparsed"

HASH_LENGTHS = {64: SHA256, 40: SHA1, 32: MD5}

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
#: A registrable-looking name: at least one dot and a final label that is
#: alphabetic. Deliberately not a public-suffix list — this decides which
#: *question* to ask, and asking the estate about `foo.local` is harmless.
_DOTTED = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")
#: A bare machine name: no dots, and not hex of a digest length.
_BARE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def detect(value: str) -> dict[str, Any]:
    """What kind of indicator this is, and how it was decided.

    Order matters. Hash detection runs **first**, because a 32-character hex
    string is also a syntactically valid hostname, and a hostname is the
    reading that produces a confident wrong answer.

    **`readings` is the list of kinds this value can validly be read as**,
    primary first, and it exists because a dotted name is genuinely two
    things. `dns1.expertware.net` is a registrable domain *and* a Wazuh agent
    name in this estate's own EDR coverage list. Collapsing it to one reading
    makes the page answer a narrower question than it was asked: read only as
    a domain, Falcon is told it has no field and never asked whether it
    manages the host; read only as a hostname, the estate is told the question
    is out of scope and never asked whether anything resolved the name. Both
    answers are available and both are wanted, so both readings are carried
    and each section says which one it used.
    """
    raw = str(value or "")
    text = raw.strip()
    if not text:
        # `readings` on every return path. The one that lacked it would have
        # raised KeyError in the router rather than reporting an absence —
        # caught by the test that asserts detect() only emits reading sets the
        # table knows, which is the direction that finds a missing key rather
        # than a wrong one.
        return {"kind": UNPARSED, "readings": [UNPARSED], "value": "",
                "reason": "No value was given."}

    # 1. Digest-shaped. Checked before anything else, and a near-miss length
    #    is refused rather than falling through to the hostname rule.
    if _HEX.match(text):
        kind = HASH_LENGTHS.get(len(text))
        if kind:
            return {"kind": kind, "readings": [kind], "value": text.lower(),
                    "how": f"{len(text)} hexadecimal characters"}
        if 16 <= len(text) <= 128:
            return {
                "kind": UNPARSED, "readings": [UNPARSED], "value": text,
                "reason": (
                    f"This is {len(text)} hexadecimal characters, which is not "
                    f"a digest length — SHA-256 is 64, SHA-1 is 40, MD5 is 32. "
                    f"It is not being looked up as a hostname, which is what it "
                    f"would otherwise match: a mistyped hash that routes as a "
                    f"machine name returns a confident 'not found' to the wrong "
                    f"question."
                ),
            }

    # 2. An address, by parsing rather than by pattern.
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        parsed = None
    if parsed is not None:
        return {"kind": IP, "readings": [IP], "value": str(parsed),
                "how": f"parsed as an IPv{parsed.version} address",
                "is_private": parsed.is_private}

    # 3. A URL, by its scheme.
    if _SCHEME.match(text):
        return {"kind": URL, "readings": [URL], "value": text,
                "how": "has a URL scheme"}

    # 4. A dotted name, or a bare machine name.
    if _DOTTED.match(text):
        # Two valid readings, not a choice. See the docstring.
        return {
            "kind": DOMAIN, "readings": [DOMAIN, HOSTNAME],
            "value": text.lower(),
            "how": "a dotted name with an alphabetic final label",
            "ambiguous": True,
            "ambiguity": (
                "A dotted name is both a domain and a possible machine name. "
                "Both readings were used: the log store was asked whether any "
                "host resolved this name, and the EDR was asked whether it "
                "manages a device called this. Each section says which "
                "reading it answered."
            ),
        }
    if "." not in text and _BARE.match(text):
        return {"kind": HOSTNAME, "readings": [HOSTNAME], "value": text,
                "how": "no dots, so read as a machine name rather than a domain"}

    return {
        "kind": UNPARSED, "readings": [UNPARSED], "value": text,
        "reason": (
            "This is not a hash, an address, a URL, a dotted name or a bare "
            "machine name, so no source has a question to ask about it. It is "
            "not guessed at."
        ),
    }


# --- routing ---------------------------------------------------------------

#: Per kind, per source: `ask`, or a named absence with the measured reason.
#:
#: A source that cannot answer gets its reason **here**, once, rather than
#: being discovered per lookup. Adding a kind without a decision for every
#: source fails `test_indicator_lookup.py`, because a kind that quietly gets
#: an empty section is the defect this table exists to prevent.
ASK = "ask"

ROUTING: dict[str, dict[str, Any]] = {
    SHA256: {
        "falcon": ASK,
        "estate": ASK,
    },
    SHA1: {
        "falcon": ASK,
        "estate": ASK,
    },
    MD5: {
        "falcon": ASK,
        "estate": ASK,
    },
    HOSTNAME: {
        "falcon": ASK,
        "estate": (absence.OUT_OF_SCOPE,
                   "The estate's DNS telemetry answers which *names a host "
                   "resolved*, not which hosts exist. A machine name is not a "
                   "name a host looks up, so this question was not asked of "
                   "it."),
    },
    DOMAIN: {
        # Measured 2026-10-15 against 200 real alerts: the Falcon alert record
        # has no `behaviors` key and no field carries a domain.
        # `behaviors.domain`, `domain`, `data_domains`, `ioc_context.domain`
        # and `ioc_value` all return HTTP 200 with zero rows, and
        # `data_domains` holds a data classification (`['Endpoint']`), not a
        # name. The intel endpoints that would answer are 403.
        "falcon": (absence.NO_FIELD_MAP,
                   "CrowdStrike Falcon has no alert field that holds a domain. "
                   "Every candidate was probed and each returns an empty "
                   "success, and `data_domains` — the only field whose name "
                   "contains the word — holds a data classification such as "
                   "'Endpoint'. The intelligence endpoints that would answer "
                   "'is this domain known bad' are refused to this credential "
                   "(403, scope not permitted). So nothing was searched: an "
                   "empty Falcon result here would mean the field, not the "
                   "domain."),
        "estate": ASK,
    },
    IP: {
        "falcon": (absence.OUT_OF_SCOPE,
                   "Falcon's `source_ips` on an alert holds *internal* source "
                   "addresses, and `local_ip` on a device is that device's own "
                   "LAN address. A remote address can never appear in either — "
                   "a valid field, a valid value, and a structurally "
                   "impossible match. Nothing was searched."),
        "estate": ASK,
    },
    URL: {
        "falcon": (absence.NO_FIELD_MAP,
                   "Falcon has no alert field that holds a URL, for the same "
                   "reason it has none for a domain."),
        # The narrower claim, labelled as such — see `url_fallback`.
        "estate": (absence.OUT_OF_SCOPE,
                   "This estate has no proxy logs: `data.proxy.url` and "
                   "`data.http.url` are both empty across the full retention "
                   "window, and `data.url` comes from a single appliance. The "
                   "estate cannot be asked at URL grain at all."),
    },
    UNPARSED: {
        "falcon": (absence.UNPARSED,
                   "The value's kind could not be determined, so no question "
                   "was chosen for it."),
        "estate": (absence.UNPARSED,
                   "The value's kind could not be determined, so no question "
                   "was chosen for it."),
    },
}

SOURCES = ("falcon", "estate")


def plan(kind: str) -> dict[str, Any]:
    """Which sources will be asked, and why the others will not.

    Indexed, not `.get()`-with-a-default: a kind absent from `ROUTING` is a
    programming error, and defaulting it to "ask everything" would send a
    value to a source that has no question for it.
    """
    if kind not in ROUTING:
        raise KeyError(
            f"no routing decision for kind {kind!r} — every kind needs one per "
            f"source, or it silently renders an empty section"
        )
    row = ROUTING[kind]
    return {source: row[source] for source in SOURCES}


#: Reading-sets `detect` can emit. Enumerated so the test below can assert a
#: decision exists for every one of them — a pair with no decision is the
#: silent collapse this whole mechanism exists to prevent.
READING_SETS: tuple[tuple[str, ...], ...] = (
    (SHA256,), (SHA1,), (MD5,), (IP,), (URL,), (HOSTNAME,), (UNPARSED,),
    (DOMAIN, HOSTNAME),
)


def plan_readings(readings: Any) -> dict[str, Any]:
    """Per source: which reading it is asked under, or why it is not asked.

    A source is asked under the **first** reading that has a question for it,
    and the reading used travels with the decision so the section can say so.
    A source refused by every reading carries the refusal from its *primary*
    reading, because that is the question the analyst actually typed.
    """
    order = [r for r in (readings or []) if r in ROUTING]
    if not order:
        raise KeyError(
            f"no routing decision for readings {readings!r} — every reading "
            f"set needs one per source, or a section silently renders empty"
        )
    out: dict[str, Any] = {}
    for source in SOURCES:
        chosen: Any = None
        for reading in order:
            if ROUTING[reading][source] is ASK:
                chosen = {"decision": ASK, "reading": reading}
                break
        if chosen is None:
            primary = order[0]
            chosen = {"decision": ROUTING[primary][source], "reading": primary}
        elif chosen["reading"] != order[0]:
            # Asked under a secondary reading. The PRIMARY reading's refusal is
            # still a fact the analyst needs, and dropping it trades one
            # collapse for another: someone typing `aka.ms` means the domain,
            # and "Falcon has no field that holds a domain" is the sentence
            # that stops them reading a hostname miss as "the EDR has nothing
            # on this domain". Both are carried.
            primary_decision = ROUTING[order[0]][source]
            if primary_decision is not ASK:
                chosen["also_refused_for"] = {
                    "reading": order[0], "decision": primary_decision,
                }
        out[source] = chosen
    return out


def refusal(decision: Any, *, raw: str | None = None) -> dict[str, Any]:
    """A routing decision rendered as the absence it is."""
    kind, reason = decision
    return absence.absent(kind, reason, raw=raw).as_json()


def url_fallback(value: str) -> dict[str, Any]:
    """The host of a URL, so the estate can answer a narrower question.

    Returned alongside the URL's own `out_of_scope`, and **labelled as the
    narrower claim**: "a host resolved this name" is not "a host fetched this
    URL", and presenting the first as an answer to the second is the kind of
    substitution that makes a panel confidently wrong.
    """
    from app.services.threatfox_match_scope import _host_of

    host = ""
    try:
        host = str(_host_of(value) or "")
    except Exception:  # noqa: BLE001
        host = ""
    if not host:
        return {}
    return {
        "asked_instead": host,
        "kind": DOMAIN,
        "claim": (
            f"The estate cannot be asked about a URL, so it was asked about "
            f"the host {host!r} instead. This is a narrower claim: it answers "
            f"whether a host resolved that name, not whether anything fetched "
            f"that URL."
        ),
    }
