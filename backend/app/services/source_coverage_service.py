"""How many sources actually answered for *this one verdict*.

`source_answer_rate_service` asks the estate-wide question: has each source
ever answered, across a window. This asks the per-verdict one: when this
observable was judged, what was available to judge it with? They are
different questions and only the second one helps the analyst holding the
case.

Why it exists
-------------
On 2026-09-15 and 2026-09-16 — the two busiest days in the 90-day window —
four of eight external sources were unavailable at once:

    VirusTotal         rate-limited on 199 runs across those two days
    intel collector    dead since 2026-07-07 (Spamhaus SIA 401)
    ThreatFox          401 since 2026-03
    OTX                HTTPError on ~70% of all runs

Three of those four are load-independent, so the composite degradation
*peaks with volume*: the evidence base thins exactly when traffic is
heaviest. Those same two days produced 201 extra `suspicious, investigate`
verdicts. More work and less information, at the same moment, compounding.

Every one of those facts was already written down. `meta.status` is on every
collector's output on every row, `feeds_checked`/`feeds_skipped` on every
threat-feeds row, `sources_checked`/`sources_skipped` on every intel row
since today. Nothing read any of them, which has been the shape of every
defect found on 2026-10-13. This is `checked and not listed` generalised from
one precondition to the whole verdict.

Read time, never stored
-----------------------
Computed from the stored evidence on each read, per the layer contract at the
top of the README: storage holds what collection produced, and anything
derived is derived when asked. Two consequences, both wanted:

  * it works retrospectively. A verdict from 2026-09-15 reports its coverage
    today with no backfill, because the inputs were always there;
  * it cannot drift from the evidence it describes.

The expected set is derived, not listed
---------------------------------------
From `COLLECTOR_REGISTRY` filtered by each collector's own
`supported_types`. A hand-kept list of sources would lag the code — `otx`
was missing from `source_answer_rate_service.SOURCES` while being 70% dead,
which is the check built to find dead sources failing to cover one, and the
third hand-maintained list to swallow an entry on 2026-10-13 after
`NOT_INSTRUMENTED` and the tolerated-failure set. Ask the data what is true,
applied to the instrument's own scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services.absence import CHECK_FAILED, OUT_OF_SCOPE, absent

#: A collector that ran and returned. The only state that is an answer.
ANSWERED = "answered"
#: A collector that ran and failed. Its silence is not a negative.
FAILED = "failed"
#: A collector that was never attempted: `meta.status = "skipped"`, or no
#: block in the evidence at all, which on this platform means it was not in
#: the selection for that run. Reported, because reading its emptiness as a
#: clean result is still wrong — but **not counted as a gap**, because
#: nothing is broken.
NOT_ATTEMPTED = "not_attempted"
#: The observable's type is outside this collector's `supported_types`, so
#: there was never a question to ask. Excluded from the denominator entirely.
NOT_APPLICABLE = "not_applicable"
#: The collector ran, but recorded nothing about whether this particular
#: sub-feed was asked. Older rows, before `feeds_checked` and
#: `sources_checked` existed. Genuinely unknown rather than known-bad.
UNKNOWN = "unknown"

#: The states that make this source a **gap in the evidence base**: it was
#: selected, it was asked, and it did not answer. This is the set the
#: headline counts.
#:
#: Deliberately **not** `NOT_ATTEMPTED` or `UNKNOWN`. The first version of
#: this service counted both, and reported "13 of 21 sources unavailable" on
#: an ordinary March verdict — a mean of 47-50% on *every* day in the window,
#: so the two days the VirusTotal quota blew did not stand out at all. A
#: field that cries wolf on every case is a field analysts learn to skip,
#: which is the failure mode this service's own test warns about. It was the
#: defect of the day committed inside the fix for it, for the fourth time.
UNAVAILABLE = frozenset({FAILED})

#: Reported beside the gaps, never inside the count.
NOT_A_GAP = frozenset({NOT_ATTEMPTED, UNKNOWN, NOT_APPLICABLE})

#: `meta.status` values that mean the collector ran to completion. Taken from
#: what the corpus actually contains rather than from the enum, because the
#: enum has values no row has ever carried and the rows have values the enum
#: does not name — `skipped`, which only `hybrid_analysis` emits.
_COMPLETED = frozenset({"completed", "success", "ok"})
_SKIPPED = frozenset({"skipped", "not_applicable", "disabled"})

#: The sub-feeds inside a single collector's output, and where each records
#: whether it was asked. These are the sources an analyst names — nobody says
#: "the threat_feeds collector", they say "ThreatFox" — so coverage is
#: reported at this grain and not at the collector's.
#:
#: Each entry: the collector key, the evidence paths holding the asked/skipped
#: records, and how a skipped entry names its feed.
_SUBFEEDS: dict[str, dict[str, Any]] = {
    "threat_feeds": {
        # `feeds_skipped` entries look like "threatfox (error: HTTPError)",
        # so a prefix match is what identifies the feed.
        "checked_at": ("feeds_checked",),
        "skipped_at": ("feeds_skipped",),
        "feeds": ("threatfox", "otx", "abuseipdb", "phishtank", "openphish",
                  "google_safe_browsing"),
    },
    "intel": {
        "checked_at": ("sources_checked",),
        "skipped_at": ("sources_skipped",),
        "feeds": ("SURBL", "Spamhaus DBL", "URLhaus (abuse.ch)", "Spamhaus SIA"),
    },
}


#: `meta.error` has always been stored and was never returned by an
#: application API until `source_coverage` existed, so surfacing it is new
#: exposure and the standing rule applies: never return a credential through
#: an API response. All 774 distinct stored error strings were scanned on
#: 2026-10-13 and none contained a key-shaped name/value pair — but that is a
#: fact about today's corpus, not about the next collector to put a signed
#: URL in an exception, so the redaction is unconditional rather than
#: conditional on having found something.
_SECRETISH = re.compile(
    r"(?i)([?&][a-z0-9_\-]*(?:key|token|secret|auth|pass|sig)[a-z0-9_\-]*=)"
    r"[^&\s\"']+"
)
#: Two separators, because the header form uses neither `=` nor a bare `:`.
#: `Authorization: Bearer <jwt>` was missed by the `[:=]`-only version, and
#: it is the exact case the standing rule names — "sanitize authorization
#: headers from traces and error reporting".
_SECRETISH_KV = re.compile(
    r"(?i)\b(api[-_]?key|apikey|auth[-_]?key|authorization|token|secret|"
    r"password|passwd|x-api-key)\b(\s*[:=]\s*)\S+(?:\s+\S+)?"
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+\S+")
#: The longest stored error is 2,321 characters. A page is not a log.
_DETAIL_MAX = 300


def _safe_detail(detail: str | None) -> str | None:
    """Redact key-shaped values and bound the length."""
    if not detail:
        return detail
    out = _SECRETISH.sub(r"\1[redacted]", str(detail))
    out = _SECRETISH_KV.sub(r"\1\2[redacted]", out)
    out = _BEARER.sub(r"\1 [redacted]", out)
    if len(out) > _DETAIL_MAX:
        out = out[:_DETAIL_MAX].rstrip() + "..."
    return out


@dataclass(frozen=True)
class SourceState:
    """One source, and whether it answered for this verdict."""

    source: str
    state: str
    #: The collector it belongs to, so a reader can tell four dead feeds in
    #: one collector from four dead collectors.
    collector: str
    detail: str | None = None

    @property
    def available(self) -> bool:
        return self.state == ANSWERED

    def as_json(self) -> dict[str, Any]:
        detail = _safe_detail(self.detail)
        out: dict[str, Any] = {
            "source": self.source,
            "collector": self.collector,
            "state": self.state,
        }
        if detail:
            out["detail"] = detail
        if self.state in {FAILED, NOT_ATTEMPTED, UNKNOWN}:
            # The absence travels with the state, so a renderer handed this
            # has a sentence to show and no way to render it as a value —
            # including for the states that are not counted as gaps, because
            # "nobody asked" still must not read as "asked and clean".
            out["absence"] = absent(
                CHECK_FAILED,
                detail or f"{self.source} did not answer for this verdict.",
                raw=self.state,
            ).as_json()
        elif self.state == NOT_APPLICABLE:
            out["absence"] = absent(
                OUT_OF_SCOPE,
                f"{self.source} does not cover this observable type, so there "
                "was no question to ask.",
            ).as_json()
        return out


@dataclass(frozen=True)
class Coverage:
    observable_type: str
    sources: list[SourceState] = field(default_factory=list)

    @property
    def applicable(self) -> list[SourceState]:
        return [s for s in self.sources if s.state != NOT_APPLICABLE]

    @property
    def answered(self) -> list[SourceState]:
        return [s for s in self.sources if s.state == ANSWERED]

    @property
    def unavailable(self) -> list[SourceState]:
        """Sources that were asked and did not answer. The gaps."""
        return [s for s in self.sources if s.state in UNAVAILABLE]

    @property
    def not_attempted(self) -> list[SourceState]:
        return [s for s in self.sources if s.state == NOT_ATTEMPTED]

    @property
    def unknown(self) -> list[SourceState]:
        return [s for s in self.sources if s.state == UNKNOWN]

    @property
    def asked(self) -> list[SourceState]:
        """The denominator: sources this run actually put a question to."""
        return [s for s in self.sources
                if s.state in (UNAVAILABLE | {ANSWERED, UNKNOWN})]

    def headline(self) -> str:
        """The sentence that belongs beside the verdict."""
        total = len(self.asked)
        out = len(self.unavailable)
        if not total:
            return "No external source was asked about this observable."
        if not out:
            return f"All {total} sources asked answered."
        return (
            f"{out} of {total} sources unavailable when this verdict was "
            f"reached: {', '.join(s.source for s in self.unavailable)}."
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "observable_type": self.observable_type,
            # `asked` is the denominator, not `applicable`: a collector that
            # was not in the selection was never a question.
            "asked": len(self.asked),
            "applicable": len(self.applicable),
            "answered": len(self.answered),
            "unavailable": len(self.unavailable),
            # Named, not just counted. "9 uninstrumented tasks" needed
            # enumerating too, for the same reason: a count tells nobody
            # which one to go and fix.
            "unavailable_sources": [s.source for s in self.unavailable],
            # Beside the gaps, never inside the count.
            "not_attempted_sources": [s.source for s in self.not_attempted],
            "unknown_sources": [s.source for s in self.unknown],
            "headline": self.headline(),
            "sources": [s.as_json() for s in self.sources],
        }


def _meta_state(block: Any) -> tuple[str, str | None]:
    """Read one collector's own account of whether it ran."""
    if not isinstance(block, dict):
        # No block at all. On this platform that means the collector was not
        # in the selection for the run — `asn`, `cape`, `brave_osint` and
        # `opencti` are absent from most rows for exactly that reason. Not a
        # gap in the evidence base; a fact about what was requested.
        return NOT_ATTEMPTED, "This collector was not part of the selection."
    meta = block.get("meta")
    if not isinstance(meta, dict):
        # A block with no meta predates CollectorMeta. Treat as answered
        # rather than inventing a failure: the older rows are not evidence
        # of breakage, and the opposite assumption is the same
        # absence-as-value error pointing the other way.
        return ANSWERED, None
    status = str(meta.get("status") or "").strip().lower()
    if status in _COMPLETED:
        return ANSWERED, None
    if status in _SKIPPED:
        return NOT_ATTEMPTED, "This collector was not part of the selection."
    if not status:
        return ANSWERED, None
    error = str(meta.get("error") or "").strip()
    return FAILED, error or f"The collector reported status {status!r}."


def _subfeed_states(collector: str, block: Any, spec: dict[str, Any],
                    parent_state: str) -> list[SourceState]:
    """Per-feed states inside one collector's output."""
    checked: set[str] = set()
    skipped: dict[str, str] = {}
    if isinstance(block, dict):
        for key in spec["checked_at"]:
            value = block.get(key)
            if isinstance(value, list):
                checked |= {str(v).strip() for v in value}
        for key in spec["skipped_at"]:
            value = block.get(key)
            if isinstance(value, dict):
                for name, ab in value.items():
                    reason = (ab or {}).get("reason") if isinstance(ab, dict) else None
                    skipped[str(name).strip()] = str(reason or "")
            elif isinstance(value, list):
                # "threatfox (error: HTTPError)" — the feed name is the head.
                for entry in value:
                    text = str(entry).strip()
                    name = text.split(" (", 1)[0].strip()
                    skipped[name] = text

    out: list[SourceState] = []
    for feed in spec["feeds"]:
        if feed in checked:
            out.append(SourceState(feed, ANSWERED, collector))
        elif feed in skipped:
            out.append(SourceState(
                feed, FAILED, collector,
                skipped[feed] or f"{feed} was recorded as skipped.",
            ))
        elif parent_state in {FAILED, NOT_ATTEMPTED}:
            # The collector itself did not run, so none of its feeds did —
            # and the feed inherits *which* kind. `FAILED` is the 2,198-run
            # case: `blocklist_hits: []` on a row where `_collect` raised,
            # which read downstream as four blocklists clearing the domain.
            # `NOT_ATTEMPTED` is a collector that was never in the selection,
            # and propagating that as `UNKNOWN` instead would have put every
            # feed behind an unselected collector into the gap count.
            out.append(SourceState(
                feed, parent_state, collector,
                f"The {collector} collector "
                + ("did not complete" if parent_state == FAILED
                   else "was not part of the selection")
                + f", so {feed} was never asked.",
            ))
        else:
            out.append(SourceState(
                feed, UNKNOWN, collector,
                f"The {collector} collector completed but recorded nothing "
                f"about whether {feed} was asked. Evidence written before "
                "that flag existed cannot say either way.",
            ))
    return out


def coverage(evidence: dict[str, Any] | None,
             observable_type: str | None = None) -> Coverage:
    """What answered for this verdict, derived from the stored evidence."""
    from app.collectors.registry import COLLECTOR_REGISTRY

    evidence = evidence if isinstance(evidence, dict) else {}
    otype = str(
        observable_type or evidence.get("observable_type") or "domain"
    ).strip().lower()

    states: list[SourceState] = []
    for name, cls in sorted(COLLECTOR_REGISTRY.items()):
        if otype not in getattr(cls, "supported_types", frozenset()):
            states.append(SourceState(name, NOT_APPLICABLE, name))
            continue
        block = evidence.get(name)
        state, detail = _meta_state(block)
        spec = _SUBFEEDS.get(name)
        if spec:
            # Report the feeds, not the collector that batches them. The
            # collector's own state still travels, as each feed's detail.
            states.extend(_subfeed_states(name, block, spec, state))
            continue
        states.append(SourceState(name, state, name, detail))

    return Coverage(observable_type=otype, sources=states)
