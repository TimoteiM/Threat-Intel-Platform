"""Has each enrichment source ever actually answered?

The companion to the watch heartbeat. That one asks *did the task run*; this
asks *did the source answer*, and they are different blindnesses. A collector
can run on schedule, succeed, and record nothing from a provider that refused
every request — which is what happened to ThreatFox for seven months.

The signature, and why it generalises
-------------------------------------
2,400 evidence rows carried a `threat_feeds` block between 2026-03-02 and
2026-10-13. Every one had an empty `threatfox_matches`. Not one hit in seven
months, across 1,827 distinct domains.

That is not a quiet estate. **Any enrichment source returning 100% empty over
a meaningful window is broken, whatever it claims about itself.** The reason
nobody noticed is that an empty result is indistinguishable from a clean one
at every layer above the request — the collector returned `[]`, the decision
engine read `[]` as "nothing to escalate on", and the report said nothing at
all.

So the check is a rate rather than a value, and it needs no new storage: the
evidence rows already hold every answer every source ever gave.

What it deliberately does not do
--------------------------------
It does not alarm. A source legitimately at 0% over a short window is
ordinary — most domains are in no blocklist — so the threshold has to come
from a week of this check's own output rather than from a number picked here.
That is the same shadow-first rule the emitter freshness work runs under.

It also reports a *rate with its denominator*, never a bare percentage: "0 of
2,400" and "0%" carry different information when the denominator is 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import TOO_LITTLE_HISTORY, absent

#: Below this many observations a rate says nothing, and a 0% that means
#: "asked three times" would be the blank-as-measurement bug the absence
#: convention exists to stop.
MIN_OBSERVATIONS = 50

#: How far back to look. Long enough that a quiet fortnight does not read as
#: a dead feed; short enough that a source broken last month still shows.
WINDOW_DAYS = 90

#: Each source, and the JSONB path whose non-emptiness means "this source
#: returned something". Declared rather than discovered: a source that stops
#: appearing in the evidence at all is a different fault, and a check that
#: silently stopped covering it would be the hand-maintained-list failure
#: this codebase has had seven times — so `test_source_answer_rate` asserts
#: every key here still exists in the stored evidence.
SOURCES: dict[str, str] = {
    "threatfox": "evidence_json->'threat_feeds'->'threatfox_matches'",
    "abuseipdb": "evidence_json->'threat_feeds'->'abuseipdb'",
    "phishtank": "evidence_json->'threat_feeds'->'phishtank'",
    "virustotal": "evidence_json->'vt'",
    "urlscan": "evidence_json->'urlscan'",
    "intel_blocklists": "evidence_json->'intel'->'blocklist_hits'",
    "subdomains": "evidence_json->'subdomains'",
}


@dataclass(frozen=True)
class SourceAnswers:
    source: str
    observations: int
    answered: int

    @property
    def rate(self) -> float | None:
        if self.observations < MIN_OBSERVATIONS:
            return None
        return self.answered / self.observations

    def as_json(self) -> dict[str, Any]:
        if self.observations < MIN_OBSERVATIONS:
            return {
                "source": self.source,
                "observations": self.observations,
                "answered": self.answered,
                "rate": absent(
                    TOO_LITTLE_HISTORY,
                    f"This source has been recorded {self.observations} times "
                    f"in the window, below the {MIN_OBSERVATIONS} needed for a "
                    "rate to mean anything. A 0% from three observations is "
                    "not evidence of a broken feed.",
                ).as_json(),
            }
        return {
            "source": self.source,
            # The denominator travels with the rate. "0%" and "0 of 2,400"
            # carry different information, and only one of them is a finding.
            "observations": self.observations,
            "answered": self.answered,
            "rate": round(self.answered / self.observations, 4),
            "never_answered": self.answered == 0,
        }


async def answer_rates(
    db: AsyncSession, *, days: int = WINDOW_DAYS, now: datetime | None = None
) -> dict[str, Any]:
    """How often each source returned anything, over the window."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    # One pass, not one per source. The first version ran seven separate
    # scans over `evidence` and took 97 seconds — unusable anywhere a caller
    # waits, and the reason this does not live on /health.
    selects = ",\n".join(
        f"""count(*) filter (where {path} is not null) as obs_{i},
            count(*) filter (
              where {path} is not null
                and {path} <> 'null'::jsonb
                and {path} <> '[]'::jsonb
                and {path} <> '{{}}'::jsonb
            ) as ans_{i}"""
        for i, path in enumerate(SOURCES.values())
    )
    row = (
        await db.execute(
            text(f"select {selects} from evidence where created_at >= :since"),
            {"since": since},
        )
    ).first()

    reports: list[SourceAnswers] = [
        SourceAnswers(
            source,
            int(getattr(row, f"obs_{i}") or 0),
            int(getattr(row, f"ans_{i}") or 0),
        )
        for i, source in enumerate(SOURCES)
    ]

    silent = [
        r.source for r in reports
        if r.observations >= MIN_OBSERVATIONS and r.answered == 0
    ]
    return {
        "window_days": days,
        "sources": [r.as_json() for r in reports],
        # The finding, named rather than left to a reader to spot in a table.
        "never_answered": sorted(silent),
        "note": (
            "A source at 0% over a meaningful window is broken, whatever it "
            "claims. This reports and does not alarm: the threshold for "
            "anything below 100% silence has to come from a week of this "
            "check's own output."
        ),
    }
