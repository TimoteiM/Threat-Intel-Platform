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

What it got wrong about itself
------------------------------
On 2026-10-13 this check reported `intel_blocklists` at 0% of 2,286 and that
figure was true and the conclusion drawn from it was wrong. It counted a row
as an **observation** whenever the JSONB path was non-null — and
`IntelEvidence.blocklist_hits` is a Pydantic field defaulting to `[]`, so the
key is present whenever an `IntelEvidence` was serialised, including on the
failure path where nothing ran. The intel collector had in fact failed
outright on 2,198 consecutive runs: `meta.status = "failed"`, every field
empty, a 401 from a fourth source raised out of `_collect`.

So "a source that stopped answering" and "a collector that never ran" were
reported as the same thing, by the check written to tell absence from zero.
`meta.status` had recorded the truth on all 2,198 rows and nothing read it —
the same shape as `feeds_skipped` for ThreatFox, one layer out, inside the
instrument this time.

A collector's own status is therefore consulted first, and a source whose
collector failed is reported as `check_failed` rather than as 0%. A rate over
runs that never happened is not a rate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import CHECK_FAILED, TOO_LITTLE_HISTORY, absent

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
#: this codebase has had seven times.
#:
#: `test_source_answer_rate` checks that each path is **well formed** — rooted
#: in `evidence_json` and quoted. It does not and cannot check that a path
#: resolves, because that needs the corpus. An earlier version of this comment
#: claimed it asserted "every key here still exists in the stored evidence",
#: which was a doc comment describing a test that did something weaker. The
#: existence check lives in `answer_rates` instead, where the data is: a path
#: that appeared in **none** of the rows in the window is reported as
#: `check_failed`, not as a 0% rate and not as too little history.
SOURCES: dict[str, str] = {
    "threatfox": "evidence_json->'threat_feeds'->'threatfox_matches'",
    # Added 2026-10-13. It was missing, and it is 70.5% dead: `feeds_skipped`
    # carries `otx (error: HTTPError)` on 1,567 of 2,221 rows in the window
    # plus 112 ReadTimeouts. The check built to find sources that stopped
    # answering did not cover one that had — the eighth instance of the
    # hand-maintained list that swallows an entry with no error.
    "otx": "evidence_json->'threat_feeds'->'otx'",
    "abuseipdb": "evidence_json->'threat_feeds'->'abuseipdb'",
    "phishtank": "evidence_json->'threat_feeds'->'phishtank'",
    "virustotal": "evidence_json->'vt'",
    "urlscan": "evidence_json->'urlscan'",
    "intel_blocklists": "evidence_json->'intel'->'blocklist_hits'",
    "subdomains": "evidence_json->'subdomains'",
}

#: The collector whose `meta.status` decides whether each source was in a
#: position to answer at all. A source with no entry here is not gated —
#: stated as an omission rather than left to be inferred from the dict, and
#: `test_source_answer_rate` asserts the keys still resolve, because this is
#: the eighth hand-maintained list in this codebase and the previous seven
#: each swallowed a new entry silently.
COLLECTOR_OF: dict[str, str] = {
    # Subdomain enumeration takes its input from the intel collector's crt.sh
    # output, so intel's status gates it too — a dependency, not a collector
    # of its own.
    "subdomains": "intel",
    "threatfox": "threat_feeds",
    "abuseipdb": "threat_feeds",
    "phishtank": "threat_feeds",
    "virustotal": "vt",
    "urlscan": "urlscan",
    "intel_blocklists": "intel",
}


@dataclass(frozen=True)
class SourceAnswers:
    source: str
    observations: int
    answered: int
    #: Rows where the source's own collector recorded `meta.status != completed`.
    #: These are not observations of the source; nothing asked it.
    collector_failed: int = 0

    @property
    def rate(self) -> float | None:
        if self.observations < MIN_OBSERVATIONS:
            return None
        return self.answered / self.observations

    def as_json(self) -> dict[str, Any]:
        if self.observations == 0:
            # The path appeared in no row at all. Either the feature stopped
            # running or the declared path is wrong, and both are faults —
            # neither is a rate, and neither is a young source.
            #
            # `subdomains` is here as of 2026-10-13, and it is the first
            # kind: subdomain enumeration only runs when
            # `intel.related_subdomains` is non-empty, and that has been
            # empty on every run since the intel collector began failing on
            # 2026-07-07. A second feature lost to the same 401, found only
            # because this branch stopped calling it "too little history".
            return {
                "source": self.source,
                "observations": 0,
                "answered": 0,
                "collector_failed": self.collector_failed,
                "rate": absent(
                    CHECK_FAILED,
                    "This source's path did not appear in a single evidence "
                    "row in the window. Either the feature stopped running or "
                    "the declared path is wrong; both are faults, and neither "
                    "is a rate.",
                    raw=SOURCES.get(self.source),
                ).as_json(),
            }
        if self.observations and self.collector_failed >= self.observations:
            # Every row in the window came from a collector that did not
            # complete. There is no rate here, and reporting 0% would say
            # the source answered nothing when it was never asked.
            return {
                "source": self.source,
                "observations": self.observations,
                "answered": self.answered,
                "collector_failed": self.collector_failed,
                "rate": absent(
                    CHECK_FAILED,
                    f"All {self.observations} rows in the window were written "
                    f"by a collector that did not complete, so this source was "
                    "never asked. An empty result here is not a negative, and "
                    "a 0% rate would describe a question nobody put.",
                ).as_json(),
            }
        if self.observations < MIN_OBSERVATIONS:
            return {
                "source": self.source,
                "observations": self.observations,
                "answered": self.answered,
                "collector_failed": self.collector_failed,
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
            # And the denominator itself needs qualifying: a row whose
            # collector failed is not an observation of this source.
            "collector_failed": self.collector_failed,
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
    def _failed_expr(source: str) -> str:
        collector = COLLECTOR_OF.get(source)
        if not collector:
            return "0"
        # `meta.status` absent counts as not-failed: the oldest rows predate
        # CollectorMeta, and inventing a failure for them would be the same
        # absence-as-value error in the other direction.
        return (
            f"count(*) filter (where {SOURCES[source]} is not null and "
            f"coalesce(evidence_json->'{collector}'->'meta'->>'status', "
            f"'completed') <> 'completed')"
        )

    selects = ",\n".join(
        f"""count(*) filter (where {path} is not null) as obs_{i},
            count(*) filter (
              where {path} is not null
                and {path} <> 'null'::jsonb
                and {path} <> '[]'::jsonb
                and {path} <> '{{}}'::jsonb
            ) as ans_{i},
            {_failed_expr(source)} as bad_{i}"""
        for i, (source, path) in enumerate(SOURCES.items())
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
            int(getattr(row, f"bad_{i}") or 0),
        )
        for i, source in enumerate(SOURCES)
    ]

    silent = [
        r.source for r in reports
        if r.observations >= MIN_OBSERVATIONS
        and r.answered == 0
        and r.collector_failed < r.observations
    ]
    # Reported separately, because the two call for different work: a silent
    # source needs its provider chased, a dead collector needs its own
    # exception found. Conflating them cost 98 days.
    never_asked = [
        r.source for r in reports
        if r.observations and r.collector_failed >= r.observations
    ]
    #: A declared source that produced no row at all. Reported separately
    #: again, because the work is different a third time: not a provider to
    #: chase and not an exception to find, but a feature or a path to check.
    never_present = [r.source for r in reports if r.observations == 0]
    return {
        "window_days": days,
        "sources": [r.as_json() for r in reports],
        # The finding, named rather than left to a reader to spot in a table.
        "never_answered": sorted(silent),
        "never_asked": sorted(never_asked),
        "never_present": sorted(never_present),
        "note": (
            "A source at 0% over a meaningful window is broken, whatever it "
            "claims. This reports and does not alarm: the threshold for "
            "anything below 100% silence has to come from a week of this "
            "check's own output."
        ),
    }
