"""
What is normal on this host, learned from what this platform already stored.

A case's raw score asks how alarming its shape is. It cannot ask whether that
shape is ordinary *here*, and on this deployment that is the question that
separates a finding from a fixture: two rules that co-fire on the same host
every day are a property of the estate, not evidence about tonight.

So familiarity is measured and applied as a multiplier. It is deliberately not
another additive term — an additive penalty can always be out-voted by enough
kill-chain shape, and the whole point is that a routine pairing should not
become interesting merely by being routine in an interesting order.

Everything here is computed from stored runs, unsupervised, with no labels and
no warm-up. The baseline is available in full the first time it is asked for,
because the history it reads has been accumulating since long before it existed.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun
from app.services.alert_field_service import UNKNOWN_CLIENT, UNKNOWN_SOURCE

logger = logging.getLogger(__name__)

# The floor on how far back familiarity is learned from. Long enough that a
# weekly job is seen four times and reads as routine; short enough that an
# estate which changed two months ago is not still being judged against its old
# self.
SURPRISE_BASELINE_DAYS = 30

# The baseline must always be much wider than the window being scored, because
# a case's own days are excluded from its own history. That exclusion is what
# stops a case measuring itself — and it means the case eats a slice of its own
# baseline, sized by the query window. At 48h against 30 days a case owns one
# day in thirty and the multiplier works; at a 30-day query against a 30-day
# baseline it owns all of it, every pair reads as never-seen, and surprise goes
# to 1.0 everywhere.
#
# That is a slope, not a cliff: the multiplier degrades continuously as the two
# windows converge, so a fixed 30 days is not a safe default but an
# operating-point assumption that fails silently the first time somebody opens a
# 7-day view. The window is therefore derived, never fixed, and the invariant it
# holds is: a case never owns more than about 1/k of the history it is judged
# against.
BASELINE_WINDOW_MULTIPLE = 12


def baseline_window_days(query_hours: int) -> int:
    """
    How far back to learn familiarity when scoring a window of `query_hours`.

    Derived rather than configured, so the invariant survives someone changing
    the query window without knowing this exists.
    """
    query_days = max(1, math.ceil(max(1, int(query_hours)) / 24))
    return max(SURPRISE_BASELINE_DAYS, query_days * BASELINE_WINDOW_MULTIPLE)

# The multiplier can never reach zero. A pure 1/(1+n) drives a pair seen fifty
# times to 0.02 and would erase any case built on familiar rules — but "boring
# rules in an alarming sequence" is a real attack shape, and an attacker using
# the tools already on the box produces exactly it. The floor is what keeps that
# case visible: heavily discounted, never silenced.
SURPRISE_FLOOR = 0.10

# Generalised mean exponent, sitting between the arithmetic mean (1) and the
# maximum (infinity).
#
# Measured on the shapes that matter, this is why it is 3 and not 1:
#
#     case shape                        mean    p=2    p=3    p=4     max
#     one novel pair among 3 routine   0.287  0.502  0.630  0.707   1.000
#     two novel, two routine           0.525  0.708  0.794  0.841   1.000
#     all routine                      0.047  0.047  0.047  0.047   0.050
#     all novel                        1.000  1.000  1.000  1.000   1.000
#
# The arithmetic mean buries a never-before-seen pair among three routine ones
# at 0.29, and that pair may be the entire reason the case is worth reading.
# `max` fails the other way: any single new pairing declares the whole case
# novel at 1.0, and the multiplier then never discounts anything. Powers 2 and 4
# both work; 3 was chosen for sitting nearest the middle of the useful range.
#
# This is a tuned choice that reads like an arbitrary one, and the obvious
# "simplification" back to a plain mean silently removes the behaviour the
# aggregation exists for. The reasoning is more fragile than the code.
SURPRISE_AGGREGATION_POWER = 3.0

# Key: (source, client, host, rule_a, rule_b) with the rules sorted. Scoped to
# the same partition cases are, so familiarity learned about one client's estate
# never speaks for another's.
PairKey = tuple[str, str, str, str, str]


def _pairs(rules: Iterable[str]) -> list[tuple[str, str]]:
    """Every unordered pair of distinct rules, sorted so a pair has one name."""
    unique = sorted({str(rule) for rule in rules if str(rule or "").strip()})
    return [(a, b) for index, a in enumerate(unique) for b in unique[index + 1 :]]


@dataclass(frozen=True)
class PairBaseline:
    """
    What the platform has learned, and how much it has had to learn from.

    The maturity fields are not diagnostics — they are the difference between
    "this pairing is genuinely novel" and "nothing has been observed yet", which
    produce the identical multiplier of 1.0. Without them a cold baseline reads
    as a feature that does nothing, and the first person to look concludes the
    multiplier is broken rather than young.
    """

    pairs: dict[PairKey, set[date]]
    window_days: int
    runs_considered: int
    observed_days: int

    @property
    def distinct_pairs(self) -> int:
        return len(self.pairs)

    @property
    def pairs_with_history(self) -> int:
        """Pairs seen on more than one day — the only ones that can discount."""
        return sum(1 for days in self.pairs.values() if len(days) > 1)

    @property
    def is_mature(self) -> bool:
        """
        Whether any case could be discounted at all.

        A pair seen on exactly one day discounts nothing once that day is
        excluded as the case's own, so a baseline of only single-day pairs
        cannot lower any score however many pairs it holds.
        """
        return self.pairs_with_history > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_days": self.window_days,
            "runs_considered": self.runs_considered,
            "observed_days": self.observed_days,
            "distinct_pairs": self.distinct_pairs,
            "pairs_with_history": self.pairs_with_history,
            "mature": self.is_mature,
            "note": (
                None
                if self.is_mature
                else (
                    "No rule pairing has yet been seen on more than one day, so every "
                    "pairing reads as novel and the familiarity multiplier is 1.0 "
                    "everywhere. That is a young baseline, not a disabled one — it "
                    "discounts as repeat pairings accumulate."
                )
            ),
        }


async def build_pair_baseline(
    db: AsyncSession, *, days: int = SURPRISE_BASELINE_DAYS
) -> PairBaseline:
    """
    For each rule pair on each host, the days both rules fired there.

    Days rather than raw counts on purpose. The question is "is this pairing a
    thing on this host", not "how loud was it" — a pair that fires forty times
    in one afternoon is one afternoon's worth of evidence that it is normal, and
    counting the forty would let a single noisy day look like a month of habit.

    Read from event time, so a replayed alert lands on the day it happened
    rather than the day it arrived.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))

    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.alert_source,
                AlertBodyInvestigationRun.alert_client,
                AlertBodyInvestigationRun.entity_host,
                AlertBodyInvestigationRun.alert_kind,
                AlertBodyInvestigationRun.detection_rule_id,
                AlertBodyInvestigationRun.detection_rule_name,
                AlertBodyInvestigationRun.event_time,
                AlertBodyInvestigationRun.created_at,
            ).where(
                AlertBodyInvestigationRun.created_at >= cutoff,
                AlertBodyInvestigationRun.entity_host.isnot(None),
            )
        )
    ).all()

    # (scope, day) → the rules that fired there, so pairs are formed per day.
    per_day: dict[tuple[str, str, str, date], set[str]] = defaultdict(set)
    for row in rows:
        # An incident is already a session; its rules are not this host's
        # habits, and counting them would teach the baseline about a summary.
        if str(row.alert_kind or "alert") == "incident":
            continue
        rule = str(row.detection_rule_id or row.detection_rule_name or "").strip()
        if not rule:
            continue
        when = row.event_time or row.created_at
        if when is None:
            continue
        per_day[(
            str(row.alert_source or UNKNOWN_SOURCE),
            str(row.alert_client or UNKNOWN_CLIENT),
            str(row.entity_host),
            when.date(),
        )].add(rule)

    baseline: dict[PairKey, set[date]] = defaultdict(set)
    for (source, client, host, day), rules in per_day.items():
        for rule_a, rule_b in _pairs(rules):
            baseline[(source, client, host, rule_a, rule_b)].add(day)

    result = PairBaseline(
        pairs=dict(baseline),
        window_days=days,
        runs_considered=len(rows),
        observed_days=len({day for (_s, _c, _h, day) in per_day}),
    )
    logger.debug(
        "Pair baseline: %d pairs (%d with history) from %d runs over %d days",
        result.distinct_pairs, result.pairs_with_history, result.runs_considered, days,
    )
    return result


def pair_surprise(cooccurrence_days: int) -> float:
    """
    How unexpected one pairing is on one host: 1 / (1 + days seen together).

    Never seen before scores 1.0. Seen once, 0.5. Seen every day for a month,
    0.03 — which the aggregate floor then lifts, because a discount is not the
    same as a silence.
    """
    return 1.0 / (1.0 + max(0, int(cooccurrence_days)))


def aggregate_surprise(surprises: list[float]) -> float:
    """
    One multiplier in [SURPRISE_FLOOR, 1.0] from the case's pair surprises.

    A generalised mean rather than an arithmetic one. The arithmetic mean lets
    three routine pairings bury the one that has never happened before, and that
    pairing may be the entire reason the case is worth reading; `max` goes too
    far the other way and lets any single new pairing declare the whole case
    novel. The exponent puts the answer between them, nearer the surprising end.
    """
    values = [min(1.0, max(0.0, float(value))) for value in surprises]
    if not values:
        # No pairs means one rule, which cannot form a case at all. Neutral
        # rather than zero: this is an absence of evidence about familiarity,
        # not evidence of familiarity.
        return 1.0
    power = SURPRISE_AGGREGATION_POWER
    mean = sum(value ** power for value in values) / len(values)
    return max(SURPRISE_FLOOR, min(1.0, mean ** (1.0 / power)))


def case_surprise(
    baseline: dict[PairKey, set[date]],
    *,
    source: str,
    client: str,
    host: str,
    rules: Iterable[str],
    own_days: set[date],
) -> tuple[float, list[dict[str, Any]]]:
    """
    The multiplier for one case, and the per-pair working behind it.

    The case's own days are subtracted from every pair's history before counting.
    Without that a case is measured partly against itself — the alerts being
    scored are in the baseline they are scored against, so a burst of activity
    would quietly make itself look familiar, and the more alerts an incident
    generated the less surprising it would appear.
    """
    detail: list[dict[str, Any]] = []
    surprises: list[float] = []

    for rule_a, rule_b in _pairs(rules):
        seen = baseline.get((source, client, host, rule_a, rule_b), set())
        prior_days = len(seen - own_days)
        value = pair_surprise(prior_days)
        surprises.append(value)
        detail.append(
            {
                "rules": [rule_a, rule_b],
                "cooccurrence_days": prior_days,
                "surprise": round(value, 3),
            }
        )

    detail.sort(key=lambda item: -item["surprise"])
    return aggregate_surprise(surprises), detail
