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
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun
from app.services.alert_field_service import UNKNOWN_CLIENT, UNKNOWN_SOURCE

logger = logging.getLogger(__name__)

# How far back familiarity is learned from. Long enough that a weekly job is
# seen four times and reads as routine; short enough that an estate which
# changed two months ago is not still being judged against its old self.
SURPRISE_BASELINE_DAYS = 30

# The multiplier can never reach zero. A pure 1/(1+n) drives a pair seen fifty
# times to 0.02 and would erase any case built on familiar rules — but "boring
# rules in an alarming sequence" is a real attack shape, and an attacker using
# the tools already on the box produces exactly it. The floor is what keeps that
# case visible: heavily discounted, never silenced.
SURPRISE_FLOOR = 0.10

# Generalised mean exponent, sitting between the arithmetic mean (1) and the
# maximum (infinity). At 3, one never-before-seen pair among three routine ones
# lifts the case to 0.63 rather than being averaged to 0.29 — the novel pair may
# be the entire signal — while still not reaching the 1.0 that `max` would give,
# which would let a single new pairing wipe out everything known about the rest.
SURPRISE_AGGREGATION_POWER = 3.0

# Key: (source, client, host, rule_a, rule_b) with the rules sorted. Scoped to
# the same partition cases are, so familiarity learned about one client's estate
# never speaks for another's.
PairKey = tuple[str, str, str, str, str]


def _pairs(rules: Iterable[str]) -> list[tuple[str, str]]:
    """Every unordered pair of distinct rules, sorted so a pair has one name."""
    unique = sorted({str(rule) for rule in rules if str(rule or "").strip()})
    return [(a, b) for index, a in enumerate(unique) for b in unique[index + 1 :]]


async def build_pair_baseline(
    db: AsyncSession, *, days: int = SURPRISE_BASELINE_DAYS
) -> dict[PairKey, set[date]]:
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

    logger.debug("Pair baseline: %d pairs over %d days", len(baseline), days)
    return baseline


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
