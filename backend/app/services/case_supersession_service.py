"""Reconnecting case rows whose key no longer re-derives.

A case key is a hash of (source, client, host, first event time, and a
discriminator). Change any input and every stored row keyed under the old
formula stops resolving — the case still exists, its alerts still exist, but
nothing can reach it.

That happened on 2026-10-07. Measured over 1,887 spine rows:

    rows written before 2026-10-06      86    100% dead
    rows written on 2026-10-07         945    705 dead (74.6%)
    rows written on 2026-10-08         803     77 dead (9.6%)

880 dead rows in total. 855 of them still have their alerts in the store and
811 carry a written AI analysis, so what is stranded is not empty rows — it is
811 investigations nothing can open. One is resolved true positive: case #9,
which is the other half of the #9/#1440 pair that has been open since the
Phase 1 review.

What this does and does not do
------------------------------
It writes a pointer from the dead row to the live one and nothing else. It
does not copy resolutions or narratives onto live rows: a resolution recorded
under one key is a judgement about that key's alerts, and overwriting a live
case's own judgement with it would be rewriting a conclusion rather than
recovering one. The earlier analysis is surfaced through the live case
attributed and dated instead.

It never guesses. A dead row that does not resolve to exactly one candidate
keeps every candidate and is marked ambiguous, because a wrong pointer
silently attributes one incident's analysis to another — which is worse than
no pointer at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

#: How far apart two records of the same incident's opening may sit. The
#: derived opening is the first alert's event time and the stored one was
#: written when the case was first seen, so they agree closely but not exactly.
OPEN_TOLERANCE = timedelta(seconds=120)

MAPPED = "mapped"
AMBIGUOUS = "ambiguous"
TARGET_UNKNOWN = "target_unknown"
EXPIRED = "expired"
#: The platform already recorded where this case went, at the time it went
#: there. That pointer is contemporaneous evidence from the code that performed
#: the merge, and it outranks anything this migration can infer from
#: timestamps afterwards — so these rows are reported, not re-decided.
ALREADY_MERGED = "merged"


@dataclass
class DeadRow:
    case_key: str
    case_number: int | None
    entity_host: str
    opened_at: datetime
    alerts_at_close: int | None
    resolution: str | None
    closed_at: datetime | None
    has_analysis: bool
    alerts_still_present: bool
    closure_kind: str | None = None
    #: A pointer the platform wrote itself when it merged this case.
    existing_pointer: str | None = None

    @property
    def counted_its_alerts(self) -> bool:
        """Whether `alerts_at_close` is a count or a blank.

        Zero is a blank. Measured across the whole spine: every row holding 0
        has a `closure_kind` of `expired` (149) or `unreadable` (25) — the
        case was closed *because* it could not be read back, so it never
        counted anything. Reading 0 as "this case had no alerts" rejected 209
        otherwise-unambiguous matches, each of which had exactly one candidate
        agreeing to the microsecond.
        """
        return self.alerts_at_close is not None and self.alerts_at_close > 0


@dataclass
class LiveCase:
    case_key: str
    case_number: int | None
    entity_host: str
    first_event_at: datetime | None
    alert_count: int


@dataclass
class Decision:
    dead: DeadRow
    state: str
    target: LiveCase | None = None
    candidates: list[LiveCase] = dc_field(default_factory=list)
    reason: str = ""

    def evidence(self) -> dict[str, Any]:
        """Why this decision, in terms a person can check against the data."""
        return {
            "dead_case": self.dead.case_number,
            "host": self.dead.entity_host,
            "dead_opened_at": self.dead.opened_at.isoformat(),
            "dead_alerts_at_close": self.dead.alerts_at_close,
            "state": self.state,
            "target_case": self.target.case_number if self.target else None,
            "target_first_event_at": (
                self.target.first_event_at.isoformat()
                if self.target and self.target.first_event_at
                else None
            ),
            "target_alert_count": self.target.alert_count if self.target else None,
            "seconds_apart": (
                round(
                    abs(
                        (self.dead.opened_at - self.target.first_event_at).total_seconds()
                    ),
                    1,
                )
                if self.target and self.target.first_event_at
                else None
            ),
            "candidates": [c.case_number for c in self.candidates],
            "reason": self.reason,
        }


def decide(dead: DeadRow, live: Sequence[LiveCase]) -> Decision:
    """Which live case, if any, this dead row is the same incident as."""
    if dead.existing_pointer:
        # Measured: all 13 rows in this state carry `closure_kind` of `merged`
        # or `auto`, so the pointer was written by the merge logic as it ran.
        # Overriding that with a timestamp heuristic would replace a record of
        # what happened with a guess about what probably happened.
        target = next(
            (case for case in live if case.case_key == dead.existing_pointer), None
        )
        return Decision(
            dead=dead,
            state=ALREADY_MERGED,
            target=target,
            candidates=[target] if target else [],
            reason=(
                "This case was merged into another at the time, and that pointer "
                "was written by the merge itself. "
                + (
                    f"It leads to case #{target.case_number}, which still derives."
                    if target
                    else "Its target no longer derives either, so the trail "
                    "continues through that row rather than ending here."
                )
            ),
        )
    if not dead.alerts_still_present:
        return Decision(
            dead=dead,
            state=EXPIRED,
            reason=(
                "No alerts remain in the store around this case's opening, so "
                "there is nothing left to re-derive it from. Its analysis is "
                "kept and the case is marked expired rather than missing."
            ),
        )

    nearby = [
        case
        for case in live
        if case.entity_host == dead.entity_host
        and case.first_event_at is not None
        and abs(dead.opened_at - case.first_event_at) <= OPEN_TOLERANCE
    ]
    if not nearby:
        return Decision(
            dead=dead,
            state=TARGET_UNKNOWN,
            reason=(
                "This case's alerts are still stored, but no case derives from "
                f"{dead.entity_host} at that moment any more — the cluster they "
                "formed has re-grouped under a shape this cannot identify."
            ),
        )

    # Exact timestamp identity first, because `opened_at` was copied from the
    # first alert's event time and that time is itself an input to the key. A
    # candidate whose first alert carries this row's opening moment to the
    # microsecond *is* the same first alert; two different clusters on one host
    # starting in the same microsecond is not a thing that happens.
    #
    # The count is the tiebreak, not the test. It was wrong to require it:
    # `alerts_at_close` was capped at 100 by the old member-list limit, and a
    # cluster that closed on three alerts derives five today because two more
    # arrived afterwards. Demanding equality rejected 76 rows that had exactly
    # one candidate agreeing to the microsecond.
    identical = [case for case in nearby if case.first_event_at == dead.opened_at]

    def drift_note(target: LiveCase) -> str:
        if not dead.counted_its_alerts:
            return (
                f" This row closed as {dead.closure_kind or 'unreadable'} without "
                "ever counting its alerts, so no count was available to check."
            )
        if target.alert_count == dead.alerts_at_close:
            return f" It holds the same {target.alert_count} alerts."
        return (
            f" It holds {target.alert_count} alerts against this row's "
            f"{dead.alerts_at_close}"
            + (
                " — the old member list capped at 100, so this row's count is a"
                " floor rather than a total."
                if dead.alerts_at_close == 100
                else " — alerts joined the cluster after this row closed."
            )
        )

    if len(identical) == 1:
        target = identical[0]
        return Decision(
            dead=dead, state=MAPPED, target=target, candidates=nearby,
            reason=(
                f"One case derives from {dead.entity_host} whose first alert "
                "carries this row's opening timestamp to the microsecond."
                + drift_note(target)
            ),
        )

    pool = identical or nearby
    if dead.counted_its_alerts:
        by_count = [c for c in pool if c.alert_count == dead.alerts_at_close]
        if len(by_count) == 1:
            target = by_count[0]
            return Decision(
                dead=dead, state=MAPPED, target=target, candidates=nearby,
                reason=(
                    f"{len(pool)} candidates on {dead.entity_host} share this "
                    f"row's opening moment, and one holds its "
                    f"{dead.alerts_at_close} alerts."
                ),
            )

    return Decision(
        dead=dead, state=AMBIGUOUS, candidates=nearby,
        reason=(
            f"{len(nearby)} case(s) derive from {dead.entity_host} near this "
            f"row's opening and {len(identical)} carry its exact timestamp"
            + (
                f"; {sum(1 for c in pool if c.alert_count == dead.alerts_at_close)} "
                f"hold its {dead.alerts_at_close} alerts."
                if dead.counted_its_alerts
                else ", and it never counted its alerts."
            )
            + " Pointing at one would attribute this analysis to an incident it"
            " may not describe, so every candidate is kept."
        ),
    )


def plan(dead_rows: Iterable[DeadRow], live: Sequence[LiveCase]) -> list[Decision]:
    """Every decision, in case order."""
    by_host: dict[str, list[LiveCase]] = {}
    for case in live:
        by_host.setdefault(case.entity_host, []).append(case)
    return [
        decide(row, by_host.get(row.entity_host, []))
        for row in sorted(dead_rows, key=lambda r: (r.case_number or 0))
    ]


def summarise(decisions: Sequence[Decision]) -> dict[str, int]:
    out: dict[str, int] = {
        MAPPED: 0, ALREADY_MERGED: 0, AMBIGUOUS: 0, TARGET_UNKNOWN: 0, EXPIRED: 0,
    }
    for decision in decisions:
        out[decision.state] = out.get(decision.state, 0) + 1
    out["carrying_analysis"] = sum(1 for d in decisions if d.dead.has_analysis)
    out["true_positive"] = sum(
        1 for d in decisions if (d.dead.resolution or "") == "true_positive"
    )
    return out


# --- what the UI needs ------------------------------------------------------

_SUPERSESSION_SQL = """
select s.case_number, s.case_key, s.supersession_state, s.supersession_note,
       s.supersession_candidates, s.resolution, s.closed_at, s.closed_by,
       s.narrative_markdown is not null as has_analysis,
       t.case_number as target_number, t.case_key as target_key,
       t.supersession_state as target_state
from alert_case_spine s
left join alert_case_spine t on t.case_key = s.superseded_by_case_key
where s.case_key = :key
"""

_EARLIER_SQL = """
select s.case_number, s.case_key, s.resolution, s.closed_at, s.closed_by,
       s.supersession_state, s.narrative_markdown
from alert_case_spine s
where s.superseded_by_case_key = :key
  and s.supersession_state in ('mapped', 'merged')
order by s.closed_at nulls last, s.case_number
"""


async def where_this_key_went(db: Any, case_key: str) -> dict[str, Any] | None:
    """For a key that no longer derives: what became of it.

    Returned instead of an empty graph, so a dead key redirects rather than
    rendering nothing. 842 of this estate's 1,889 case rows are in this state.
    """
    from sqlalchemy import text as _text

    row = (await db.execute(_text(_SUPERSESSION_SQL), {"key": case_key})).first()
    if row is None or row.supersession_state is None:
        return None
    candidates = (row.supersession_candidates or {}).get("candidates") or []
    return {
        "state": row.supersession_state,
        "note": row.supersession_note,
        "continues_as": (
            {"case_key": row.target_key, "case_number": row.target_number}
            if row.target_key and row.target_state is None
            else None
        ),
        # A pointer into another dead row: the trail continues, and saying so
        # beats presenting a link that lands on another empty page.
        "chains_through": (
            {"case_key": row.target_key, "case_number": row.target_number}
            if row.target_key and row.target_state is not None
            else None
        ),
        "candidates": candidates,
        "this_row": {
            "case_number": row.case_number,
            "resolution": row.resolution,
            "closed_at": row.closed_at.isoformat() if row.closed_at else None,
            "closed_by": row.closed_by,
            "has_analysis": bool(row.has_analysis),
        },
    }


async def earlier_keys_for(db: Any, case_key: str) -> list[dict[str, Any]]:
    """Analyses recorded under earlier keys for this same incident.

    Attributed and dated, and never merged into the live case's own verdict: a
    resolution recorded under one key is a judgement about that key's alerts,
    and overwriting a live conclusion with it would be rewriting one rather
    than recovering it. 741 live cases have at least one of these, and 785
    stranded analyses become reachable through them.
    """
    from sqlalchemy import text as _text

    rows = (await db.execute(_text(_EARLIER_SQL), {"key": case_key})).all()
    return [
        {
            "case_number": row.case_number,
            "case_key": row.case_key,
            "resolution": row.resolution,
            "closed_at": row.closed_at.isoformat() if row.closed_at else None,
            "closed_by": row.closed_by,
            "state": row.supersession_state,
            "narrative_markdown": row.narrative_markdown,
            "attribution": (
                f"An earlier key for this incident, case #{row.case_number}, "
                + (
                    f"recorded {row.closed_at.date().isoformat()}"
                    if row.closed_at
                    else "with no recorded closing date"
                )
                + (
                    f", concluded {str(row.resolution).replace('_', ' ')}."
                    if row.resolution
                    else ", recorded no conclusion."
                )
                + " This is that key's own judgement about its own alerts, not"
                " this case's."
            ),
        }
        for row in rows
    ]
