"""Two case keys over one incident.

Cases #9 and #1440 are the same eight alerts on `EXP-FIN-034.corp.local`,
opened the same minute, both resolved true positive. They are two rows because
the case key is derived from the alerts in a window, and the same cluster
re-anchors under a different key when the window moves — which is why a case
found over "All" need not re-form over 720 hours.

Detection is on the **alert-ID set**, not on host plus opening minute. Host and
minute are properties two genuinely separate incidents can share: a noisy rule
firing on one machine opens cases all day, and 59.1% of this estate's cases
hold a single alert, so a host-and-minute rule would merge unrelated cases
every time two alerts landed in the same sixty seconds. The alert set is the
incident; if two keys cover the same alerts, there is one incident.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

#: How much of two cases' alerts must coincide before they are called one
#: incident. Not 1.0: a late arrival can join one key and not the other, and
#: an incident that is 95% the same alerts is the same incident. Not lower
#: either — at 0.5 a big case swallows a small one that merely overlaps it.
SAME_INCIDENT = 0.9


@dataclass(frozen=True)
class Collision:
    """One incident, found under several keys."""
    case_numbers: tuple[int | None, ...]
    case_keys: tuple[str, ...]
    alerts: int
    overlap: float


def _alert_ids(case: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        str(a.get("run_id"))
        for a in (case.get("alerts") or [])
        if a.get("run_id")
    )


def _overlap(a: frozenset[str], b: frozenset[str]) -> float:
    """Jaccard. Symmetric, so neither case is privileged, and it falls off
    when one set is much larger — which is what stops a 1,889-alert bucket
    absorbing every small case that happens to sit inside it."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def detect(cases: Sequence[dict[str, Any]]) -> list[Collision]:
    """Groups of cases covering one incident.

    Note the caveat this inherits: the correlation service caps a case's
    member list at 100 alerts while reporting the true count separately, so
    two cases of more than 100 alerts are compared on their first 100. For the
    24 cases in this estate above that size the comparison is partial, and
    `alerts` below reports what was actually compared rather than the case's
    full size.
    """
    sets = [(case, _alert_ids(case)) for case in cases]
    sets = [(case, ids) for case, ids in sets if ids]

    # Index by a member alert, so this is near-linear rather than comparing
    # every case against every other: two cases can only collide if they share
    # at least one alert.
    by_alert: dict[str, list[int]] = {}
    for index, (_case, ids) in enumerate(sets):
        for alert_id in ids:
            by_alert.setdefault(alert_id, []).append(index)

    parent = list(range(len(sets)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        a, b = find(i), find(j)
        if a != b:
            parent[max(a, b)] = min(a, b)

    checked: set[tuple[int, int]] = set()
    scores: dict[tuple[int, int], float] = {}
    for candidates in by_alert.values():
        for i in candidates:
            for j in candidates:
                if i >= j or (i, j) in checked:
                    continue
                checked.add((i, j))
                score = _overlap(sets[i][1], sets[j][1])
                if score >= SAME_INCIDENT:
                    scores[(i, j)] = score
                    union(i, j)

    groups: dict[int, list[int]] = {}
    for index in range(len(sets)):
        groups.setdefault(find(index), []).append(index)

    out: list[Collision] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        pair_scores = [
            score for (i, j), score in scores.items()
            if i in members and j in members
        ]
        ordered = sorted(
            members,
            key=lambda i: (sets[i][0].get("case_number") is None,
                           sets[i][0].get("case_number") or 0),
        )
        out.append(
            Collision(
                case_numbers=tuple(sets[i][0].get("case_number") for i in ordered),
                case_keys=tuple(str(sets[i][0].get("case_key")) for i in ordered),
                alerts=len(sets[ordered[0]][1]),
                overlap=min(pair_scores) if pair_scores else 1.0,
            )
        )
    return sorted(out, key=lambda c: (c.case_numbers[0] or 0))


def collision_for(
    case_key: str, cases: Sequence[dict[str, Any]]
) -> Collision | None:
    """The collision this case takes part in, if any."""
    for collision in detect(cases):
        if case_key in collision.case_keys:
            return collision
    return None


def as_payload(collision: Collision | None, *, case_key: str) -> dict[str, Any] | None:
    """What the graph carries, so one incident renders once and says so."""
    if collision is None:
        return None
    others = [
        {"case_key": key, "case_number": number}
        for key, number in zip(collision.case_keys, collision.case_numbers)
        if key != case_key
    ]
    return {
        "same_incident_as": others,
        "alerts_compared": collision.alerts,
        "overlap": round(collision.overlap, 3),
        "note": (
            "This incident exists under "
            f"{len(collision.case_keys)} case keys covering the same alerts. "
            "A case key is derived from its alerts in a window, so the same "
            "cluster re-anchors under a new key when the window moves. One "
            "incident is drawn here, carrying every key."
        ),
    }


def metric(collisions: Iterable[Collision]) -> dict[str, Any]:
    """The number worth watching: how much of the case list is duplicates."""
    found = list(collisions)
    duplicate_rows = sum(len(c.case_keys) - 1 for c in found)
    return {
        "incidents_with_several_keys": len(found),
        "surplus_case_rows": duplicate_rows,
        "largest_group": max((len(c.case_keys) for c in found), default=0),
    }


# --- the other half: keys that no longer re-derive at all ------------------
#
# Measured before writing this. Cases #9 and #1440 are not two live cases: of
# 1,880 spine rows only 1,002 still re-derive, and #9 is one of the 878 that
# do not. So the alert-set match above — which is the right test, and which
# correctly finds nothing among live cases, because within one derivation an
# alert belongs to exactly one case — cannot see this pair at all. A key that
# does not re-derive has no alert set to compare.
#
# 683 of those dead keys (36.3% of the whole case list) sit on the same host,
# within two minutes of a live case's opening, carrying the same closing alert
# count. 673 of them are false positives; exactly one is a true positive, and
# that one is #9.
#
# This test is deliberately labelled weaker than the one above and reported
# separately. Host, minute and count are properties two separate incidents can
# share, which is why they are not allowed to merge two *live* cases. They are
# admissible for attaching a dead key to a live one, because a key that cannot
# be re-derived is not an independent incident competing for those alerts — but
# it is an inference, not a proof, and the payload says so.

from sqlalchemy import text as _sql_text  # noqa: E402

SHADOW_WINDOW_SECONDS = 120


async def shadowing_keys(
    db: Any, *, case_key: str, entity_host: str | None, opened_at: Any,
    alert_count: int | None,
) -> list[dict[str, Any]]:
    """Spine rows for this incident whose keys no longer re-derive."""
    if not entity_host or opened_at is None:
        return []
    rows = (
        await db.execute(
            _sql_text(
                """
                select case_number, case_key, resolution, closed_at, opened_at
                from alert_case_spine
                where entity_host = :host
                  and case_key <> :key
                  and abs(extract(epoch from (opened_at - :opened))) <= :window
                  and coalesce(alerts_at_close, -1) = coalesce(:n, -1)
                order by case_number
                """
            ),
            {
                "host": entity_host, "key": case_key, "opened": opened_at,
                "window": SHADOW_WINDOW_SECONDS, "n": alert_count,
            },
        )
    ).all()
    return [
        {
            "case_number": number,
            "case_key": key,
            "resolution": resolution,
            "closed_at": closed.isoformat() if closed else None,
        }
        for number, key, resolution, closed, _opened in rows
    ]


def shadow_payload(shadows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """What the graph carries for keys it matched on the weaker signal."""
    if not shadows:
        return None
    return {
        "also_known_as": shadows,
        "matched_on": "host, opening time within 120s, and closing alert count",
        "note": (
            "This incident also exists under "
            f"{len(shadows)} earlier case {'key' if len(shadows) == 1 else 'keys'} "
            "that can no longer be re-derived, so there is no alert set to "
            "compare and the match is by host, opening time and alert count "
            "rather than by alerts. 878 of this estate's 1,880 case rows no "
            "longer re-derive; treat the link as likely, not established."
        ),
    }
