"""Which alerts on a host actually belong to the same case.

A case used to be every alert on one device, cut only where the clock showed a
quiet stretch. Nothing asked whether the alerts had anything to do with each
other, so a password change at 11:43, a system critical event at 17:44 and a
.NET crash at 18:56 were reported as one case — and the case page said three
independent detections "agree on this entity", which reads as corroboration
when it is co-location.

Measured over 11,359 alerts and 660 cases before this existed:

  * 277 cases held more than one alert; 182 of those were the same detection
    repeated, which is a real case and stays one.
  * 95 mixed different detections. In 12% of those did every member share an
    indicator with another member. In the rest, at least one alert had nothing
    in common with the others but the device and the hour.
  * 55 cases (20%) were built by *chaining*: each consecutive gap stayed under
    six hours while the ends drifted up to 23.8 hours apart.

So membership is now a question about evidence. The session still bounds a
case in time — two things a week apart are not one incident whatever they
share — and inside that bound, alerts are grouped by what ties them together.

**What counts as a tie**

  the same detection      the obvious case: one rule firing repeatedly is one
                          story, and this is what keeps the 182 intact
  a shared indicator      the same address, domain, hash or URL in both alerts
  the same account        when the alert carries one, which today is rare

**What does not**

The device, because a case is already per-device: every member shares it by
construction. The same mistake, in the same codebase, made every retrieved log
event "relevant" and every tenant's alerts match "Manager: Siembiot".

An indicator carried across the estate, for the same reason one step out. In
this data `expertware.net` appears on 130 distinct hosts, `onenet.be` on 49, a
Microsoft schema URL on 47, an all-zero hash on 23. Letting those link alerts
would rebuild exactly the case this replaces. 1,984 of 2,185 distinct
indicator values appear on a single host, so the cut costs almost nothing: it
removes 19 values and keeps the rest.

The threshold is deliberately generous. A real campaign touching five machines
leaves its address on five hosts, and that must still link the alerts on each
one of them.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Iterable, Sequence

# An indicator on more than this many distinct devices is describing the
# estate rather than an incident. See the module docstring for the measured
# distribution behind the number.
UBIQUITY_HOST_LIMIT = 10

# Indicator values that are never evidence of anything, whatever they are
# attached to. Everything else environmental is caught by the host-spread rule
# rather than by a list, because a list is a thing nobody updates.
_NEVER_LINKS = frozenset({
    "0.0.0.0",
    "::",
    "127.0.0.1",
    "::1",
    "00000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256 of nothing
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5 of nothing
})


def _host_of(row: Any) -> str:
    return str(getattr(row, "entity_host", "") or "").casefold()


def ubiquitous_values(
    rows: Iterable[Any], indicators_of: Callable[[Any], Iterable[str]],
    *, limit: int = UBIQUITY_HOST_LIMIT,
) -> set[str]:
    """Indicator values that appear across too much of the estate to link.

    Counted in distinct devices rather than in alerts: a value on one busy host
    may be in a thousand alerts and still be the single most useful thing about
    that host, while a value on forty hosts is infrastructure however rarely
    each one mentions it.
    """
    spread: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        host = _host_of(row)
        for value in indicators_of(row):
            cleaned = str(value or "").strip().casefold()
            if cleaned:
                spread[cleaned].add(host)
    return {value for value, hosts in spread.items() if len(hosts) > limit}


def linking_signals(
    row: Any, indicators_of: Callable[[Any], Iterable[str]], *, ubiquitous: set[str],
) -> set[str]:
    """Everything this alert could be tied to another alert by.

    Namespaced, so a hostname that happens to equal a detection name cannot
    join two alerts that share nothing.
    """
    signals: set[str] = set()

    detection = (
        getattr(row, "detection_name", None)
        or getattr(row, "detection_rule_id", None)
        or getattr(row, "detection_rule_name", None)
    )
    if detection:
        signals.add(f"detection:{str(detection).strip().casefold()}")

    user = str(getattr(row, "entity_user", "") or "").strip().casefold()
    if user:
        # Both halves of DOMAIN\user: one alert may carry either spelling, and
        # treating them as different accounts splits a case that is one person.
        signals.add(f"user:{user}")
        if "\\" in user:
            signals.add(f"user:{user.split(chr(92), 1)[1]}")

    for value in indicators_of(row):
        cleaned = str(value or "").strip().casefold()
        if cleaned and cleaned not in ubiquitous and cleaned not in _NEVER_LINKS:
            signals.add(f"ioc:{cleaned}")

    return signals


def cluster_linked(
    members: Sequence[Any], indicators_of: Callable[[Any], Iterable[str]],
    *, ubiquitous: set[str],
) -> list[list[Any]]:
    """Split one session's alerts into groups that are actually tied together.

    Transitive by design: A shares a hash with B, B shares an address with C,
    so all three are one case. That is how an intrusion reads — the stages do
    not each carry every indicator — and it is the difference between this and
    merely requiring that every pair match.

    An alert that ties to nothing becomes a case of its own. That is the
    honest answer: it happened on the device, we have no evidence it belongs
    with anything else, and saying so is better than filing it beside
    something it has nothing to do with.

    Groups come back in the order their earliest member appears in `members`,
    so a caller that passed events in time order gets cases in time order.
    """
    if not members:
        return []

    parent = list(range(len(members)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # The lower index wins, so the representative of a group is always
            # its earliest member when `members` is in time order.
            parent[max(ra, rb)] = min(ra, rb)

    # Index by signal rather than comparing every pair: a session of 500 alerts
    # is 125,000 comparisons, and the answer is the same.
    seen: dict[str, int] = {}
    for index, row in enumerate(members):
        for signal in linking_signals(row, indicators_of, ubiquitous=ubiquitous):
            first = seen.setdefault(signal, index)
            if first != index:
                union(first, index)

    groups: dict[int, list[Any]] = defaultdict(list)
    for index, row in enumerate(members):
        groups[find(index)].append(row)
    return [groups[root] for root in sorted(groups)]


async def ubiquitous_values_across_estate(
    db: Any, *, since: Any, limit: int = UBIQUITY_HOST_LIMIT,
) -> set[str]:
    """The estate-wide indicator spread, as one aggregate query.

    Whether an indicator describes the estate or an incident is a property of
    the estate, never of the rows a particular pass happened to fetch. Counting
    it from those rows made the answer depend on the question: a pass narrowed
    to one host saw every value on exactly one host, so nothing was ever
    ubiquitous, the linking changed, and the same host produced 12 cases
    scoped and 34 unscoped — only 2 of them the same case.

    Cheap now that the values are a column: one GROUP BY over `ioc_values`
    rather than a scan of every alert's JSON.
    """
    from sqlalchemy import text as _text

    rows = await db.execute(
        _text(
            """
            SELECT lower(value) AS value
            FROM alert_body_investigation_runs r,
                 LATERAL unnest(coalesce(r.ioc_values, ARRAY[]::text[])) AS value
            WHERE r.entity_host IS NOT NULL
              AND coalesce(r.event_time, r.created_at) >= :since
            GROUP BY lower(value)
            HAVING count(DISTINCT r.entity_host) > :limit
            """
        ),
        {"since": since, "limit": int(limit)},
    )
    return {row[0] for row in rows.all() if row[0]}
