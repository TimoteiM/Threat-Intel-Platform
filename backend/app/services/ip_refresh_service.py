"""Which stored IP verdicts are old enough to be worth asking again.

The cache policy set when `ip_lookups` was first read said: no refresh path
until we know how often a stale verdict is actually *hit*. A month of logging
answered it, though not with the number that was first reported.

Measured 2026-10-12, and the first three attempts measured the wrong thing
each time, which is why all four are written down:

    63.9% of rows      Wrong unit. `ip_lookups` is append-only history: 6,376
                       rows over 1,535 addresses, one address holding 186. A
                       row count describes the archive, not any answer read.

    57.9% of reads     Still wrong — computed by joining mentions to *rows*,
                       so an address with 186 rows counted 186 times.

    53.4% of addresses Right unit, wrong population: it counts addresses
                       nobody looks at alongside ones on every case page.

    What is read       Of 133 draws of public addresses in case graphs, 24
                       are of a verdict over 30 days old (18.0%). Of 6,334
                       `ioc_values` mentions, 52.7% are.

So the refresh is worth building, and the honest justification is the second
population rather than the panel: the panel's public addresses are all covered
and mostly current. 800 routable addresses have a stale newest verdict, median
56 days old and oldest 68 — none from March, though March *rows* exist, for
addresses that have been looked up again since.

What this deliberately does not do:

  * It does not touch private or reserved addresses. 1,040 of the 1,173 `ip`
    nodes drawn in case graphs are RFC1918 and similar, no feed has an opinion
    about them, and spending an AbuseIPDB check on 10.1.1.4 would buy nothing.

  * It does not update rows. The table is history by design, and the verdict
    from August is how we know what was believed in August. A refresh appends.

  * It does not fix ThreatFox. That has failed on every row ever written and
    will fail on these too; `indicator_enrichment_service` reports it as
    `check_failed` either way. A refreshed row is not a complete row, and
    reading one as "now fully checked" would be the same sentinel bug in a
    newer timestamp.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

#: Matches `indicator_enrichment_service.STALE_AFTER`. The panel marks a
#: verdict old at 30 days; refreshing on a different threshold would mean the
#: badge and the refresh disagreed about the same word.
STALE_AFTER = timedelta(days=30)

#: Addresses per run. AbuseIPDB allows 1,000 checks a day on each configured
#: key and `abuseipdb_get` walks every key, so this is a small fraction of one
#: key's budget and leaves the rest for interactive lookups, which a person is
#: waiting on and this is not. At 150 a day the 800 now due drain in under a
#: week, after which the daily arrival is whatever ages past 30 days.
PER_RUN = 150

_DUE_SQL = """
with newest as (
    select distinct on (ip) ip, queried_at
    from ip_lookups
    order by ip, queried_at desc
),
drawn as (
    select label as value, count(*) as n
    from alert_graph_entity where kind = 'ip' group by label
),
mentioned as (
    select v as value, count(*) as n
    from alert_body_investigation_runs r,
         lateral unnest(coalesce(r.ioc_values, array[]::text[])) v
    group by v
)
select coalesce(d.value, m.value) as value,
       coalesce(d.n, 0) as draws,
       coalesce(m.n, 0) as mentions,
       nw.queried_at
from drawn d
full outer join mentioned m on m.value = d.value
join newest nw on nw.ip = coalesce(d.value, m.value)
where nw.queried_at < :cutoff
"""


@dataclass(frozen=True)
class Due:
    value: str
    draws: int
    mentions: int
    queried_at: datetime
    age_days: int


@dataclass(frozen=True)
class Selection:
    """What a run should refresh, and what it is leaving behind.

    `skipped_for_cap` exists because a bounded slice of an ordered list that
    reports only its own length reads as "that was all of them". This project
    has shipped that bug on alert members and on case membership at close, and
    the fix both times was to carry the remainder rather than the slice.
    """

    due: list[Due]
    skipped_for_cap: int
    not_routable: int

    @property
    def total_due(self) -> int:
        return len(self.due) + self.skipped_for_cap


def _routable(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def select(rows, *, now: datetime, limit: int = PER_RUN) -> Selection:
    """Order the due addresses by what refreshing them would be worth.

    Drawn in a case graph first: those are the verdicts an analyst reads on a
    page. Then by how often the address is referenced at all, then by age. An
    address nobody looks at is still refreshed eventually, but it does not
    take a quota slot from one on a case page.
    """
    candidates: list[Due] = []
    not_routable = 0
    for row in rows:
        value = str(row.value or "").strip()
        if not _routable(value):
            not_routable += 1
            continue
        stamp = row.queried_at
        if stamp is not None and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        candidates.append(
            Due(
                value=value,
                draws=int(row.draws or 0),
                mentions=int(row.mentions or 0),
                queried_at=stamp,
                age_days=(now - stamp).days if stamp else 0,
            )
        )

    candidates.sort(key=lambda d: (-(d.draws > 0), -d.draws, -d.mentions, -d.age_days))
    return Selection(
        due=candidates[:limit],
        skipped_for_cap=max(0, len(candidates) - limit),
        not_routable=not_routable,
    )


def due_sql_params(now: datetime) -> dict:
    return {"cutoff": now - STALE_AFTER}


async def due(db, *, now: datetime | None = None, limit: int = PER_RUN) -> Selection:
    """The async read, for the CLI and for tests against the live database."""
    now = now or datetime.now(timezone.utc)
    rows = (await db.execute(text(_DUE_SQL), due_sql_params(now))).all()
    return select(rows, now=now, limit=limit)
