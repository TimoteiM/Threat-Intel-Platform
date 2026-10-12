"""What is known about an indicator, and what only looks known.

The graph draws addresses, domains, URLs and hashes. Two tables hold what was
found out about them, and they fail in different ways, so the panel has to
treat them differently rather than merging them into one "verdict".

Measured 2026-10-12 before building anything on them, then re-measured the
same day because the first pass counted the wrong things:

    ip_lookups      6,376 rows — but it is **append-only history**, 1,535
                    distinct addresses at 4.2 rows each, one address holding
                    186. So a count of rows is not a count of answers, and the
                    first figure here ("63.9% of rows older than 30 days") was
                    a statistic about the archive, not about anything read.
                    Per address, newest row only: 820 of 1,535 (53.4%).

                    Narrowed to what this panel actually draws —
                    `alert_graph_entity` where kind = 'ip' — the picture
                    changes again, and in the other direction:

                      133 draws of 84 public addresses, **every one covered**
                      1,040 draws of 407 private or reserved addresses,
                        none covered and none coverable
                      24 of the 133 public draws are over 30 days old (18.0%)

                    Coverage is not the problem here and never was; the
                    earlier "1,420 of 1,424 covered (99.7%)" was measured over
                    `alert_body_investigation_runs.ioc_values` — a different
                    population from the graph's nodes, and named in this
                    docstring as though `ioc_values` were a table of its own.
                    Age is a real but minority problem, on 24 draws.

    investigations  2,488 rows, and **no `ip` observable type exists at all**.
                    url 83.4% of distinct values, domain 35.9%, ip 0.0%. The
                    zero is structural, not a gap: this pipeline does not
                    investigate addresses. Saying "not investigated" for an IP
                    as though a record were missing would invite someone to go
                    looking for it.

And two enrichment sources inside `ip_lookups` are not equal:

    ThreatFox   `errors` records `ThreatFox: HTTPError` on **all 6,371 rows**,
                while `threatfox_count` reads 0 on every one. The count is a
                sentinel, not a measurement — the same shape as a feed failing
                6,259 times at debug level and surfacing as zero. Reported as
                `check_failed`, never as "no hits".

    AbuseIPDB   failed on 1,096 rows and stored **NULL**, not 0. So a 0 here
                is a real "not abusive", and 3,117 rows say it. This one got it
                right, and the difference is why they are read separately.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import (
    CHECK_FAILED,
    NEVER_OBSERVED,
    OUT_OF_SCOPE,
    UNCLASSIFIED,
    absent,
)

#: Past this, a stored verdict is shown with its age marked. Not discarded:
#: an old answer is still an answer, and the analyst decides what it is worth.
STALE_AFTER = timedelta(days=30)

#: Observable types `investigations` actually holds. Derived from the data
#: rather than declared, because the point of the check was that `ip` is
#: missing from it.
INVESTIGATED_TYPES = ("url", "domain", "hash")

#: `ip_lookups` is append-only history, so this has to say which row it wants.
#: It did not. `{str(r.ip): r for r in rows}` kept whichever row Postgres
#: happened to return last, which on 218 of 1,535 addresses (14.2%) was not
#: the newest. On 16 the stored abuse score differed, and on two of those the
#: pick inverted the distinction this whole module is built on: 57.141.20.61
#: was shown a confident `0` when the newest row holds NULL (the check
#: failed), and 44.204.162.73 was shown "AbuseIPDB did not answer" when the
#: newest row holds a real 0. The `investigations` read below picks the newest
#: explicitly; this one is the same table shape and did not.
_IP_SQL = """
select distinct on (ip)
       ip, abuse_score, isp, country_code, threatfox_count, result_json, queried_at
from ip_lookups where ip = any(:values)
order by ip, queried_at desc
"""

_INV_SQL = """
select lower(domain) as value, observable_type, state, classification, confidence,
       risk_score, recommended_action, created_at, concluded_at, id
from investigations where lower(domain) = any(:values)
"""


@dataclass(frozen=True)
class Enrichment:
    value: str
    kind: str
    #: Everything below is either a value or an `Absent`, never a silent zero.
    fields: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        def render(v: Any) -> Any:
            return v.as_json() if hasattr(v, "as_json") else v

        return {
            "value": self.value,
            "kind": self.kind,
            **{k: render(v) for k, v in self.fields.items()},
        }


def _stale(queried_at: datetime | None, now: datetime) -> dict[str, Any]:
    """The age of an answer, stated rather than hidden behind a freshness rule."""
    if queried_at is None:
        return {"queried_at": None, "age_days": None, "stale": None}
    stamp = queried_at if queried_at.tzinfo else queried_at.replace(tzinfo=timezone.utc)
    age = now - stamp
    return {
        # Verbatim, because "3 weeks ago" is a rounding of something exact.
        "queried_at": stamp.isoformat(),
        "age_days": age.days,
        "stale": age > STALE_AFTER,
    }


def _routable(value: str) -> bool:
    """Whether a reputation service could have an opinion about this address.

    Private, loopback, link-local and reserved space is 1,040 of the 1,173
    `ip` nodes this panel draws. No feed has ever been asked about them and
    none ever will be, so their absence is a different claim from a public
    address that was somehow missed — and the panel used to make the second
    claim about all of them.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
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


def _threatfox(row_json: Any) -> Any:
    """ThreatFox has not answered once. The count is a sentinel.

    The lookup itself now records *why* in `threatfox_status`, and that is
    preferred over anything reconstructed here: "no Auth-Key is configured"
    and "the feed was unreachable" are different facts about whose problem it
    is, and every row written before 2026-10-12 was the first one wearing the
    second one's clothes.
    """
    stored = (row_json or {}).get("threatfox_status")
    if isinstance(stored, dict) and stored.get("absent"):
        return stored
    errors = (row_json or {}).get("errors")
    errors = errors if isinstance(errors, list) else []
    if any("threatfox" in str(e).lower() for e in errors):
        return absent(
            CHECK_FAILED,
            "ThreatFox did not answer for this lookup, so nothing was checked "
            "against it. The stored count reads 0 for every address in this "
            "estate and means 'not asked', not 'no hits'.",
            raw=next((str(e) for e in errors if "threatfox" in str(e).lower()), None),
        )
    return (row_json or {}).get("threatfox") or []


async def enrich(
    db: AsyncSession, *, values: Iterable[tuple[str, str]], now: datetime | None = None
) -> dict[str, Enrichment]:
    """`[(value, kind)]` -> what is known about each, with absences named.

    `kind` is the graph's node kind: ip, domain, url, file.
    """
    now = now or datetime.now(timezone.utc)
    wanted = [(str(v).strip(), str(k)) for v, k in values if str(v).strip()]
    if not wanted:
        return {}

    ips = sorted({v for v, k in wanted if k == "ip"})
    others = sorted({v.lower() for v, k in wanted if k != "ip"})

    ip_rows = (
        (await db.execute(text(_IP_SQL), {"values": ips})).all() if ips else []
    )
    by_ip = {str(r.ip): r for r in ip_rows}
    inv_rows = (
        (await db.execute(text(_INV_SQL), {"values": others})).all() if others else []
    )
    by_value: dict[str, Any] = {}
    for row in inv_rows:
        # Newest conclusion wins; an earlier one is history, not the answer.
        prev = by_value.get(row.value)
        if prev is None or (row.concluded_at or row.created_at) > (
            prev.concluded_at or prev.created_at
        ):
            by_value[row.value] = row

    out: dict[str, Enrichment] = {}
    for value, kind in wanted:
        if kind == "ip":
            row = by_ip.get(value)
            if row is None:
                out[value] = Enrichment(value, kind, {
                    "looked_up": absent(
                        OUT_OF_SCOPE,
                        "This is a private or reserved address, so no "
                        "reputation service has an opinion about it and none "
                        "was asked. Its meaning comes from which host it is, "
                        "not from a feed.",
                    ) if not _routable(value) else absent(
                        NEVER_OBSERVED,
                        "This address is routable but has no reputation lookup "
                        "stored. Every other public address drawn in this "
                        "estate has one, so this is unusual rather than "
                        "normal and is worth looking up by hand.",
                    ),
                })
                continue
            out[value] = Enrichment(value, kind, {
                # A real 0 here means "not abusive"; a failed check stored NULL.
                "abuse_score": row.abuse_score if row.abuse_score is not None else absent(
                    CHECK_FAILED,
                    "AbuseIPDB did not answer for this address, so there is no "
                    "score. It stores nothing rather than zero when it fails, "
                    "so a 0 elsewhere is a real result.",
                ),
                "isp": row.isp,
                "country_code": row.country_code,
                "threatfox": _threatfox(row.result_json),
                "investigated": absent(
                    OUT_OF_SCOPE,
                    "Addresses are not investigated by this platform: of 2,488 "
                    "investigations, none has an `ip` observable type. This is "
                    "how the pipeline is built, not a missing record.",
                ),
                **_stale(row.queried_at, now),
            })
            continue

        row = by_value.get(value.lower())
        if row is None:
            out[value] = Enrichment(value, kind, {
                "investigated": absent(
                    UNCLASSIFIED,
                    "No investigation has been run on this indicator. Coverage "
                    "is 83.4% of URLs and 35.9% of domains, so an absence here "
                    "is ordinary and is not evidence that it is harmless.",
                ),
            })
            continue
        out[value] = Enrichment(value, kind, {
            "state": row.state,
            # The automated conclusion and an analyst's are different claims
            # and are never merged: the platform's verdict is what it computed,
            # and a person disagreeing with it is the more interesting fact.
            "classification": row.classification,
            "confidence": row.confidence,
            "risk_score": row.risk_score,
            "recommended_action": row.recommended_action,
            "observable_type": row.observable_type,
            "investigation_id": str(row.id),
            **_stale(row.concluded_at or row.created_at, now),
        })
    return out
