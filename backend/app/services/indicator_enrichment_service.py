"""What is known about an indicator, and what only looks known.

The graph draws addresses, domains, URLs and hashes. Two tables hold what was
found out about them, and they fail in different ways, so the panel has to
treat them differently rather than merging them into one "verdict".

Measured 2026-10-12 before building anything on them:

    ip_lookups      6,371 rows. 1,420 of the 1,424 public addresses in
                    `ioc_values` are covered (99.7%), so absence is rare. Age
                    is the problem: **63.9% of rows were queried more than 30
                    days ago**, the oldest in March. A verdict from March shown
                    without its date is a confident lie about today.

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

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.absence import CHECK_FAILED, NEVER_OBSERVED, UNCLASSIFIED, absent

#: Past this, a stored verdict is shown with its age marked. Not discarded:
#: an old answer is still an answer, and the analyst decides what it is worth.
STALE_AFTER = timedelta(days=30)

#: Observable types `investigations` actually holds. Derived from the data
#: rather than declared, because the point of the check was that `ip` is
#: missing from it.
INVESTIGATED_TYPES = ("url", "domain", "hash")

_IP_SQL = """
select ip, abuse_score, isp, country_code, threatfox_count, result_json, queried_at
from ip_lookups where ip = any(:values)
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


def _threatfox(row_json: Any) -> Any:
    """ThreatFox has not answered once. The count is a sentinel."""
    errors = (row_json or {}).get("errors")
    errors = errors if isinstance(errors, list) else []
    if any("threatfox" in str(e).lower() for e in errors):
        return absent(
            CHECK_FAILED,
            "ThreatFox has not been reachable for this lookup, so nothing was "
            "checked against it. The stored count reads 0 for every address in "
            "this estate and means 'not asked', not 'no hits'.",
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
                        NEVER_OBSERVED,
                        "This address has no reputation lookup stored. 1,420 of "
                        "1,424 public addresses in this estate do, so this is "
                        "unusual rather than normal.",
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
                    NEVER_OBSERVED,
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
