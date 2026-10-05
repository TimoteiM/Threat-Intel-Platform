"""What the sandbox VM does on its own, separated from what the sample did.

Every detonation reported the same nine or ten domains — cdn.onenote.net,
login.microsoftonline.com, outlook.office.com, substrate.office.com,
www.microsoft365.com, portal.office.com, res.public.onecdn.static.microsoft,
www.clarity.ms, assets.adobedtm.com — because the guest image is a logged-in
Office workstation that phones home whether or not anything is detonated on it.

Measured over the 19 stored analyses that carried any network at all:

    cdn.onenote.net                     19/19   100%
    www.microsoft365.com                19/19   100%
    login.microsoftonline.com           19/19   100%
    substrate.office.com                19/19   100%
    portal.office.com                   19/19   100%
    res.public.onecdn.static.microsoft  19/19   100%
    outlook.office.com                  19/19   100%
    www.clarity.ms                      17/19    89%
    assets.adobedtm.com                 16/19    84%
    google.com                           8/19    42%
    ...
    0055.top                             1/19     5%
    boutique-dofus.fr                    1/19     5%
    societegeneral-securedaccount.fr     1/19     5%

The split is not subtle, and the bottom of that list is the part an analyst
opened the page to read. It was indistinguishable from the top.

**Nothing is hidden.** A domain is labelled with how often the sandbox reaches
it unprompted, and the UI groups on that label. Suppressing it outright would
be a worse bug than the one being fixed: a sample really can talk to
login.microsoftonline.com, and an analyst must be able to see that it did.

Prevalence is measured rather than listed, because the baseline is a property
of this estate's guest image and changes when that image does. The curated seed
below exists only for the window before there is enough history to measure —
below MIN_ANALYSES, a single detonation would otherwise make its own target
look like background.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import SandboxAnalysis

logger = logging.getLogger(__name__)

# How often the sandbox must reach a destination unprompted before it is called
# background. Deliberately high: the cost of mislabelling a real callback as
# noise is an analyst not reading it.
BASELINE_SHARE = 0.80

# Below this, prevalence means nothing — with three analyses, one target domain
# shared by two of them reads as 67% background.
MIN_ANALYSES = 8

# How much history to measure over. Long enough to be stable, short enough that
# re-imaging the guest is reflected within a few dozen detonations.
WINDOW = 200

# Used only until MIN_ANALYSES is reached. The telemetry of a logged-in Office
# workstation — not a blocklist, and not consulted once there is real history.
SEED = frozenset({
    "cdn.onenote.net",
    "login.microsoftonline.com",
    "outlook.office.com",
    "portal.office.com",
    "res.public.onecdn.static.microsoft",
    "substrate.office.com",
    "www.microsoft365.com",
    "www.clarity.ms",
    "assets.adobedtm.com",
})

_CACHE: dict[str, Any] = {"generation": None, "prevalence": {}, "analyses": 0}


def _domains_of(normalized: Any) -> set[str]:
    network = (normalized or {}).get("network") or {}
    out: set[str] = set()
    for field in ("domains", "dns_queries", "tls_sni"):
        for value in network.get(field) or []:
            text = str(value or "").strip().lower()
            if text:
                out.add(text)
    return out


async def prevalence(db: AsyncSession) -> dict[str, float]:
    """How often each destination appears across recent detonations.

    Cached against the number of stored analyses, so a new detonation refreshes
    it and nothing else recomputes it.
    """
    generation = (
        await db.execute(
            select(func.count(SandboxAnalysis.id)).where(SandboxAnalysis.provider == "cape")
        )
    ).scalar() or 0

    if _CACHE["generation"] == generation:
        return _CACHE["prevalence"]

    rows = (
        await db.execute(
            select(SandboxAnalysis.normalized_json)
            .where(SandboxAnalysis.provider == "cape")
            .order_by(SandboxAnalysis.created_at.desc())
            .limit(WINDOW)
        )
    ).scalars().all()

    seen: dict[str, int] = {}
    counted = 0
    for normalized in rows:
        domains = _domains_of(normalized)
        if not domains:
            # An analysis with no network says nothing about what is background.
            continue
        counted += 1
        for domain in domains:
            seen[domain] = seen.get(domain, 0) + 1

    share = (
        {domain: count / counted for domain, count in seen.items()}
        if counted >= MIN_ANALYSES
        else {}
    )
    _CACHE.update({"generation": generation, "prevalence": share, "analyses": counted})
    return share


async def annotate(db: AsyncSession, normalized: dict[str, Any] | None) -> dict[str, Any] | None:
    """Tag each network destination with how routine it is for this sandbox.

    Applied when a result is read rather than when it is written, so the
    analyses already stored gain the distinction without anyone re-detonating
    a sample.
    """
    if not normalized:
        return normalized

    network = normalized.get("network")
    if not isinstance(network, dict):
        return normalized

    try:
        share = await prevalence(db)
    except Exception as exc:  # noqa: BLE001 — a label is never worth a 500
        logger.warning("Sandbox baseline could not be computed: %s", exc)
        return normalized

    measured = bool(share)

    def routine(value: str) -> tuple[bool, float | None]:
        key = str(value or "").strip().lower()
        if measured:
            seen = share.get(key, 0.0)
            return seen >= BASELINE_SHARE, round(seen, 3)
        return key in SEED, None

    annotated: dict[str, list[dict[str, Any]]] = {}
    for field in ("domains", "dns_queries", "tls_sni"):
        values = network.get(field)
        if not isinstance(values, list):
            continue
        rows = []
        for value in values:
            is_baseline, seen = routine(str(value))
            rows.append({"value": value, "baseline": is_baseline, "seen_in": seen})
        annotated[field] = rows

    out = dict(normalized)
    out["network"] = {
        **network,
        # The original lists are left exactly as they were. Anything reading
        # `network.domains` — the collector's JSONB containment lookups, the
        # evidence it builds — keeps working on the same shape.
        "annotated": annotated,
        "baseline": {
            "measured": measured,
            "analyses": _CACHE.get("analyses", 0),
            "threshold": BASELINE_SHARE,
        },
    }
    return out
