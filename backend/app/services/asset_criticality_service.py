"""Which machines matter, and how a candidate gets proposed without being asserted.

Three states, the same shape the graph already uses for techniques:

    confirmed   a person promoted it
    proposed    a signal suggested it and nobody has agreed yet
    unknown     no row

`unknown` is not `normal`. This estate has 1,878 cases and no asset
inventory, so a host with no row is a host nobody has classified — and a graph
that draws that as "not a crown jewel" is making a claim on the strength of an
empty table.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AssetCriticality

CROWN_JEWEL = "crown_jewel"
HIGH = "high"
NORMAL = "normal"
TIERS = (CROWN_JEWEL, HIGH, NORMAL)

CONFIRMED = "confirmed"
PROPOSED = "proposed"
UNKNOWN = "unknown"


async def criticality_for(
    db: AsyncSession, hosts: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Tier and state per host label. Hosts with no row are absent from the
    result, and the caller renders them as `unknown` rather than as normal."""
    labels = [h for h in dict.fromkeys((h or "").strip().lower() for h in hosts) if h]
    if not labels:
        return {}
    rows = (
        await db.execute(
            select(AssetCriticality).where(AssetCriticality.host.in_(labels))
        )
    ).scalars().all()
    return {
        row.host: {
            "tier": row.tier,
            "state": row.state,
            "reason": row.reason,
            "set_by": row.set_by,
            "set_at": row.set_at.isoformat() if row.set_at else None,
        }
        for row in rows
    }


# --- the seeding helper ----------------------------------------------------
#
# Every candidate below lands `proposed`. The point of the helper is to save a
# person typing, not to decide.

#: A name that *suggests* a controller. Anchored on separators so `EXP-DCOM-02`
#: cannot match on `DC`, which is exactly how a pattern-based badge goes wrong.
#: Still only ever a proposal: the pattern is evidence about a string, not
#: about a machine's role.
_CONTROLLER_NAME = re.compile(
    r"(?:^|[-_.])(?:dc\d*|addc\d*|pdc|domaincontroller)(?:$|[-_.])", re.IGNORECASE
)

#: Behaviour, which is better evidence than a name: a machine named as the
#: answer to `nltest /dclist` is being treated as a controller by the attacker,
#: whatever it is called. Also `\\HOST\ADMIN$`-style administrative shares and
#: anything named as a `targetServer`.
_DCLIST = re.compile(r"nltest\s+/dclist\s*:?\s*([A-Za-z0-9._-]+)", re.IGNORECASE)


def propose_from_name(host: str) -> tuple[str, str] | None:
    label = (host or "").strip().lower().split(".")[0]
    if not label:
        return None
    if _CONTROLLER_NAME.search(label):
        return (
            CROWN_JEWEL,
            f"The name {label!r} looks like a domain controller. A name is "
            "evidence about a string, not about a role — confirm or reject it.",
        )
    return None


def propose_from_behaviour(
    *, host: str, observed: Iterable[str]
) -> tuple[str, str] | None:
    """Evidence from what an attack did, which beats what a machine is called.

    `observed` is the set of relationship kinds that reached this host in the
    graph. Being the far end of `remote_exec_via` means somebody reached it
    over an administrative share; that is worth a human look whatever the
    machine is named.
    """
    kinds = set(observed)
    if "remote_exec_via" in kinds:
        return (
            HIGH,
            "An attack reached this machine over an administrative share, so "
            "something treated it as worth pivoting to.",
        )
    return None


async def propose(
    db: AsyncSession,
    *,
    host: str,
    tier: str,
    reason: str,
    set_by: str = "seeding helper",
) -> AssetCriticality | None:
    """Record a candidate. Never overwrites a confirmation.

    A helper that could flip a person's `confirmed` row back to `proposed`
    would make the whole three-state distinction worthless on the next run.
    """
    label = (host or "").strip().lower().split(".")[0]
    if not label or tier not in TIERS:
        return None
    existing = (
        await db.execute(
            select(AssetCriticality).where(AssetCriticality.host == label)
        )
    ).scalars().first()
    if existing is not None:
        return existing if existing.state == CONFIRMED else existing
    row = AssetCriticality(
        host=label, tier=tier, state=PROPOSED, reason=reason, set_by=set_by,
        set_at=datetime.now(timezone.utc),
    )
    db.add(row)
    return row


async def confirm(
    db: AsyncSession, *, host: str, tier: str, reason: str | None, set_by: str
) -> AssetCriticality | None:
    """A person's decision. This is the only path to `confirmed`."""
    label = (host or "").strip().lower().split(".")[0]
    if not label or tier not in TIERS:
        return None
    row = (
        await db.execute(
            select(AssetCriticality).where(AssetCriticality.host == label)
        )
    ).scalars().first()
    if row is None:
        row = AssetCriticality(host=label)
        db.add(row)
    row.tier = tier
    row.state = CONFIRMED
    row.reason = reason
    row.set_by = set_by
    row.set_at = datetime.now(timezone.utc)
    return row


def dclist_targets(text: str | None) -> list[str]:
    """Domains named as the argument to `nltest /dclist:`.

    Returns the *domain*, not a host — `nltest /dclist:corp.local` names the
    domain whose controllers were enumerated. Resolving that to machines needs
    directory data this platform does not ingest, so it is reported as a
    domain and a person maps it.
    """
    return [m.group(1).lower() for m in _DCLIST.finditer(text or "")]


# --- which machines are the estate ------------------------------------------
#
# Measured 2026-10-12 on `alert_body_investigation_runs` over 2026-09-18..09-24,
# the last full week before the ingestion collapse: 5,477 alerts from 100
# hosts, of which **2,579 (47%) came from `Windows-Test-Device`** and 4,237
# (77%) from that host plus `EXP-4LWK334`.
#
# So an estate-wide number computed without this filter is substantially a
# number about one test machine. That is the fifth instance in this codebase of
# a statistic whose dominant term is an artefact rather than the thing being
# measured, after `Manager: Siembiot`, "same device as the alert",
# `(source, client, host)` membership, and `ioc_values` boilerplate.

PRODUCTION = "production"
TEST = "test"
ENVIRONMENTS = (PRODUCTION, TEST, UNKNOWN)


async def environments_for(
    db: AsyncSession, hosts: Iterable[str]
) -> dict[str, dict[str, Any]]:
    """Environment and its state per host label.

    A host with no row is absent from the result and is `unknown` — which is
    not `production`. The caller must keep that distinction: counting unknowns
    as production is how a test rig ends up inside an estate figure, and
    dropping them is how a real machine disappears from one.
    """
    labels = [h for h in dict.fromkeys((h or "").strip().lower() for h in hosts) if h]
    if not labels:
        return {}
    rows = (
        await db.execute(
            select(AssetCriticality).where(AssetCriticality.host.in_(labels))
        )
    ).scalars().all()
    return {
        row.host: {
            "environment": row.environment or UNKNOWN,
            "state": row.environment_state,
            "reason": row.environment_reason,
        }
        for row in rows
        if row.environment
    }


async def test_hosts(db: AsyncSession, *, include_proposed: bool = False) -> set[str]:
    """The host labels classed as test.

    `include_proposed` is off by default: a proposal nobody has agreed to must
    not silently remove a host's alerts from the estate's numbers. A figure
    that wants the wider exclusion asks for it and says which it used.
    """
    query = select(AssetCriticality.host).where(AssetCriticality.environment == TEST)
    if not include_proposed:
        query = query.where(AssetCriticality.environment_state == CONFIRMED)
    return {h for h in (await db.execute(query)).scalars().all() if h}


@dataclass(frozen=True)
class EstateScope:
    """What a figure covered, carried with the figure.

    The point is that an estate number can no longer be quoted without saying
    which hosts it excluded and how many it could not classify. Both halves
    matter: the excluded set is the correction, and the unknown set is the
    remaining uncertainty.
    """

    excluded_test: tuple[str, ...]
    unknown_hosts: int
    production_hosts: int
    include_proposed: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "excluded_test_hosts": list(self.excluded_test),
            "excluded_test_count": len(self.excluded_test),
            "unclassified_hosts": self.unknown_hosts,
            "production_hosts": self.production_hosts,
            "proposed_included": self.include_proposed,
            "note": (
                f"Excludes {len(self.excluded_test)} host(s) classed as test. "
                f"{self.unknown_hosts} host(s) carry no environment "
                "classification and are counted here as unknown, not as "
                "production."
            ),
        }


async def estate_scope(
    db: AsyncSession, hosts: Iterable[str], *, include_proposed: bool = False
) -> tuple[set[str], EstateScope]:
    """Split a host set into (kept, what-was-excluded-and-why)."""
    labels = {h for h in ((h or "").strip().lower() for h in hosts) if h}
    excluded = await test_hosts(db, include_proposed=include_proposed)
    known = await environments_for(db, labels)
    kept = labels - excluded
    production = sum(
        1 for h in kept if known.get(h, {}).get("environment") == PRODUCTION
    )
    return kept, EstateScope(
        excluded_test=tuple(sorted(labels & excluded)),
        unknown_hosts=len(kept) - production,
        production_hosts=production,
        include_proposed=include_proposed,
    )
