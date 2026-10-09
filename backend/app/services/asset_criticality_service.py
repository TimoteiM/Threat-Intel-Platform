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
