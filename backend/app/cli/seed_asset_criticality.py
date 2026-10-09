"""Propose which machines might matter. Every proposal lands unconfirmed.

    python -m app.cli.seed_asset_criticality --dry-run
    python -m app.cli.seed_asset_criticality

Two signals, both weak on their own and both labelled as proposals:

  name       a label that looks like a controller. Anchored on separators so
             `EXP-DCOM-02` cannot match on `DC`, but still only evidence about
             a string — a controller named `EXP-SRV-09` matches nothing, which
             is exactly why this cannot be the mechanism.
  behaviour  a machine an attack reached over an administrative share. Better
             evidence than a name, because it is what something actually did.

Nothing here writes `confirmed`. A person promotes a row, and until they do
the graph renders the host as `proposed`, never as a crown jewel.
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.database import AlertGraphEdge, AlertGraphEntity, AssetCriticality
from app.services.asset_criticality_service import (
    propose,
    propose_from_behaviour,
    propose_from_name,
)


async def run(dry_run: bool) -> None:
    async with AsyncSessionLocal() as db:
        hosts = (
            await db.execute(
                select(AlertGraphEntity.label)
                .where(AlertGraphEntity.kind == "host")
                .distinct()
            )
        ).scalars().all()
        # Which hosts an attack reached over an administrative share.
        reached = set(
            (
                await db.execute(
                    select(AlertGraphEdge.target_key).where(
                        AlertGraphEdge.kind == "remote_exec_via"
                    )
                )
            ).scalars().all()
        )
        reached_labels = {
            key.split(":", 1)[1] for key in reached if key.startswith("host:")
        }
        existing = {
            row.host: row
            for row in (await db.execute(select(AssetCriticality))).scalars().all()
        }

        proposals: list[tuple[str, str, str]] = []
        for host in sorted(set(hosts)):
            if host in existing:
                continue
            found = propose_from_behaviour(host=host, observed=
                ["remote_exec_via"] if host in reached_labels else []
            ) or propose_from_name(host)
            if found:
                proposals.append((host, found[0], found[1]))

        print(f"hosts seen in the graph: {len(set(hosts))}")
        print(f"already classified     : {len(existing)}")
        print(f"proposals              : {len(proposals)}")
        for host, tier, reason in proposals:
            print(f"  {host:<28} {tier:<12} {reason[:72]}")
        if dry_run:
            print("\n(dry run — nothing written)")
            return
        for host, tier, reason in proposals:
            await propose(db, host=host, tier=tier, reason=reason)
        await db.commit()
        print(f"\n{len(proposals)} rows written as `proposed`. "
              "None is confirmed; a person has to promote each one.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    asyncio.run(run(args.dry_run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
