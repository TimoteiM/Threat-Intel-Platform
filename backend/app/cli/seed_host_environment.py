"""Propose which hosts are test rigs. A person confirms.

    python -m app.cli.seed_host_environment            # show proposals
    python -m app.cli.seed_host_environment --apply    # write them as proposed
    python -m app.cli.seed_host_environment --confirm windows-test-device …

Every candidate lands `proposed`, for the same reason the criticality table
exists: `EXP-DC-01` matches `-DC-` and so does `EXP-DCOM-02`. A name is
evidence about a string, not about a machine's role, and a proposal nobody has
agreed to must not silently remove a host's alerts from the estate's figures.

Near-misses are printed rather than guessed at in either direction. A host
called `siembiot-package-teste-1` is probably a test rig and `PFTEST-WIN11`
probably is too, but neither matches a separator-anchored `test`, and this
codebase has produced eleven delimiter-boundary bugs by deciding such
questions with a pattern.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text

from app.db.session import AsyncSessionLocal
from app.models.database import AssetCriticality
from app.services.asset_criticality_service import CONFIRMED, PROPOSED, TEST

#: `test` as its own token, bounded by a separator or the ends of the string.
#: Anchored so `latest-build-01` and `contest02` cannot match.
_TEST_TOKEN = re.compile(r"(?:^|[-_. ])(test|tst|lab|sandbox|demo)(?:$|[-_. 0-9])", re.I)

#: Printed for a person to judge, never applied. These contain the letters but
#: not the token.
_NEAR = re.compile(r"test|tst|lab|sandbox|demo", re.I)


async def candidates(db) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    rows = (
        await db.execute(
            text(
                "select lower(split_part(entity_host, '.', 1)) as host, count(*) n "
                "from alert_body_investigation_runs where entity_host is not null "
                "group by 1 order by n desc"
            )
        )
    ).all()
    hits = [(r.host, r.n) for r in rows if _TEST_TOKEN.search(r.host)]
    near = [
        (r.host, r.n)
        for r in rows
        if not _TEST_TOKEN.search(r.host) and _NEAR.search(r.host)
    ]
    return hits, near


async def run(apply: bool, confirm: list[str]) -> None:
    async with AsyncSessionLocal() as db:
        if confirm:
            now = datetime.now(timezone.utc)
            for host in confirm:
                label = host.strip().lower()
                row = (
                    await db.execute(
                        select(AssetCriticality).where(AssetCriticality.host == label)
                    )
                ).scalar_one_or_none()
                if row is None:
                    row = AssetCriticality(id=uuid.uuid4(), host=label, set_at=now)
                    db.add(row)
                row.environment = TEST
                row.environment_state = CONFIRMED
                row.environment_reason = (
                    (row.environment_reason or "")
                    + f" Confirmed test host at the console {now:%Y-%m-%d}."
                ).strip()
                print(f"confirmed test: {label}")
            await db.commit()
            return

        hits, near = await candidates(db)
        print("Proposed as test, from a separator-anchored name token:")
        for host, n in hits:
            print(f"  {n:7d} alerts  {host}")
        print("\nNear misses — contain the letters but not the token. Judge these "
              "yourself; nothing is written for them:")
        for host, n in near:
            print(f"  {n:7d} alerts  {host}")

        if not apply:
            print("\nNothing written. Re-run with --apply to record these as "
                  "`proposed`, or --confirm <host> … to confirm one.")
            return

        now = datetime.now(timezone.utc)
        for host, n in hits:
            row = (
                await db.execute(
                    select(AssetCriticality).where(AssetCriticality.host == host)
                )
            ).scalar_one_or_none()
            if row is None:
                row = AssetCriticality(id=uuid.uuid4(), host=host, set_at=now)
                db.add(row)
            if row.environment_state == CONFIRMED:
                print(f"  left alone, already confirmed: {host}")
                continue
            row.environment = TEST
            row.environment_state = PROPOSED
            row.environment_reason = (
                f"Name carries a separator-anchored test token. {n} alerts in the "
                "store. A name is evidence about a string, not about a machine."
            )
            print(f"  proposed test: {host}")
        await db.commit()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--confirm", nargs="*", default=[])
    args = ap.parse_args()
    asyncio.run(run(args.apply, args.confirm))


if __name__ == "__main__":
    main()
