#!/usr/bin/env python3
"""Apply config/client-sources.yaml into `tenant_integrations`, or check it.

    scripts/apply_client_sources.py --check    # report differences, change nothing
    scripts/apply_client_sources.py --apply    # write the file's connection details

Run inside the api container, which has the application package and the
database:

    docker compose exec -T -e PYTHONPATH=/app api python /app/../scripts/apply_client_sources.py --check

**Connection details only. Never credentials.** A credential is set through
the API into `tenant_integrations.secret_ciphertext`, encrypted under
INTEGRATION_ENCRYPTION_KEY. This script does not read, write, or print one,
and the loader refuses a file containing anything secret-shaped.

**Runs as the migration role.** Writing another client's row is exactly what
row-level security refuses for the application role, so this uses
`DATABASE_MIGRATION_URL` — the owning connection, which bypasses the policy.
That is correct for an administrative apply and wrong for anything serving a
request, which is why this is a script and not an endpoint.

**--apply never deletes.** A row in the database that the file does not
declare is *reported* and left alone. Deleting it would mean this script can
disconnect a client's platform by way of someone editing a YAML file, and the
reconciliation report is a better place for that decision than a `DELETE`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _engine():
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    from app.config import get_settings

    url = make_url(get_settings().database_migration_url)
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg2")
    return create_engine(url, poolclass=NullPool)


def _rows(db):
    from sqlalchemy import text

    return [
        {"tenant_id": r[0], "tool": r[1], "config": r[2] or {}}
        for r in db.execute(text(
            "SELECT tenant_id, tool, config FROM tenant_integrations"
        ))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true",
                       help="report differences and change nothing")
    group.add_argument("--apply", action="store_true",
                       help="write the file's connection details into the database")
    parser.add_argument("--map", default=None, help="an alternative map file")
    args = parser.parse_args()

    from sqlalchemy import text
    from sqlalchemy.orm import Session

    from app.services import client_sources

    expected = client_sources.load(args.map)
    print(f"source map: {len(expected)} client(s), "
          f"{sum(len(e.sources) for e in expected.values())} platform entr(ies)")

    engine = _engine()
    with Session(engine) as db:
        who = db.execute(text("SELECT current_user")).scalar()
        print(f"connected as: {who}")

        if args.check:
            findings = client_sources.reconcile(_rows(db), args.map)
            if not findings:
                print("the database matches the source map")
                return 0
            print("DIFFERENCES:")
            for kind, items in findings.items():
                for item in items:
                    print(f"  {kind}: {item}")
            # Exit 1 so this can gate something later. A check that cannot
            # fail is decoration.
            return 1

        written = 0
        for entry in expected.values():
            for source in entry.sources:
                db.execute(text("""
                    INSERT INTO tenant_integrations
                        (id, tenant_id, tool, config, created_at, updated_at)
                    VALUES (gen_random_uuid(), :tenant, :tool,
                            CAST(:config AS jsonb), now(), now())
                    ON CONFLICT (tenant_id, tool) DO UPDATE
                       SET config = CAST(:config AS jsonb), updated_at = now()
                """), {
                    "tenant": source.tenant_id,
                    "tool": source.platform,
                    "config": json.dumps(dict(source.connection), sort_keys=True),
                })
                written += 1
        db.commit()
        print(f"wrote {written} platform entr(ies); credentials untouched")

        leftover = client_sources.reconcile(_rows(db), args.map)
        extra = leftover.get("in_database_not_in_file") or []
        if extra:
            print("still configured but not declared in the file "
                  "(left alone, not deleted):")
            for item in extra:
                print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
