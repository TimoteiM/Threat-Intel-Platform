"""Onboard tenant `c29` deliberately, rather than letting ingest mint it.

`_provision_tenant` creates a row the first time an alert names an unknown
tenant — correctly, because refusing that alert would lose it — but it marks
the row `provisional` with a name derived mechanically from the id, precisely
because *a sender naming itself in a URL is not a decision to onboard a
client*. `PATCH /tenants/{id}` is the route that turns that into a decision,
and it 404s on a tenant that does not exist yet.

So for a client we are onboarding *before* the first alert arrives, this does
both halves in one transaction: creates the row and records the decision in
`tenant_events`, because a status column says what a tenant is now and can
never say who decided that.

Defaults chosen, and each is the conservative one:

    kind      = customer   — migration 074's reasoning: presuming "someone
                             else's data" is the safer presumption
    feed_kind = alerts     — this sender posts to /tenants/c29 the same way
                             c00 does, i.e. single alerts to be correlated.
                             `incidents` would mint a case per row.
    status    = active     — this IS the onboarding decision; the whole point
                             of running it is that a person made it

Re-runnable: ON CONFLICT DO NOTHING, and the event is only written when the
row is actually created.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402

from app.config import get_settings  # noqa: E402

TENANT_ID = "c29"
NAME = "C29"
ACTOR = "expertware.marketing@gmail.com"
NOTE = (
    "Onboarded 2026-10-27 ahead of the first alert, together with the firewall "
    "and INGEST_TRUSTED_CIDRS entries for the sender at 172.23.39.16. Created "
    "deliberately rather than left to ingest provisioning so it is active and "
    "named from the start."
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT tenant_id, name, kind, feed_kind, status FROM tenants "
                 " WHERE tenant_id = :t"),
            {"t": TENANT_ID},
        ).first()
    if existing:
        print(f"{TENANT_ID} already exists: name={existing.name} "
              f"kind={existing.kind} feed_kind={existing.feed_kind} "
              f"status={existing.status}")
        print("Nothing to do — use PATCH /tenants/{id} to change it.")
        return 0

    print(f"would create tenant {TENANT_ID!r}: name={NAME} kind=customer "
          f"feed_kind=alerts status=active")
    if not args.apply:
        print("\n(dry run — pass --apply to write)")
        return 0

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO tenants (id, tenant_id, name, kind, feed_kind,
                                     status, notes, created_at)
                VALUES (gen_random_uuid(), :t, :n, 'customer', 'alerts',
                        'active', :note, now())
                ON CONFLICT (tenant_id) DO NOTHING
            """),
            {"t": TENANT_ID, "n": NAME, "note": NOTE},
        )
        # Only if we actually created it — the event records a decision, and a
        # no-op insert is not one.
        conn.execute(
            text("""
                INSERT INTO tenant_events (id, tenant_id, action, actor,
                                           actor_role, from_status, to_status,
                                           from_name, to_name, note, at)
                SELECT gen_random_uuid(), :t, 'onboarded', :actor, 'admin',
                       NULL, 'active', NULL, :n, :note, now()
                 WHERE EXISTS (SELECT 1 FROM tenants WHERE tenant_id = :t)
            """),
            {"t": TENANT_ID, "n": NAME, "actor": ACTOR, "note": NOTE},
        )

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT tenant_id, name, kind, feed_kind, status FROM tenants "
                 " WHERE tenant_id = :t"),
            {"t": TENANT_ID},
        ).first()
        events = conn.execute(
            text("SELECT count(*) FROM tenant_events WHERE tenant_id = :t"),
            {"t": TENANT_ID},
        ).scalar()
    print(f"created: {row.tenant_id} name={row.name} kind={row.kind} "
          f"feed_kind={row.feed_kind} status={row.status}")
    print(f"tenant_events rows for {TENANT_ID}: {events}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
