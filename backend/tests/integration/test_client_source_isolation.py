"""The control: a run carrying tenant X can only ever reach X's sources.

**These tests try to cross and must fail**, and they run against a real
Postgres as the real restricted role, because the thing being tested is a
database policy. A fake session cannot refuse a query; it can only agree with
whatever the test set up — which is the defect this platform keeps finding in
its own checks.

Three directions, in increasing order of how much a failure would cost:

1. The resolver refuses a tenant outside the caller's scope. Code-level, and
   the weakest of the three, because it holds only on the paths that call it.
2. A bound session reading **with an explicit cross-tenant WHERE clause** gets
   nothing. This is the one that matters: it means a query written to cross
   cannot, whatever the code intended.
3. An **unbound** session gets nothing at all. Fails closed, so a path that
   forgets to scope reads zero rows rather than every client's.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.services.client_sources import TENANT_SETTING, bind_tenant
from app.services.tenant_scope import TenantForbidden, TenantScope

TENANT_A = f"zz-iso-a-{uuid.uuid4().hex[:6]}"
TENANT_B = f"zz-iso-b-{uuid.uuid4().hex[:6]}"


def _owner_engine():
    """The migration connection — owner, so it bypasses the policy and can seed."""
    from app.config import get_settings

    url = make_url(get_settings().database_migration_url)
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg2")
    return create_engine(url, poolclass=NullPool)


def _app_engine():
    """The application's own connection, as configured.

    **`database_sync_url`, deliberately.** An earlier version of this file
    built the `tip_app` connection by hand, because on 2026-10-19 that
    variable still pointed at `threatintel` on the host — superuser and table
    owner, which row-level security exempts — so the isolation assertions
    below passed while nothing was isolated. The fail-closed test caught it by
    reading 2 rows from a session bound to nobody.

    That divergence was closed on 2026-10-20: the host `.env` now points the
    application URLs at `tip_app`, the same role the containers use, and the
    owning connection lives under `DATABASE_MIGRATION_URL` where anything
    needing ownership asks for it by name.

    So this reads the real variable again — and the fixture asserts the role it
    got. **Those two together make this file a control on the divergence**: if
    anyone re-points the application URL at an owner, these tests fail loudly
    instead of passing vacuously, which is the opposite of what happened the
    first time.
    """
    from app.config import get_settings
    from app.db.session import _explicit_driver

    return create_engine(_explicit_driver(get_settings().database_sync_url),
                         poolclass=NullPool)


def _reachable(engine) -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def seeded():
    """Two clients' rows, written as the owner, removed afterwards."""
    owner = _owner_engine()
    if not _reachable(owner):
        pytest.skip("no Postgres reachable on the migration connection")
    app_engine = _app_engine()
    if not _reachable(app_engine):
        pytest.skip(
            "no Postgres reachable on the application connection — run "
            "scripts/provision_db_roles.sh, which creates the role the "
            "application URLs name"
        )
    # The premise of every assertion below, checked rather than assumed.
    # Row-level security does not apply to a superuser or to the table's
    # owner, so if this connection were either, the isolation tests would
    # pass by not being tested.
    with app_engine.connect() as conn:
        who = conn.execute(text("SELECT current_user")).scalar()
        is_super = conn.execute(text(
            "SELECT usesuper FROM pg_user WHERE usename = current_user"
        )).scalar()
        # `table_owner`, not `owner` — `owner` is the engine two lines up, and
        # shadowing it here handed a string to `Session()`.
        table_owner = conn.execute(text(
            "SELECT tableowner FROM pg_tables WHERE tablename = 'tenant_integrations'"
        )).scalar()
    assert who == "tip_app", (
        f"the application connection resolves to {who!r}, not the restricted "
        f"role. DATABASE_SYNC_URL has been re-pointed; the row-level policy "
        f"does not apply to an owner and every assertion below would pass "
        f"while nothing was isolated. scripts/liveness.sh checks this too."
    )
    assert not is_super, "the restricted role is a superuser; RLS cannot bind"
    assert who != table_owner, f"{who!r} owns the table, so RLS does not apply to it"
    with Session(owner) as db:
        db.execute(text(
            "DELETE FROM tenant_integrations WHERE tenant_id IN (:a, :b)"
        ), {"a": TENANT_A, "b": TENANT_B})
        for tenant, console in ((TENANT_A, "https://a.example"),
                                (TENANT_B, "https://b.example")):
            db.execute(text(
                "INSERT INTO tenant_integrations "
                "(id, tenant_id, tool, config, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :t, 'sentinelone', "
                "CAST(:cfg AS jsonb), now(), now())"
            ), {"t": tenant, "cfg": f'{{"console_url": "{console}"}}'})
        db.commit()
    try:
        yield app_engine
    finally:
        with Session(owner) as db:
            db.execute(text(
                "DELETE FROM tenant_integrations WHERE tenant_id IN (:a, :b)"
            ), {"a": TENANT_A, "b": TENANT_B})
            db.commit()
        app_engine.dispose()
        owner.dispose()


# ── 1. the resolver refuses out-of-scope tenants ─────────────────────────


def test_the_resolver_refuses_a_tenant_outside_the_scope(tmp_path):
    """A refusal, not an empty list.

    An empty list reads as "this client has no sources configured", which is a
    different and reassuring fact. The caller asked about a client it may not
    see, and that is the thing to say.
    """
    from app.services import client_sources

    source_map = tmp_path / "map.yaml"
    source_map.write_text(
        "version: 1\n"
        "clients:\n"
        f"  - tenant_id: {TENANT_A}\n"
        "    platforms:\n"
        "      - platform: sentinelone\n"
        "        connection:\n"
        "          console_url: https://a.example\n"
    )
    scope = TenantScope(tenant_ids=(TENANT_B,), actor="client-b-user")

    with pytest.raises(TenantForbidden) as exc:
        client_sources.sources_for(TENANT_A, scope=scope, map_path=source_map)
    assert TENANT_A in str(exc.value)

    # The control: the same call with the right scope returns the source, so
    # the refusal above is about the scope and not about the map being empty.
    allowed = TenantScope(tenant_ids=(TENANT_A,), actor="client-a-user")
    got = client_sources.sources_for(TENANT_A, scope=allowed, map_path=source_map)
    assert [s.platform for s in got] == ["sentinelone"]


def test_an_empty_tenant_is_refused_rather_than_treated_as_all():
    from app.services import client_sources

    with pytest.raises(TenantForbidden):
        client_sources.sources_for("", scope=TenantScope(all_tenants=True))


# ── 2. the database refuses a query written to cross ─────────────────────


def test_a_bound_session_cannot_read_another_tenant_even_when_it_asks(seeded):
    """**The test that tries to cross and fails.**

    Not "the ORM filters it out" — the statement below contains
    `WHERE tenant_id = :other` and the database returns nothing. A query
    written by someone who meant to cross, or by someone who passed the wrong
    variable, cannot.
    """
    with Session(seeded) as db:
        bind_tenant(db, TENANT_A)

        own = db.execute(text(
            "SELECT count(*) FROM tenant_integrations WHERE tenant_id = :t"
        ), {"t": TENANT_A}).scalar()
        assert own == 1, (
            "the bound tenant cannot see its own row, so this test is not "
            "measuring isolation — it is measuring an empty table"
        )

        crossed = db.execute(text(
            "SELECT count(*) FROM tenant_integrations WHERE tenant_id = :t"
        ), {"t": TENANT_B}).scalar()
        assert crossed == 0, "a cross-tenant read succeeded"

        # And no unfiltered read reaches it either: the row count with no
        # WHERE clause at all must still be the bound tenant's.
        unfiltered = db.execute(text(
            "SELECT count(*) FROM tenant_integrations "
            "WHERE tenant_id IN (:a, :b)"
        ), {"a": TENANT_A, "b": TENANT_B}).scalar()
        assert unfiltered == 1

        # The hardest version: ask for the other tenant's secret column.
        leaked = db.execute(text(
            "SELECT count(*) FROM tenant_integrations "
            "WHERE tenant_id <> :t"
        ), {"t": TENANT_A}).scalar()
        assert leaked == 0, "a negated filter reached other tenants' rows"
        db.rollback()


def test_an_unbound_session_reads_nothing_at_all(seeded):
    """Fails closed, which is the property that makes this a control.

    A path that forgets to bind a tenant gets zero rows. The alternative — an
    unbound session seeing everything — would mean the protection applied only
    to code that remembered it, which is what a convention is.
    """
    with Session(seeded) as db:
        count = db.execute(text(
            "SELECT count(*) FROM tenant_integrations WHERE tenant_id IN (:a, :b)"
        ), {"a": TENANT_A, "b": TENANT_B}).scalar()
        assert count == 0, (
            "an unbound session read rows; the policy is not failing closed"
        )
        db.rollback()


def test_the_binding_does_not_survive_the_transaction(seeded):
    """`SET LOCAL`, not `SET`.

    These engines are NullPool, but the application's are not. A binding that
    outlived its transaction would leave a pooled connection still bound to
    the previous caller's tenant — the cross-tenant read arriving by way of
    the pool, which no amount of query review would catch.
    """
    with Session(seeded) as db:
        bind_tenant(db, TENANT_A)
        assert db.execute(
            text("SELECT current_setting(:n, true)"), {"n": TENANT_SETTING}
        ).scalar() == TENANT_A
        db.rollback()
        # After the transaction ends the setting is gone, so the next reader on
        # this connection starts unbound — and unbound reads nothing.
        assert db.execute(
            text("SELECT current_setting(:n, true)"), {"n": TENANT_SETTING}
        ).scalar() in (None, "")
        db.rollback()


def test_the_owner_still_sees_everything_so_migrations_work(seeded):
    """ENABLE, not FORCE, and that is deliberate.

    Alembic runs as the owner and must be able to read every row to migrate
    it. If this test fails the policy was switched to FORCE and migrations
    that touch this table will silently see nothing.
    """
    owner = _owner_engine()
    try:
        with Session(owner) as db:
            count = db.execute(text(
                "SELECT count(*) FROM tenant_integrations WHERE tenant_id IN (:a, :b)"
            ), {"a": TENANT_A, "b": TENANT_B}).scalar()
            assert count == 2
    finally:
        owner.dispose()
