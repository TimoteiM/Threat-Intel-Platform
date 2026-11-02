"""Encrypt the token map at rest, and move the TTL to a 24-hour ceiling

Two changes to the same table, together because both rewrite every row.

**Encryption.** `investigation_token_maps.token_map` held real hostnames,
accounts and addresses as readable JSONB — by construction, since
reversibility is the point. Anyone who could read the table had every
identifier the tokenisation existed to protect. It is now a Fernet ciphertext
under `INTEGRATION_ENCRYPTION_KEY`, which lives in the environment and not in
the database, so a database read alone no longer yields identifiers.

This reuses `app.security.secret_box`, which already seals integration
credentials: MultiFernet, a `key_id` per row, and rotation that re-encrypts
without the plaintext passing through twice. No new primitive, no new key, no
new package — the thing that made this small rather than a project.

The map was already read and written whole and never queried by key, so
losing SQL visibility into it costs nothing.

**The ceiling.** `expires_at` was six hours, which was a number chosen for an
agent loop that does not exist yet. The lifetime is now: purge when the
investigation completes, with 24 hours as a wall-clock backstop for the ones
that are abandoned or crash. A ceiling that fires is a signal rather than
routine housekeeping — it means either the ceiling is wrong or investigations
are leaking — so the purge reports which of the two reasons applied.

Existing rows are deleted rather than migrated. They are plaintext under the
old column and ephemeral by design, and rewriting them would mean reading
every identifier out in order to seal it back.

Revision ID: 071
Revises: 070
"""

from alembic import op
import sqlalchemy as sa

revision = "071"
down_revision = "070"
branch_labels = None
depends_on = None

_TABLE = "investigation_token_maps"


def _columns(bind) -> set[str]:
    inspector = sa.inspect(bind)
    if not inspector.has_table(_TABLE):
        return set()
    return {c["name"] for c in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind)
    if not existing:
        return

    # Before adding anything: the rows hold plaintext identifiers under a
    # column that is about to stop existing, and sealing them would mean
    # reading every one of them back out first.
    op.execute(sa.text(f"DELETE FROM {_TABLE}"))

    if "token_map_ciphertext" not in existing:
        op.add_column(_TABLE, sa.Column("token_map_ciphertext", sa.Text(), nullable=True))
    if "token_map_key_id" not in existing:
        op.add_column(_TABLE, sa.Column("token_map_key_id", sa.String(32), nullable=True))
    if "token_map" in existing:
        op.drop_column(_TABLE, "token_map")


def downgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind)
    if not existing:
        return
    op.execute(sa.text(f"DELETE FROM {_TABLE}"))
    if "token_map" not in existing:
        op.add_column(
            _TABLE,
            sa.Column(
                "token_map", sa.dialects.postgresql.JSONB,
                nullable=False, server_default=sa.text("'{}'::jsonb"),
            ),
        )
    for column in ("token_map_ciphertext", "token_map_key_id"):
        if column in existing:
            op.drop_column(_TABLE, column)
