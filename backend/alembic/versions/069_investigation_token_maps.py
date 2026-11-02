"""A per-investigation, per-tenant token map with an expiry

The assistant's token map lives on `assistant_session_entries.token_map_json`
and has no owner, no tenant and no end: it is written when a session runs and
kept for as long as the row exists. That is adequate for a single-shot analysis
whose tokens are restored once, in the same call, and never used again.

A query boundary needs three things that map cannot give:

* **a tenant.** Without one, `[HOST_1]` from one customer resolves under
  another customer's map to a different host — not a refusal, a silently wrong
  answer, which is the cross-tenant failure this platform is built to prevent.
* **an investigation.** Same entity, same token *within* one investigation;
  different tokens across them. Numbering alone restarts, so `[HOST_1]` in two
  investigations names two different machines.
* **an end.** This table holds real hostnames, accounts and addresses in
  exchange for reversibility. A map with no expiry is an indefinite copy of
  customer identifiers, so every row carries `expires_at` and
  `purge_expired()` deletes on it.

One row per (tenant, investigation). The map is JSONB for the same reason the
assistant's is: it is read and written whole, never queried by key.

Idempotent, because `Base.metadata.create_all` runs at startup and is a second
schema authority — backlog 25.

Revision ID: 069
Revises: 068
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "069"
down_revision = "068"
branch_labels = None
depends_on = None

_TABLE = "investigation_token_maps"


def _has_table(bind) -> bool:
    return sa.inspect(bind).has_table(_TABLE)


def _indexes(bind) -> set[str]:
    return {ix["name"] for ix in sa.inspect(bind).get_indexes(_TABLE)}


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind):
        op.create_table(
            _TABLE,
            sa.Column(
                "id", postgresql.UUID(as_uuid=True),
                primary_key=True, server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("tenant_id", sa.String(64), nullable=False),
            sa.Column("investigation_id", sa.String(64), nullable=False),
            # Derived from (tenant, investigation) under the deployment pepper
            # and embedded in every token this map issues, so a token carries
            # the scope it was minted under and cannot be resolved by another.
            sa.Column("fingerprint", sa.String(16), nullable=False),
            sa.Column(
                "token_map", postgresql.JSONB,
                nullable=False, server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "created_at", sa.DateTime(timezone=True),
                nullable=False, server_default=sa.text("now()"),
            ),
            # Not nullable and not defaulted to "never". A map without an end
            # is an indefinite copy of customer identifiers.
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )

    existing = _indexes(bind)
    if "uq_token_map_scope" not in existing:
        op.create_index(
            "uq_token_map_scope", _TABLE,
            ["tenant_id", "investigation_id"], unique=True,
        )
    if "ix_token_map_expires_at" not in existing:
        op.create_index("ix_token_map_expires_at", _TABLE, ["expires_at"])


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind):
        op.drop_table(_TABLE)
