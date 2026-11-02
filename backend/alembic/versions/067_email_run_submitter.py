"""Capture the submitter on email_investigation_runs

The endpoint has a session and was discarding the actor, so every new run
became permanently unattributable. Attribution of a submission is only
possible at submission — there is no later point where it can be recovered.

Existing rows get `predates_attribution`, which is the precise claim: an actor
existed and was not recorded. `automated_ingest` would assert no human was
involved, and a human uploaded each of these files.

Idempotent, because `create_all` is a second schema authority — backlog 25.

Revision ID: 067
Revises: 066
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "067"
down_revision = "066"
branch_labels = None
depends_on = None

_TABLE = "email_investigation_runs"


def _columns(bind) -> set[str]:
    inspector = sa.inspect(bind)
    if _TABLE not in set(inspector.get_table_names()):
        return set()
    return {c["name"] for c in inspector.get_columns(_TABLE)}


def upgrade() -> None:
    bind = op.get_bind()
    cols = _columns(bind)
    if not cols or "actor_kind" in cols:
        return

    op.add_column(_TABLE, sa.Column(
        "actor_kind", sa.String(length=32), nullable=False,
        server_default="predates_attribution"))
    op.add_column(_TABLE, sa.Column(
        "actor_user_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column(_TABLE, sa.Column(
        "actor_recorded", sa.String(length=255), nullable=True))
    op.create_index("idx_email_runs_actor", _TABLE, ["actor_kind"])


def downgrade() -> None:
    bind = op.get_bind()
    if "actor_kind" not in _columns(bind):
        return
    try:
        op.drop_index("idx_email_runs_actor", table_name=_TABLE)
    except Exception:  # noqa: BLE001
        pass
    for column in ("actor_recorded", "actor_user_id", "actor_kind"):
        op.drop_column(_TABLE, column)
