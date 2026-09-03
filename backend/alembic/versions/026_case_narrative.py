"""
One explanation of the whole case, kept beside the case.

Every alert in a correlated case already carries its own AI resolution, and an
analyst reading eight of them in a row has to assemble the intrusion themselves
— which is the work the correlation was supposed to have done. This stores the
overall reading: what happened, in what order, what it means, and what to do.

Two columns here are about *when not to regenerate*. A correlated case is
recomputed on every page load, and calling a model on every read would spend a
token budget on the fact that someone opened a tab. narrative_fingerprint holds
the score, member count and tactic set the narrative was written from, so a
stale one is detectable and an unchanged one is left alone — the same
change signal that already governs whether a snapshot is appended.

narrative_session_id links the assistant session that produced it, so the
analyst can open the full conversation and its incident graph rather than only
seeing the rendered summary.

Revision ID: 026
Revises: 025
"""

from alembic import op
import sqlalchemy as sa

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_case_spine", sa.Column("narrative_markdown", sa.Text(), nullable=True))
    op.add_column(
        "alert_case_spine",
        sa.Column("narrative_generated_at", sa.DateTime(timezone=True), nullable=True),
    )
    # queued | completed | failed — so a case whose narrative is still being
    # written reads as "being written" rather than as having none.
    op.add_column(
        "alert_case_spine",
        sa.Column("narrative_status", sa.String(20), nullable=True),
    )
    op.add_column(
        "alert_case_spine",
        sa.Column("narrative_fingerprint", sa.String(64), nullable=True),
    )
    op.add_column(
        "alert_case_spine",
        sa.Column("narrative_session_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "alert_case_spine",
        sa.Column("narrative_error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    for column in (
        "narrative_error",
        "narrative_session_id",
        "narrative_fingerprint",
        "narrative_status",
        "narrative_generated_at",
        "narrative_markdown",
    ):
        op.drop_column("alert_case_spine", column)
