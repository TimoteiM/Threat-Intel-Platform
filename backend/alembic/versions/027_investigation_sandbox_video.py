"""
Which investigations have a sandbox recording to play.

The fact lives six levels deep inside a collector's stored JSON, at
items[].domain_intelligence.raw_summary.report_excerpt.analysis.content.video.
Answering "show me the ones with a video" from there means a LIKE across the
whole of every evidence document on every request — unindexable, and it grows
with the corpus rather than with the answer.

So it is derived once, when the analysis concludes, and stored. The column
holds the ANY.RUN task id rather than a boolean: the filter only needs "is it
null", and the page needs the id anyway to build the player.

Revision ID: 027
Revises: 026
"""

from alembic import op
import sqlalchemy as sa

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("sandbox_video_task_id", sa.String(64), nullable=True),
    )
    # Partial: on this corpus 1 investigation in 483 has a recording, so an
    # index over the nulls would be almost entirely dead weight.
    op.create_index(
        "idx_investigations_sandbox_video",
        "investigations",
        ["sandbox_video_task_id"],
        postgresql_where=sa.text("sandbox_video_task_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_investigations_sandbox_video", table_name="investigations")
    op.drop_column("investigations", "sandbox_video_task_id")
