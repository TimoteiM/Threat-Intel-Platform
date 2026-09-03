"""
A case that survives the page load that computed it.

Membership stays stateless: which alerts belong together is recomputed from
event time on every read, and this migration does not change that. What it adds
is the thin overlay a case needs to be *worked* — an assignee, a status, the
highest score it ever reached, and the record of how it got there.

The identity column is session_started_at, not session_seq, and that is the one
decision in here worth defending. session_seq was the obvious key and it is
wrong: an incrementing ordinal is a function of where the query started, not of
what happened. Measured against stored runs — 27 hosts, 1,080 arbitrary window
boundaries, 53,262 comparisons against the full-history answer:

    ordinal session_seq ................. 95.3% of keys disagreed
    session-start, window cut naively ... 66.5% disagreed
    session-start, walked back to a gap .. 0.0% disagreed

So the key is the session's first event time, session_seq survives only as the
ordinal a human reads ("3rd session on this host"), and the read that assigns
sessions must extend backwards past the window boundary until it finds a gap
wider than the timeout. The 72h hard cap conveniently bounds that walk: no
session can be longer, so no lookback needs to reach further.

One consequence to hold onto. The key is stable under re-querying but not under
re-history: an alert arriving late enough to merge two sessions genuinely moves
the boundary, and the key correctly changes with it. The spine therefore has to
tolerate a never-before-seen case_key adopting an existing case's history —
which is why supersedes_case_key exists rather than the merge silently
orphaning an assignee.

Revision ID: 025
Revises: 024
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_case_spine",
        # hash(alert_source, alert_client, entity_host, session_started_at)
        sa.Column("case_key", sa.String(64), primary_key=True),
        # The four grouping keys are untouched; session_started_at extends them.
        sa.Column("alert_source", sa.String(128), nullable=False),
        sa.Column("alert_client", sa.String(255), nullable=False),
        sa.Column("entity_host", sa.String(255), nullable=False),
        sa.Column("session_started_at", sa.DateTime(timezone=True), nullable=False),
        # Display ordinal only. Never an input to case_key — see the docstring.
        sa.Column("session_seq", sa.Integer, nullable=False, server_default="0"),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("assignee", sa.String(255), nullable=True),
        # peak_score is meaningless without knowing which scoring function
        # produced it: the Stealth fix moved a real case from 75 to 100 without
        # a single alert changing. A peak carried across a scoring change would
        # be a comparison between two different questions.
        sa.Column("peak_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("peak_score_version", sa.String(64), nullable=True),
        sa.Column("peak_at", sa.DateTime(timezone=True), nullable=True),
        # Forward pointer from a dead key to the live one that absorbed it, set
        # when a late-arriving alert closed a gap and re-identified the session.
        # Direction matters: the lookup we need is dead -> live (an analyst
        # follows a stale link, a snapshot hangs off an old key), so the pointer
        # lives on the row that died. A row with this set is dead; status is
        # 'superseded'.
        #
        # Chains COLLAPSE ON WRITE. If C absorbs B and B had already absorbed A,
        # both A and B are repointed to C in the same transaction, so this column
        # always names a live head and reads never follow more than one hop. The
        # alternative — resolving transitively at read — pays for a rare merge on
        # every read, and leaves a half-collapsed chain indistinguishable from a
        # complete one. Two late merges onto the same host will happen; with
        # collapse-on-write the invariant is checkable in one query:
        #   SELECT 1 FROM alert_case_spine d JOIN alert_case_spine t
        #     ON d.superseded_by_case_key = t.case_key
        #   WHERE t.superseded_by_case_key IS NOT NULL;   -- must return nothing
        sa.Column("superseded_by_case_key", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    # The working queue: open cases, most recently active first.
    op.create_index(
        "idx_case_spine_open_activity",
        "alert_case_spine",
        ["last_activity_at"],
        postgresql_where=sa.text("status = 'open'"),
    )
    # Re-finding a session's row from a recomputed assignment.
    op.create_index(
        "idx_case_spine_scope_session",
        "alert_case_spine",
        ["alert_source", "alert_client", "entity_host", "session_started_at"],
    )

    op.create_table(
        "alert_case_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_key", sa.String(64),
                  sa.ForeignKey("alert_case_spine.case_key", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        # Both halves of the product, so a score can be explained later without
        # rebuilding the baseline that produced it.
        sa.Column("score", sa.Integer, nullable=False),
        sa.Column("raw_score", sa.Integer, nullable=True),
        sa.Column("surprise", sa.Float, nullable=True),
        # Stamped at write from the SCORE_VERSION in force. The escalation delta
        # MUST compare against the most recent snapshot carrying the SAME
        # score_version — storing it is not enough on its own. Comparing across a
        # formula change fires spuriously on first deploy of new weights: the
        # Stealth fix alone moved a real case 75 -> 100 with no new alerts.
        sa.Column("score_version", sa.String(64), nullable=False),
        sa.Column("member_count", sa.Integer, nullable=False),
        sa.Column("tactics", postgresql.JSONB, nullable=True),
        # Marks the snapshot that crossed the escalation threshold. Recompute
        # happens on every read, so without a recorded emission the same crossing
        # would re-notify on each page load.
        #
        # The boolean alone is not enough once the thresholds are tunable. "Have
        # we already notified for this crossing" has to stay answerable after
        # someone edits the config: a case escalated under delta=20 must not be
        # treated as already-notified when the delta drops to 10 and a new, lower
        # crossing occurs. So the emission records what it was measured against —
        # the two scores compared, and the thresholds in force at the time.
        # Without these, retuning the delta either re-notifies the whole backlog
        # or silently swallows new legitimate escalations, with no way to tell
        # which one happened.
        sa.Column("escalated", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("escalated_from_score", sa.Integer, nullable=True),
        sa.Column("escalated_to_score", sa.Integer, nullable=True),
        sa.Column("escalated_delta_config", sa.Integer, nullable=True),
        sa.Column("escalated_min_score_config", sa.Integer, nullable=True),
    )
    # Reading a case's history, and finding the previous snapshot to compare
    # against, are the same query in opposite directions.
    op.create_index(
        "idx_case_snapshots_case_time",
        "alert_case_snapshots",
        ["case_key", sa.text("computed_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("idx_case_snapshots_case_time", table_name="alert_case_snapshots")
    op.drop_table("alert_case_snapshots")
    op.drop_index("idx_case_spine_scope_session", table_name="alert_case_spine")
    op.drop_index("idx_case_spine_open_activity", table_name="alert_case_spine")
    op.drop_table("alert_case_spine")
