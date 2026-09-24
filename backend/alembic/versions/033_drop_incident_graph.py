"""
Drop the stored incident graphs.

The graph was a per-session interpretation of the alert rendered as nodes and
edges. It is being removed because it stopped earning its cost: at this alert
volume nobody reads it, and it is heavy in the one place heaviness hurts most.

Measured before writing this:

    alert_body_investigation_runs   13,192 of 13,226 rows carry one    127 MB
    assistant_sessions              21,370 of 21,527 rows carry one    310 MB
    largest single graph                                          1,836,436 chars

437 MB inside `result_json`, which is read whole to render a run and scanned in
full by the detection-quality, ATT&CK-coverage and cost rollups. That is the
"loads harder and harder" — a 1.8 MB graph detoasted to show a report nobody
looked at.

Batched deliberately. `result_json - 'incident_graph'` rewrites every row it
touches, and rewriting 34,000 rows holding hundreds of megabytes in one
transaction would hold a lock long enough to matter on a live ingest. A
thousand rows at a time commits as it goes, and re-running is harmless because
the predicate only matches rows that still have the key.
"""

from alembic import op
import sqlalchemy as sa

revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None

BATCH = 1000


def _strip(conn, table: str, path: str) -> int:
    """Remove the key from one table, a batch at a time. Returns rows changed."""
    total = 0
    while True:
        if path == "root":
            sql = sa.text(
                f"UPDATE {table} SET result_json = result_json - 'incident_graph' "
                f"WHERE id IN (SELECT id FROM {table} WHERE result_json ? 'incident_graph' LIMIT :n)"
            )
        else:
            sql = sa.text(
                f"UPDATE {table} SET result_json = jsonb_set("
                f"  result_json, '{{ai_report}}', (result_json->'ai_report') - 'incident_graph') "
                f"WHERE id IN (SELECT id FROM {table} "
                f"             WHERE result_json->'ai_report' ? 'incident_graph' LIMIT :n)"
            )
        changed = conn.execute(sql, {"n": BATCH}).rowcount
        total += changed
        if changed < BATCH:
            return total


def upgrade() -> None:
    conn = op.get_bind()
    runs = _strip(conn, "alert_body_investigation_runs", "ai_report")
    sessions = _strip(conn, "assistant_sessions", "root")
    print(f"[033] incident graph removed from {runs} alert run(s) and {sessions} assistant session(s)")


def downgrade() -> None:
    # Nothing to restore: the graphs were derived from reports that are still
    # here, and inventing empty ones would be worse than their absence.
    pass
