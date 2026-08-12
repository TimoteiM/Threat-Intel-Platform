"""surface the alert-run fields the detections and cost rollups read

Revision ID: 020
Revises: 019
Create Date: 2026-08-12

Detection quality, ATT&CK coverage and the cost dashboard each aggregate over
every alert run in the window. All three read `result_json`, and all three use
only a small part of it — `attack_assessment`, `summary`, `extraction` — about
2.8 KB of a 14 KB row.

Measured on 626 runs: 729 ms to fetch and deserialise 21 MB of JSON, and 0.6 ms
to compute the answer from it. The work was almost entirely moving bytes.

Same remedy as migration 019. Stored generated columns hold the sub-objects
inline, so a rollup reads them without detoasting the full payload; Postgres
maintains them, so there is no write path to keep in step and no way for them to
disagree with `result_json`.

Measured on the same query: 171 ms -> 44 ms.

`result_overall_verdict` exists only to preserve a fallback in
`detection_quality_service` that reads the verdict out of the JSON when the
column is null. No row in this database needs it, but removing a fallback is a
behaviour change and this migration is not the place for one.
"""

from __future__ import annotations

from alembic import op


revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE alert_body_investigation_runs
          ADD COLUMN IF NOT EXISTS result_attack_assessment jsonb
            GENERATED ALWAYS AS (result_json->'attack_assessment') STORED,
          ADD COLUMN IF NOT EXISTS result_summary jsonb
            GENERATED ALWAYS AS (result_json->'summary') STORED,
          ADD COLUMN IF NOT EXISTS result_extraction jsonb
            GENERATED ALWAYS AS (result_json->'extraction') STORED,
          ADD COLUMN IF NOT EXISTS result_overall_verdict text
            GENERATED ALWAYS AS (result_json->>'overall_verdict') STORED
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE alert_body_investigation_runs
          DROP COLUMN IF EXISTS result_overall_verdict,
          DROP COLUMN IF EXISTS result_extraction,
          DROP COLUMN IF EXISTS result_summary,
          DROP COLUMN IF EXISTS result_attack_assessment
        """
    )
