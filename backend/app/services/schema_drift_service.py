"""Does the code in this container match the schema in the database?

The outage this exists to prevent: migration 055 renamed a column, `api` was
rebuilt, `worker` and `beat` were not — both had been running 24 hours — and
the worker then died with `UndefinedColumnError` on every analysis task for
two hours and thirty-eight minutes. Nothing alarmed, because a worker dying on
every task and a worker with nothing to do produce the same queue.

The deeper problem is that a rename is not a deployment. `alembic upgrade head`
changes the database for every container at once; rebuilding a container
changes the code for one. Between those two acts, any container still running
the old code is broken, and nothing in the system notices because each half is
individually consistent.

So this compares the two directly: every column the ORM models expect against
every column the database actually has. A mismatch is a deployment that is
half-done, and it is reported at startup — once, loudly, naming the columns —
rather than as an exception per task with the cause buried in a traceback.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

#: Tables worth checking. Not every table in the schema: the point is to catch
#: a half-finished deployment quickly at startup, and the hot path is what
#: breaks first. These are the tables the analysis and correlation paths read
#: on every alert.
WATCHED = (
    "alert_body_investigation_runs",
    "alert_case_spine",
    "alert_graph_entity",
    "alert_graph_edge",
    "alert_log_context",
)


async def columns_the_database_has(db: AsyncSession, table: str) -> set[str]:
    rows = (
        await db.execute(
            text(
                "select column_name from information_schema.columns "
                "where table_schema = 'public' and table_name = :t"
            ),
            {"t": table},
        )
    ).scalars().all()
    return {str(r) for r in rows}


def columns_the_code_expects(table: str) -> set[str]:
    from app.models.database import Base

    mapped = Base.metadata.tables.get(table)
    if mapped is None:
        return set()
    return {column.name for column in mapped.columns}


async def check(db: AsyncSession) -> dict[str, Any]:
    """What the code expects that the database does not have, and vice versa.

    `missing_in_database` is the fatal direction: the code will ask for a
    column that is not there and every query touching it dies. That is exactly
    what happened on 2026-10-09, when the worker still expected
    `highest_risk_score` after migration 055 renamed it.

    `missing_in_code` is the benign direction — a migration has run ahead of a
    rebuild, which is the normal ordering and harmless until something tries to
    write the new column. Reported, not alarmed.
    """
    fatal: dict[str, list[str]] = {}
    ahead: dict[str, list[str]] = {}
    for table in WATCHED:
        expected = columns_the_code_expects(table)
        if not expected:
            continue
        actual = await columns_the_database_has(db, table)
        if not actual:
            continue
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            fatal[table] = missing
        if extra:
            ahead[table] = extra

    if fatal:
        logger.error(
            "schema_drift_fatal tables=%s — this container's code expects "
            "columns the database does not have, so every query touching them "
            "will fail. A migration has run and this container was not "
            "rebuilt. On 2026-10-09 this exact state ran for 2h38m in the "
            "worker while the api was healthy, and nothing alarmed. Details: %s",
            ",".join(sorted(fatal)), fatal,
        )
    elif ahead:
        logger.info(
            "schema_ahead_of_code tables=%s columns=%s — the database has "
            "columns this code does not know about, which is the safe ordering "
            "(migrate, then rebuild) and needs no action until something "
            "writes them",
            ",".join(sorted(ahead)), ahead,
        )
    else:
        logger.info("schema_matches_code tables=%d", len(WATCHED))

    return {
        "ok": not fatal,
        "missing_in_database": fatal,
        "missing_in_code": ahead,
        "tables_checked": list(WATCHED),
    }
