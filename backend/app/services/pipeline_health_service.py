"""Is the analysis pipeline actually producing verdicts?

Written because it wasn't, for two hours and thirty-eight minutes, and the only
signal was a person looking at a screen.

What happened on 2026-10-09: migration 055 renamed
`alert_body_investigation_runs.highest_risk_score` to `indicator_risk_score`.
The `api` container was rebuilt. The `worker` and `beat` containers were not —
both had been up 24 hours — so the worker kept asking for a column that no
longer existed and every analysis task died with `UndefinedColumnError`. Last
verdict 10:17:09 UTC, first stuck alert 10:55:09.

What made it invisible is the shape this module exists to break. A stalled
queue looks exactly like a quiet one: alerts in `queued`, no errors on any
page, counts that only go up. The failure state was indistinguishable from a
quiet success — the same shape as a threat feed that failed 6,259 consecutive
times at debug level and surfaced as `threatfox_count = 0`.

So two measurements, both of which must be true for the pipeline to be
working, and neither of which can be satisfied by a stall:

    depth            how many alerts are waiting
    time since last  how long since anything reached a verdict

Depth alone is not enough: a quiet estate has a depth of zero and so does a
pipeline that has crashed with nothing left to try. Time-since-last alone is
not enough either: a genuinely idle Sunday has no recent verdict and nothing
wrong. Together they are decisive — alerts waiting AND nothing completing is a
stall, and that is the only combination this alarms on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

#: How long alerts may sit waiting before something is wrong.
#:
#: The outage this was written for ran 2h38m before a person noticed. The
#: platform's own quiet period is 6 hours and an analysis takes seconds, so a
#: backlog that has not moved in fifteen minutes is not a busy queue.
STALL_AFTER = timedelta(minutes=15)

#: A depth that is worth saying out loud even while the pipeline is moving,
#: because a queue that is growing faster than it drains fails later.
DEPTH_WARNING = 50

_STALL_SQL = """
select
  (select count(*) from alert_body_investigation_runs where status = 'queued')      as queued,
  (select count(*) from alert_body_investigation_runs where status = 'processing')  as processing,
  (select max(completed_at) from alert_body_investigation_runs)                     as last_verdict,
  (select min(created_at) from alert_body_investigation_runs where status = 'queued') as oldest_queued
"""


@dataclass
class PipelineHealth:
    queued: int
    processing: int
    last_verdict_at: datetime | None
    oldest_queued_at: datetime | None
    now: datetime

    @property
    def since_last_verdict(self) -> timedelta | None:
        if self.last_verdict_at is None:
            return None
        stamp = (
            self.last_verdict_at
            if self.last_verdict_at.tzinfo
            else self.last_verdict_at.replace(tzinfo=timezone.utc)
        )
        return self.now - stamp

    @property
    def oldest_wait(self) -> timedelta | None:
        if self.oldest_queued_at is None:
            return None
        stamp = (
            self.oldest_queued_at
            if self.oldest_queued_at.tzinfo
            else self.oldest_queued_at.replace(tzinfo=timezone.utc)
        )
        return self.now - stamp

    @property
    def stalled(self) -> bool:
        """Alerts are waiting and nothing is finishing.

        Both halves are required. An empty queue is not a stall however long
        ago the last verdict was, and a busy queue that is completing work is
        not a stall however deep it is.
        """
        if self.queued <= 0:
            return False
        waited = self.oldest_wait
        if waited is None or waited < STALL_AFTER:
            return False
        since = self.since_last_verdict
        return since is None or since >= STALL_AFTER

    def as_json(self) -> dict[str, Any]:
        return {
            "queued": self.queued,
            "processing": self.processing,
            "last_verdict_at": (
                self.last_verdict_at.isoformat() if self.last_verdict_at else None
            ),
            "seconds_since_last_verdict": (
                int(self.since_last_verdict.total_seconds())
                if self.since_last_verdict
                else None
            ),
            "oldest_queued_seconds": (
                int(self.oldest_wait.total_seconds()) if self.oldest_wait else None
            ),
            "stalled": self.stalled,
            "deep": self.queued >= DEPTH_WARNING,
            "stall_threshold_seconds": int(STALL_AFTER.total_seconds()),
        }


async def check(db: AsyncSession, *, now: datetime | None = None) -> PipelineHealth:
    row = (await db.execute(text(_STALL_SQL))).first()
    health = PipelineHealth(
        queued=int(row.queued or 0),
        processing=int(row.processing or 0),
        last_verdict_at=row.last_verdict,
        oldest_queued_at=row.oldest_queued,
        now=now or datetime.now(timezone.utc),
    )
    if health.stalled:
        # Error, not warning. The outage this was written for produced no log
        # line anyone was looking for, and a warning among warnings is how the
        # next one hides.
        logger.error(
            "analysis_pipeline_stalled queued=%d oldest_wait_minutes=%.0f "
            "minutes_since_last_verdict=%s — alerts are waiting and nothing is "
            "completing. Check that every container running app code was rebuilt "
            "after the last migration: on 2026-10-09 the api was and the worker "
            "was not, and the worker died on every task for 2h38m.",
            health.queued,
            (health.oldest_wait or timedelta()).total_seconds() / 60.0,
            (
                int((health.since_last_verdict or timedelta()).total_seconds() / 60)
                if health.since_last_verdict
                else "never"
            ),
        )
    elif health.queued >= DEPTH_WARNING:
        logger.warning(
            "analysis_queue_deep queued=%d processing=%d — moving, but deeper "
            "than %d; a queue growing faster than it drains fails later",
            health.queued, health.processing, DEPTH_WARNING,
        )
    return health
