"""What a verdict used to be, beside what it is now.

On a platform where verdicts change, a reader who sees only the newest cannot
distinguish a stable assessment from one that flipped two hours ago. That is
a property of the whole store, not of any one investigation.

`live.com` is the case that made it concrete. It concluded
malicious/high/90/block at 12:05 on 2026-10-13 from 25 ThreatFox indicators
that all belonged to other hosts, and was re-analysed to
suspicious/low/40/monitor at 14:41 once the worker was restarted onto the
fixed code. Three report rows exist. `ReportRepository.get_latest` returns
one, ordered by iteration, so every surface served the newest and no surface
said the verdict had moved — the prior assessment survived only in a table
nothing reads.

Derived, not stored
-------------------
For investigations the history already exists: `reports` is append-only, one
row per iteration, each carrying its own verdict in `report_json`. So
supersession is **computed on read** from rows that are already there, per
the layer contract at the top of the README. Two consequences, both wanted:
it works for every historical investigation with no backfill, and it cannot
drift from the reports it describes.

A correction notice is something a person writes once, on one record, that
nobody maintains. This is a field: every future supersession carries its own
history without anyone remembering to add one.

Alert runs are different
------------------------
`alert_body_investigation_runs` holds one row per run with no iteration
history, so there is nothing to derive from and the supersession has to be
recorded. It goes in `result_json["superseded"]` — JSONB, so no migration —
and `withdrawal()` builds it in the same shape the derived one has, so a
reader does not need to know which store it came from.

Both stores or neither: correcting the investigation while the alert run
still asserts the old verdict leaves the two contradicting each other, which
is the same condition in the other direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

#: The four fields a verdict is made of. Named once so the derived and the
#: recorded shapes cannot drift apart.
VERDICT_FIELDS = ("classification", "confidence", "risk_score",
                  "recommended_action")


def _verdict_of(report_json: Any) -> dict[str, Any]:
    body = report_json if isinstance(report_json, dict) else {}
    return {k: body.get(k) for k in VERDICT_FIELDS}


def _differs(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two verdicts are the same assessment.

    Compared on all four fields, not just `classification`: malicious/high
    becoming malicious/low is a change of assessment an analyst should see,
    and comparing only the class would call it stable.
    """
    return any(a.get(k) != b.get(k) for k in VERDICT_FIELDS)


@dataclass(frozen=True)
class Supersession:
    current: dict[str, Any] = field(default_factory=dict)
    #: Earlier verdicts that differ from the current one, oldest first.
    superseded: list[dict[str, Any]] = field(default_factory=list)
    #: Iterations that existed and said the same thing. Counted, not listed:
    #: a re-analysis that reached the same answer is corroboration, not a
    #: change, and listing it would bury the changes.
    unchanged_iterations: int = 0

    @property
    def flipped(self) -> bool:
        return bool(self.superseded)

    def headline(self) -> str | None:
        """The sentence that belongs beside a changed verdict."""
        if not self.superseded:
            return None
        first = self.superseded[0]
        when = first.get("at")
        return (
            f"This verdict changed. It previously read "
            f"{first.get('classification')}/{first.get('confidence')} "
            f"risk {first.get('risk_score')}, action "
            f"{first.get('recommended_action')}"
            + (f", recorded {when}" if when else "")
            + ". The earlier report is kept as the record of what was "
              "concluded then."
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "flipped": self.flipped,
            "current": self.current,
            "superseded": self.superseded,
            "unchanged_iterations": self.unchanged_iterations,
            "headline": self.headline(),
        }


def from_reports(rows: list[Any]) -> Supersession:
    """Derive supersession from this investigation's report rows.

    `rows` are `Report` objects or anything exposing `report_json`,
    `iteration` and `created_at`. Ordered here rather than relying on the
    caller, because the ordering *is* the meaning: `get_latest` sorts by
    iteration then created_at, and a history assembled in a different order
    would name the wrong verdict as current.
    """
    ordered = sorted(
        [r for r in rows if r is not None],
        key=lambda r: (
            getattr(r, "iteration", 0) or 0,
            getattr(r, "created_at", None) or datetime.min,
        ),
    )
    if not ordered:
        return Supersession()

    latest = ordered[-1]
    current = _verdict_of(getattr(latest, "report_json", None))
    superseded: list[dict[str, Any]] = []
    unchanged = 0

    for row in ordered[:-1]:
        verdict = _verdict_of(getattr(row, "report_json", None))
        if not _differs(verdict, current):
            unchanged += 1
            continue
        created = getattr(row, "created_at", None)
        superseded.append({
            **verdict,
            "iteration": getattr(row, "iteration", None),
            "at": created.isoformat() if hasattr(created, "isoformat") else None,
        })

    return Supersession(current=current, superseded=superseded,
                        unchanged_iterations=unchanged)


async def for_investigation(db: AsyncSession, investigation_id) -> Supersession:
    """Every report row for one investigation, reduced to its supersession."""
    from app.models.database import Report

    rows = (
        await db.execute(
            select(Report).where(Report.investigation_id == investigation_id)
        )
    ).scalars().all()
    return from_reports(list(rows))


def withdrawal(
    *,
    classification: str | None,
    confidence: str | None = None,
    risk_score: int | None = None,
    recommended_action: str | None = None,
    reason: str,
    at: str,
    by: str,
) -> dict[str, Any]:
    """A recorded supersession, for stores with no iteration history.

    Same shape as a derived entry plus `reason`/`by`, so a reader does not
    have to know whether it was derived or recorded. Written into
    `alert_body_investigation_runs.result_json["superseded"]`.
    """
    return {
        "flipped": True,
        "superseded": [{
            "classification": classification,
            "confidence": confidence,
            "risk_score": risk_score,
            "recommended_action": recommended_action,
            "at": at,
            "reason": reason,
            "withdrawn_by": by,
        }],
        "unchanged_iterations": 0,
    }


def of_alert_run(result_json: Any) -> Supersession:
    """Read a recorded supersession off an alert run, if one is there."""
    body = result_json if isinstance(result_json, dict) else {}
    rec = body.get("superseded")
    if not isinstance(rec, dict):
        return Supersession(current={
            "classification": body.get("overall_verdict"),
        })
    entries = rec.get("superseded")
    return Supersession(
        current={"classification": body.get("overall_verdict")},
        superseded=[e for e in entries if isinstance(e, dict)]
        if isinstance(entries, list) else [],
        unchanged_iterations=int(rec.get("unchanged_iterations") or 0),
    )
