"""Persisting the log context, and deciding what is still owed.

The read of a live alert's window happens twice — once when the alert arrives,
once after the window has closed. Everything in here exists to make the second
read safe to repeat: it starts from a stored high-water mark, merges on the
document's own identity, and never moves the mark backwards.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import AlertLogContext
from app.services.alert_log_context_service import LogContext, merge_logs

logger = logging.getLogger(__name__)

# The states that still owe a read.
PENDING_STATUSES = ("partial", "unavailable")
TERMINAL_STATUSES = frozenset({"collected", "empty", "skipped", "failed"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return _aware(value)
    if not value:
        return None
    try:
        return _aware(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return None


def save(db: Session, run_id: uuid.UUID, context: LogContext) -> AlertLogContext | None:
    """Write the first read, creating the row or merging into an existing one.

    Merging rather than replacing matters even on the first write: a run
    re-analysed by hand calls this again, and replacing would throw away logs a
    follow-up had already fetched.
    """
    window = context.window or {}
    start = _parse(window.get("start"))
    end = _parse(window.get("end"))
    covered = _parse(window.get("covered_until"))
    if start is None or end is None or covered is None:
        # No window means nothing to follow up — a skipped or unreadable
        # context is reported on the run and needs no row of its own.
        return None

    settings = get_settings()
    row = db.execute(
        select(AlertLogContext).where(AlertLogContext.run_id == run_id)
    ).scalars().first()

    created = row is None
    if row is None:
        row = AlertLogContext(
            id=uuid.uuid4(),
            run_id=run_id,
            window_start=start,
            window_end=end,
            covered_until=covered,
            logs=[],
        )
        db.add(row)

    row.status = context.status
    row.reason = context.reason
    row.truncated = bool(context.truncated or row.truncated)
    row.selectors = context.selectors or {}
    row.sources = context.sources or {}
    row.logs = merge_logs(row.logs or [], context.logs or [])
    # Never backwards: a follow-up that read less than an earlier pass must not
    # re-open ground already covered.
    row.covered_until = max(_aware(row.covered_until) or covered, covered)
    row.updated_at = _now()
    row.next_attempt_at = (
        None if context.status in TERMINAL_STATUSES
        else _aware(end) + timedelta(seconds=int(settings.alert_log_followup_delay_seconds))
    )
    # The analysis runs immediately after this, over exactly these records.
    # Anything that arrives later is something the verdict never saw.
    row.logs_at_analysis = len(row.logs or [])
    row.analysed_at = _now()

    try:
        db.commit()
    except IntegrityError:
        # Another worker created the row for this run a moment ago. Theirs is
        # the record; merge into it rather than failing the alert.
        db.rollback()
        if not created:
            raise
        return save(db, run_id, context)
    db.refresh(row)
    return row


def record_attempt(db: Session, row: AlertLogContext, context: LogContext) -> AlertLogContext:
    """Fold a follow-up read into the stored record."""
    settings = get_settings()
    row.attempts = int(row.attempts or 0) + 1
    row.logs = merge_logs(row.logs or [], context.logs or [])
    row.truncated = bool(context.truncated or row.truncated)
    if context.selectors:
        row.selectors = context.selectors
    if context.sources:
        merged_sources = dict(row.sources or {})
        merged_sources.setdefault("follow_ups", [])
        merged_sources["follow_ups"] = list(merged_sources["follow_ups"]) + [context.sources]
        row.sources = merged_sources

    covered = _parse((context.window or {}).get("covered_until"))
    if covered:
        row.covered_until = max(_aware(row.covered_until) or covered, covered)

    window_end = _aware(row.window_end)
    if context.status in ("collected", "empty", "partial") and row.covered_until >= window_end:
        # The whole window has now been read. Which terminal state depends on
        # whether anything was in it, not on what the last slice returned.
        row.status = "collected" if row.logs else "empty"
        row.reason = None if row.logs else "No logs matched this device or account in the window."
        row.next_attempt_at = None
    elif context.status in ("skipped", "failed"):
        row.status = context.status
        row.reason = context.reason
        row.next_attempt_at = None
    else:
        row.status = "partial" if context.status != "unavailable" else "unavailable"
        row.reason = context.reason
        row.last_error = context.reason if context.status == "unavailable" else row.last_error
        if row.attempts >= int(settings.alert_log_followup_max_attempts):
            # A cluster that has been unreachable for five tries is not going
            # to answer on the sixth within this alert's useful lifetime. Stop,
            # and say so on the record rather than retrying for ever.
            row.status = "failed"
            row.reason = (
                f"Gave up after {row.attempts} attempts to read the remainder of the window. "
                + (context.reason or "")
            ).strip()
            row.next_attempt_at = None
        else:
            row.next_attempt_at = _now() + timedelta(
                seconds=int(settings.alert_log_followup_delay_seconds) * row.attempts
            )

    row.updated_at = _now()
    db.commit()
    db.refresh(row)
    return row


def due(db: Session, *, limit: int = 50, now: datetime | None = None) -> list[AlertLogContext]:
    """Rows whose window has closed and which still owe a read."""
    now = now or _now()
    return list(
        db.execute(
            select(AlertLogContext)
            .where(
                AlertLogContext.status.in_(PENDING_STATUSES),
                AlertLogContext.next_attempt_at.isnot(None),
                AlertLogContext.next_attempt_at <= now,
            )
            .order_by(AlertLogContext.next_attempt_at.asc())
            .limit(limit)
        ).scalars().all()
    )


def for_run(db: Session, run_id: uuid.UUID) -> AlertLogContext | None:
    return db.execute(
        select(AlertLogContext).where(AlertLogContext.run_id == run_id)
    ).scalars().first()


def as_payload(row: AlertLogContext | None, *, include_logs: bool = True) -> dict[str, Any]:
    """The shape the run report and the API show."""
    if row is None:
        return {"status": "unavailable", "log_count": 0, "logs": []}
    payload: dict[str, Any] = {
        "status": row.status,
        "reason": row.reason,
        "log_count": len(row.logs or []),
        "truncated": bool(row.truncated),
        "window": {
            "start": _aware(row.window_start).isoformat(),
            "end": _aware(row.window_end).isoformat(),
            "covered_until": _aware(row.covered_until).isoformat(),
            "complete": _aware(row.covered_until) >= _aware(row.window_end),
        },
        "selectors": row.selectors or {},
        "sources": row.sources or {},
        "attempts": int(row.attempts or 0),
    }
    payload.update(analysis_basis(row))
    if include_logs:
        payload["logs"] = row.logs or []
    return payload


def analysis_basis(row: AlertLogContext) -> dict[str, Any]:
    """How much of the log context the stored analysis was formed from.

    Three states, and the middle one is the reason this exists:

    ``complete``  the analysis saw every log this window holds
    ``partial``   logs arrived after the analysis ran; it never saw them
    ``unknown``   the row predates this being recorded

    An analysis presented as complete when it was formed on a third of the
    window is worse than having no log context at all, because it reads as
    though the quiet half was checked and found quiet.
    """
    total = len(row.logs or [])
    seen = row.logs_at_analysis
    if seen is None:
        return {
            "analysis_basis": "unknown",
            "analysis_saw_logs": None,
            "new_logs_since_analysis": None,
            "analysis_note": "This run predates log-context tracking.",
        }

    new = max(0, total - int(seen))
    window_complete = _aware(row.covered_until) >= _aware(row.window_end)
    if new == 0 and window_complete:
        return {
            "analysis_basis": "complete",
            "analysis_saw_logs": int(seen),
            "new_logs_since_analysis": 0,
            "analysis_note": None,
        }
    if new == 0:
        return {
            "analysis_basis": "partial",
            "analysis_saw_logs": int(seen),
            "new_logs_since_analysis": 0,
            "analysis_note": (
                "The alert is live and the rest of its window has not been read yet. "
                "The analysis covers the logs retrieved so far."
            ),
        }
    return {
        "analysis_basis": "partial",
        "analysis_saw_logs": int(seen),
        "new_logs_since_analysis": new,
        "analysis_note": (
            f"{new} log event{'s' if new != 1 else ''} arrived after this analysis was written "
            "and were not considered in its verdict. Re-run the analysis to include them."
        ),
    }


def mark_analysed(db: Session, row: AlertLogContext) -> AlertLogContext:
    """Record that an analysis has just been formed over everything now stored."""
    row.logs_at_analysis = len(row.logs or [])
    row.analysed_at = _now()
    row.updated_at = _now()
    db.commit()
    db.refresh(row)
    return row


# Failures worth retrying once the operator has fixed something. A refused
# query or an alert with no queryable entity is not one of them — retrying
# those produces the same answer for ever.
RECOVERABLE_MARKERS = (
    "ca bundle", "certificate", "tls", "ssl",
    "no opensearch node answered", "not configured", "connecterror", "timeout",
    # A run that had no verified tenant when its window was read has no cluster
    # it is entitled to query — correctly, at that moment. But a tenant can be
    # assigned afterwards, by a backfill or by an analyst, and then the same
    # window is readable. Found live: 15 contexts failed this way while their
    # runs sat in the deploy gap, and migration 031 gave every one of them a
    # tenant minutes later.
    "no verified tenant",
)


def recoverable(row: AlertLogContext, *, tenant_id: str | None = None) -> bool:
    """Whether retrying could now produce a different answer.

    `tenant_id` is the run's tenant *as it stands today*, which is the whole
    point for the no-tenant case: the failure is only recoverable once the run
    actually has one.
    """
    text = f"{row.reason or ''} {row.last_error or ''}".casefold()
    if "no verified tenant" in text:
        return bool(tenant_id)
    return any(marker in text for marker in RECOVERABLE_MARKERS)


def reopen_for_retry(db: Session, rows: Sequence[AlertLogContext], *, now: datetime | None = None) -> dict[str, Any]:
    """Put recoverable rows back in the queue after an outage is fixed.

    Attempts are reset, because the five that were spent proving the CA was
    missing say nothing about whether the cluster answers now.

    A window older than the cluster's retention is *not* reopened: the indices
    that held those logs have rolled away, so the retry would spend a query to
    learn that. It is marked `expired` instead, which is the truthful outcome
    and distinguishable from "we never tried".
    """
    settings = get_settings()
    now = now or _now()
    horizon = now - timedelta(days=int(getattr(settings, "opensearch_retention_days", 120)))

    # One query rather than one per row: the run's tenant is what decides a
    # no-tenant failure, and these are swept in batches of hundreds.
    from app.models.database import AlertBodyInvestigationRun

    tenants: dict[Any, str | None] = {}
    if rows:
        tenants = {
            run_id: tenant
            for run_id, tenant in db.execute(
                select(AlertBodyInvestigationRun.id, AlertBodyInvestigationRun.tenant_id)
                .where(AlertBodyInvestigationRun.id.in_([r.run_id for r in rows]))
            ).all()
        }

    reopened, expired, skipped = 0, 0, 0
    for row in rows:
        if not recoverable(row, tenant_id=tenants.get(row.run_id)):
            skipped += 1
            continue
        if _aware(row.window_end) < horizon:
            row.status = "expired"
            row.reason = (
                "The logs for this window have aged out of the cluster's retention "
                f"(~{int(getattr(settings, 'opensearch_retention_days', 120))} days), so there is "
                "nothing left to retrieve."
            )
            row.next_attempt_at = None
            expired += 1
            continue
        row.status = "partial"
        row.attempts = 0
        row.last_error = None
        row.reason = "Queued for retry after the connection to the log cluster was restored."
        row.next_attempt_at = now
        reopened += 1
    for row in rows:
        row.updated_at = now
    db.commit()
    return {"reopened": reopened, "expired": expired, "skipped_not_recoverable": skipped}


def retryable(db: Session, *, limit: int = 500) -> list[AlertLogContext]:
    """Every row a recovery pass should look at."""
    return list(
        db.execute(
            select(AlertLogContext)
            .where(AlertLogContext.status.in_(("unavailable", "failed", "skipped")))
            .order_by(AlertLogContext.window_end.desc())
            .limit(limit)
        ).scalars().all()
    )


def combine_for_case(rows: Sequence[AlertLogContext], *, max_logs: int | None = None) -> dict[str, Any]:
    """One log set for a correlated case: every member's window, deduplicated.

    Members of a case overlap — alerts minutes apart on one host produce windows
    that share most of their logs — so the union is substantially smaller than
    the sum, and a case report that simply concatenated them would show the same
    line five times.
    """
    settings = get_settings()
    cap = int(max_logs if max_logs is not None else settings.alert_log_case_max_hits)

    logs: list[dict[str, Any]] = []
    windows: list[dict[str, Any]] = []
    indices: set[str] = set()
    statuses: list[str] = []
    for row in rows:
        logs = merge_logs(logs, row.logs or [])
        statuses.append(row.status)
        windows.append({
            "run_id": str(row.run_id),
            "start": _aware(row.window_start).isoformat(),
            "end": _aware(row.window_end).isoformat(),
            "complete": _aware(row.covered_until) >= _aware(row.window_end),
        })
        for name in (row.sources or {}).get("indices") or []:
            indices.add(str(name))

    truncated = len(logs) > cap
    return {
        # A case is only as complete as its least complete member: one alert
        # still waiting on its window means the case's picture is not final.
        "status": ("partial" if any(s in PENDING_STATUSES for s in statuses)
                   else ("collected" if logs else "empty")),
        "log_count": len(logs[:cap]),
        "unique_before_cap": len(logs),
        "truncated": truncated,
        "member_windows": windows,
        "sources": {"indices": sorted(indices), "member_count": len(rows)},
        "logs": logs[:cap],
    }


def attach_to_case(db: Session, case: dict[str, Any] | None) -> dict[str, Any] | None:
    """Give a correlated case the union of its members' logs.

    Each member already has its own window, read around *its* own timestamp —
    which is what the requirement asks for and is also the only correct reading:
    a case spanning forty minutes has no single instant to centre ten minutes
    on. Combining them here is a union over documents already fetched, so it
    costs a query against Postgres and nothing against the log cluster.

    Members ingested before this feature existed have no row. They are counted
    and named rather than passed over, because a case whose logs cover four of
    its six alerts must not read as though it covers all six.
    """
    if not case:
        return case

    members = case.get("alerts") or []
    run_ids: list[uuid.UUID] = []
    for member in members:
        try:
            run_ids.append(uuid.UUID(str(member.get("run_id"))))
        except (TypeError, ValueError):
            continue
    if not run_ids:
        return case

    rows = list(
        db.execute(select(AlertLogContext).where(AlertLogContext.run_id.in_(run_ids)))
        .scalars()
        .all()
    )
    payload = combine_for_case(rows)
    covered = {str(r.run_id) for r in rows}
    payload["members_with_logs"] = len(covered)
    payload["members_total"] = len(run_ids)
    payload["members_without_logs"] = [str(r) for r in run_ids if str(r) not in covered]
    case["log_context"] = payload
    return case

