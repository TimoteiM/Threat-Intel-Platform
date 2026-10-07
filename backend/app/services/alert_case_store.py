"""Persistence for correlated cases: a thin overlay, never the membership.

Which alerts belong to a case is recomputed from event time on every read and
is never written down. What is written down is the part a human touches — the
assignee, the status, the worst the case ever got — plus the record of how its
score moved, because a case that climbed from 40 to 90 over a day is a
different object from one that arrived at 90, and only stored history can tell
them apart.

Everything here is keyed on the session identity from alert_session_service,
which is derived from the session's first event time. See that module for why
the obvious alternative, an incrementing ordinal, cannot be an identity.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import func, select, update
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertCaseSnapshot, AlertCaseSpine
from app.services.alert_session_service import SCORE_VERSION

logger = logging.getLogger(__name__)


def _as_utc_value(value: datetime) -> datetime:
    """Compare a stored stamp and a computed one on the same footing.

    Postgres hands these back aware, but a freshly built one in the same pass
    may not be, and comparing the two raises.
    """
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# How often a late-arriving alert re-anchored a session and re-identified its
# case. anchor_index returns 0 when it exhausts history without finding a gap,
# and 46.8% of measured walks end that way — every one of those is a latent
# re-identification waiting for an older alert to arrive. With 323-day lags in
# this deployment, supersession is structural rather than exceptional, so the
# rate is worth reading rather than guessing at.
_SUPERSESSION_STATS: dict[str, int] = {"superseded": 0, "chains_collapsed": 0}


def supersession_stats() -> dict[str, int]:
    """How often case identity has moved under a late arrival."""
    return dict(_SUPERSESSION_STATS)


def reset_supersession_stats() -> None:
    _SUPERSESSION_STATS.update({"superseded": 0, "chains_collapsed": 0})


async def supersession_state(db: AsyncSession) -> dict[str, Any]:
    """The durable supersession picture, read from the spine.

    supersession_stats() above counts what THIS process did since it started:
    per-worker, lost on restart, and therefore useless as something to alert on.
    The spine is the record that survives, so anything watching for the first
    real re-anchor has to read this instead.

    Reported rather than merely logged because the supersession gate is the one
    path real data has not yet exercised. Every anchor walk that exhausts
    history without finding a gap — 46.8% of them, measured — is a latent
    re-identification waiting for a late-arriving alert, and this deployment has
    lags up to 323 days. When this count first leaves zero, the case it names is
    worth reading: it is the intersection where a reborn key could double-page
    or inherit a stale reference and go quiet.
    """
    superseded = (
        await db.execute(
            select(func.count())
            .select_from(AlertCaseSpine)
            .where(AlertCaseSpine.superseded_by_case_key.isnot(None))
            .execution_options(query_name="spine_supersession_count")
        )
    ).scalar() or 0

    # The collapse-on-write invariant: nothing may point at a key that itself
    # points somewhere. A violation means a chain was left half-collapsed, which
    # reads exactly like a complete one.
    dead = aliased(AlertCaseSpine)
    target = aliased(AlertCaseSpine)
    violations = (
        await db.execute(
            select(func.count())
            .select_from(dead)
            .join(target, dead.superseded_by_case_key == target.case_key)
            .where(target.superseded_by_case_key.isnot(None))
            .execution_options(query_name="spine_chain_violations")
        )
    ).scalar() or 0

    if violations:
        logger.error(
            "%d supersession pointer(s) target a key that is itself superseded "
            "— collapse-on-write did not hold", violations,
        )

    return {
        "cases_superseded": int(superseded),
        "chain_violations": int(violations),
        # Zero here is not proof the gate works, only that it has not been
        # needed yet. The first non-zero reading is the one to look at.
        "ever_occurred": bool(superseded),
        "this_process": supersession_stats(),
    }


@dataclass(frozen=True)
class SnapshotOutcome:
    """What snapshot_if_changed decided, and everything a firing rule needs.

    Every field here is read from stored rows BEFORE the new snapshot is added
    to the session. That ordering is deliberate: a pending row is a statement
    about now, and every question escalation asks is a question about the past.
    Letting the row being written answer "has this case ever been seen before"
    is the same class of bug as scoring on ingest order.
    """

    snapshot: AlertCaseSnapshot | None
    # True when this row establishes a comparison point rather than recording a
    # change: a case's first snapshot, or the first under a new score_version.
    # Escalation must never fire on a baseline.
    is_baseline: bool
    previous_score: int | None
    # Whether ANY snapshot existed for this case at ANY score_version. This is
    # the field that separates a genuinely new case from a case re-baselined by
    # a formula change — the two are identical under a version-scoped query, and
    # firing "arrived bad" on the second would page once per existing high case
    # the moment new weights deploy.
    had_prior_any_version: bool = False
    # The earliest score recorded under this score_version, and the score the
    # last escalation actually emitted at. Escalation measures from the emission
    # rather than from the previous snapshot, so that lowering the delta later
    # surfaces a crossing that was missed rather than silently swallowing it.
    version_baseline_score: int | None = None
    last_emission_score: int | None = None


async def upsert_spine(
    db: AsyncSession,
    *,
    case_key: str,
    source: str,
    client: str,
    host: str,
    session_started_at: datetime,
    session_seq: int,
    last_activity_at: datetime,
    score: int,
    score_version: str = SCORE_VERSION,
    title: str | None = None,
    known: dict[str, AlertCaseSpine] | None = None,
) -> AlertCaseSpine:
    """Create or refresh the persisted spine for one session.

    `known` is the entity's existing rows, already loaded. Passed in, a miss
    costs nothing; without it every new case is a round trip that finds
    nothing.

    Only the fields a recompute owns are touched. status and assignee are
    written by people, so a recompute that overwrote them would silently undo an
    analyst's work every time the page was opened.
    """
    row = known.get(case_key) if known is not None else await db.get(AlertCaseSpine, case_key)
    now = datetime.now(timezone.utc)

    if row is None:
        row = AlertCaseSpine(
            case_key=case_key,
            alert_source=source,
            alert_client=client,
            entity_host=host,
            session_started_at=session_started_at,
            session_seq=session_seq,
            opened_at=session_started_at,
            last_activity_at=last_activity_at,
            status="open",
            peak_score=score,
            peak_score_version=score_version,
            peak_at=now,
            # The handle a person uses, taken once from the sequence. The key
            # stays a sha256 because it has to be derivable from the events.
            case_number=await next_case_number(db),
            title=title,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        if known is not None:
            known[case_key] = row
        return row

    # Only touch the row when something actually changed. It used to stamp
    # `updated_at` on every recompute, so one page load issued 673 UPDATEs
    # against a table nobody had asked to change — and made `updated_at`
    # useless as a record of when the case last moved, because it meant "when
    # somebody last looked".
    changed = False
    if row.session_seq != session_seq:
        row.session_seq = session_seq
        changed = True
    newest = max(row.last_activity_at, last_activity_at)
    if newest != row.last_activity_at:
        row.last_activity_at = newest
        changed = True
    if row.case_number is None:
        row.case_number = await next_case_number(db)
        changed = True
    # Kept current while the case is open; frozen once it closes, so a
    # continuation that names the case it follows names it the same way the
    # case does.
    if title and row.closed_at is None and row.title != title:
        row.title = title
        changed = True

    # A peak is only a peak of the formula that produced it. Carrying one across
    # a scoring change compares two different questions: the Stealth fix moved a
    # real case 75 -> 100 with no new alerts. On a version change the peak is
    # re-based rather than compared.
    if row.peak_score_version != score_version:
        row.peak_score = score
        row.peak_score_version = score_version
        row.peak_at = now
        changed = True
    elif score > row.peak_score:
        row.peak_score = score
        row.peak_at = now
        changed = True

    if changed:
        row.updated_at = now
    return row


async def snapshot_if_changed(
    db: AsyncSession,
    *,
    case_key: str,
    score: int,
    raw_score: int | None,
    surprise: float | None,
    member_count: int,
    tactics: Iterable[str],
    score_version: str = SCORE_VERSION,
) -> SnapshotOutcome:
    """Append a snapshot only when the case actually moved.

    Recompute runs on every read, so appending unconditionally would record how
    often the page was opened rather than what the case did.

    The previous snapshot is selected filtered to the SAME score_version, and
    that filter is the whole point rather than a detail. Comparing across a
    formula change makes every open case look like it moved the moment new
    weights deploy — a flood that is indistinguishable from mass escalation. On
    a version change the first row per case is therefore a baseline: it records
    the new formula's reading and establishes the point later readings are
    compared against, and it must not be treated as a change event.
    """
    tactic_list = sorted({str(t) for t in tactics if str(t or "").strip()})

    previous = (
        await db.execute(
            select(AlertCaseSnapshot)
            .where(
                AlertCaseSnapshot.case_key == case_key,
                AlertCaseSnapshot.score_version == score_version,
            )
            .order_by(AlertCaseSnapshot.computed_at.desc())
            .limit(1)
            .execution_options(query_name="snapshot_previous")
        )
    ).scalar_one_or_none()

    # Read before anything is added to the session — see SnapshotOutcome.
    any_version = (
        await db.execute(
            select(AlertCaseSnapshot.id)
            .where(AlertCaseSnapshot.case_key == case_key)
            .limit(1)
            .execution_options(query_name="snapshot_any_version")
        )
    ).scalar_one_or_none()
    version_baseline = (
        await db.execute(
            select(AlertCaseSnapshot.score)
            .where(
                AlertCaseSnapshot.case_key == case_key,
                AlertCaseSnapshot.score_version == score_version,
            )
            .order_by(AlertCaseSnapshot.computed_at.asc())
            .limit(1)
            .execution_options(query_name="snapshot_version_baseline")
        )
    ).scalar_one_or_none()
    last_emission = (
        await db.execute(
            select(AlertCaseSnapshot.escalated_to_score)
            .where(
                AlertCaseSnapshot.case_key == case_key,
                AlertCaseSnapshot.score_version == score_version,
                AlertCaseSnapshot.escalated.is_(True),
            )
            .order_by(AlertCaseSnapshot.computed_at.desc())
            .limit(1)
            .execution_options(query_name="snapshot_last_emission")
        )
    ).scalar_one_or_none()
    facts = {
        "had_prior_any_version": any_version is not None,
        "version_baseline_score": version_baseline,
        "last_emission_score": last_emission,
    }

    if previous is not None:
        unchanged = (
            previous.score == score
            and previous.member_count == member_count
            and sorted(previous.tactics or []) == tactic_list
        )
        if unchanged:
            return SnapshotOutcome(
                snapshot=None, is_baseline=False, previous_score=previous.score,
                **facts,
            )

    row = AlertCaseSnapshot(
        case_key=case_key,
        computed_at=datetime.now(timezone.utc),
        score=score,
        raw_score=raw_score,
        surprise=surprise,
        score_version=score_version,
        member_count=member_count,
        tactics=tactic_list,
        escalated=False,
    )
    db.add(row)
    return SnapshotOutcome(
        snapshot=row,
        is_baseline=previous is None,
        previous_score=previous.score if previous is not None else None,
        **facts,
    )


async def absorb_superseded(
    db: AsyncSession,
    *,
    live_case_key: str,
    source: str,
    client: str,
    host: str,
    session_started_at: datetime,
    session_ended_at: datetime,
    known: dict[str, AlertCaseSpine] | None = None,
) -> list[str]:
    """Point every dead key inside this session's span at the live one.

    `known` is the entity's rows, already loaded. With it the candidates are
    selected in memory and the database is touched only when there is
    something to absorb — which is almost never. Without it this ran one
    query per cluster: 1,056 on a single page load, for an answer that was
    empty every time.

    A late-arriving alert can close a gap that previously split two sessions.
    The merged session starts earlier, so it hashes to a key nothing has seen,
    and the spine rows for the sessions it swallowed become unreachable — along
    with their assignee and their snapshot history. Human attention is the
    scarcest thing here, so it is followed forward rather than orphaned.

    Chains COLLAPSE ON WRITE: anything already pointing at a key that died in
    this pass is repointed to the live key in the same transaction. Resolving
    transitively at read would instead make a half-collapsed chain look exactly
    like a complete one — a silent failure, which is the property this build
    keeps removing.
    """
    if known is not None:
        dead = [
            row for row in known.values()
            if row.case_key != live_case_key
            and row.superseded_by_case_key is None
            and _as_utc_value(row.session_started_at) > _as_utc_value(session_started_at)
            and _as_utc_value(row.session_started_at) <= _as_utc_value(session_ended_at)
        ]
        if not dead:
            return []
    else:
        dead = (
            await db.execute(
                select(AlertCaseSpine).where(
                    AlertCaseSpine.alert_source == source,
                    AlertCaseSpine.alert_client == client,
                    AlertCaseSpine.entity_host == host,
                # Strictly later. A session this one swallowed must have
                # started *after* the merged start — that is what being
                # swallowed means.
                #
                # It was `>=`, which also matched every row sharing this
                # session's own start. One session now yields several cases
                # (its alerts are grouped by evidence, not just by time), and
                # they all carry the same session_started_at — so sibling
                # cases cannibalised each other, and a continuation was eaten
                # by the parent it continues. 94 of 96 supersession pointers
                # in the database targeted a row with the same host and the
                # same session start.
                    AlertCaseSpine.session_started_at > session_started_at,
                    AlertCaseSpine.session_started_at <= session_ended_at,
                    AlertCaseSpine.case_key != live_case_key,
                    AlertCaseSpine.superseded_by_case_key.is_(None),
                )
                .execution_options(query_name="spine_superseded")
            )
        ).scalars().all()
        if not dead:
            return []

    dead_keys = [row.case_key for row in dead]
    now = datetime.now(timezone.utc)
    for row in dead:
        row.superseded_by_case_key = live_case_key
        row.status = "superseded"
        row.updated_at = now

    # Collapse: rows that pointed at one of these now point at the survivor.
    collapsed = (
        await db.execute(
            update(AlertCaseSpine)
            .where(
                AlertCaseSpine.superseded_by_case_key.in_(dead_keys),
                # Never point the survivor at itself. Without this, a live case
                # that happened to be pointing at a key dying in this pass was
                # repointed to its own key — 92 rows in the database had
                # superseded_by_case_key = case_key, which resolves forward
                # for ever and makes the case unreachable.
                AlertCaseSpine.case_key != live_case_key,
            )
            .values(superseded_by_case_key=live_case_key, updated_at=now)
        )
    ).rowcount or 0

    _SUPERSESSION_STATS["superseded"] += len(dead_keys)
    _SUPERSESSION_STATS["chains_collapsed"] += int(collapsed)
    logger.info(
        "case %s absorbed %d earlier session(s) on %s after a late arrival "
        "re-anchored them%s",
        live_case_key[:12], len(dead_keys), host,
        f" (collapsed {collapsed} existing pointer(s))" if collapsed else "",
    )
    return dead_keys


async def live_case_key(db: AsyncSession, case_key: str) -> str:
    """Follow a possibly-dead key to the case that carries its history.

    Collapse-on-write means this is a single hop by construction; the loop is a
    guard, not a design. If it ever runs twice the invariant has been broken and
    that is worth knowing about.
    """
    seen: set[str] = set()
    current = case_key
    for hop in range(4):
        row = await db.get(AlertCaseSpine, current)
        if row is None or not row.superseded_by_case_key:
            return current
        if hop > 0:
            logger.warning(
                "supersession chain deeper than one hop at %s — collapse-on-write "
                "did not hold", case_key[:12],
            )
        if row.superseded_by_case_key in seen:
            return current
        seen.add(current)
        current = row.superseded_by_case_key
    return current


# ── the case lifecycle ───────────────────────────────────────────────────────


async def next_case_number(db: AsyncSession) -> int:
    """The next human-facing case number, from the database sequence.

    A sequence rather than `max(case_number) + 1`: two correlation passes can
    open a case in the same instant, and the second would reuse the first's
    number. Gaps from a rolled-back transaction are fine — a case number has
    to be unique and ordered, not contiguous.
    """
    return int((await db.execute(select(func.nextval("alert_case_number_seq")))).scalar_one())


async def claim_for_closure(
    db: AsyncSession, *, case_key: str, now: datetime | None = None,
    stale_after_seconds: int = 600,
) -> bool:
    """Take exclusive responsibility for closing this case.

    The closing job runs every minute and a model call takes longer than that,
    so two runs would otherwise answer the same case twice. The claim is
    conditional in SQL — `WHERE status='open' AND (claim IS NULL OR claim is
    stale)` — so the database decides the winner, not a read followed by a
    write. A claim older than `stale_after_seconds` is reclaimable: a worker
    killed mid-answer must not leave a case unanswerable for ever.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=stale_after_seconds)
    result = await db.execute(
        update(AlertCaseSpine)
        .where(
            AlertCaseSpine.case_key == case_key,
            AlertCaseSpine.status == "open",
            AlertCaseSpine.closed_at.is_(None),
            (AlertCaseSpine.closure_claimed_at.is_(None))
            | (AlertCaseSpine.closure_claimed_at < cutoff),
        )
        .values(closure_claimed_at=now)
    )
    return bool(result.rowcount)


async def close_case(
    db: AsyncSession, *, case_key: str, resolution: str, title: str | None,
    alerts_at_close: int, closed_at: datetime | None = None,
    closure_kind: str = "auto",
    closed_by: str | None = None,
    closure_note: str | None = None,
    narrative_fingerprint: str | None = None,
) -> AlertCaseSpine | None:
    """Record the answer. A closed case is never reopened — see the service.

    The single writer of closure state for every path — automatic, expired,
    inherited and analyst — so the invariant lives in one place. The three
    optional arguments are only ever supplied by a person closing a case; the
    scheduled paths leave them None and are unchanged.
    """
    row = await db.get(AlertCaseSpine, case_key)
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    row.closed_at = closed_at or now
    row.closure_kind = closure_kind
    row.resolution = resolution
    if closed_by:
        row.closed_by = closed_by
    if closure_note:
        row.closure_note = closure_note
    if narrative_fingerprint:
        row.closed_narrative_fingerprint = narrative_fingerprint
    row.alerts_at_close = int(alerts_at_close)
    row.status = "closed"
    if title and not row.title:
        row.title = title
    row.updated_at = now
    return row


async def open_continuation(
    db: AsyncSession, *, case_key: str, continues: str, source: str, client: str,
    host: str, session_started_at: datetime, last_activity_at: datetime, score: int,
    title: str | None = None,
) -> AlertCaseSpine:
    """A case that carries on from one already answered.

    Not a reopening. Closing stops the SLA clock, and a case that could reopen
    hours later would make MTTR meaningless — one straggler at hour sixteen
    turning a four-minute resolution into a sixteen-hour one. This is a case
    of its own, measured on its own, that names the one it follows.
    """
    row = await db.get(AlertCaseSpine, case_key)
    now = datetime.now(timezone.utc)
    if row is not None:
        if not row.continues_case_key:
            row.continues_case_key = continues
            row.updated_at = now
        return row
    row = AlertCaseSpine(
        case_key=case_key,
        alert_source=source,
        alert_client=client,
        entity_host=host,
        session_started_at=session_started_at,
        session_seq=0,
        opened_at=session_started_at,
        last_activity_at=last_activity_at,
        status="open",
        peak_score=score,
        peak_score_version=SCORE_VERSION,
        peak_at=now,
        continues_case_key=continues,
        case_number=await next_case_number(db),
        title=title,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    return row


async def resolve_stranded(
    db: AsyncSession, *, older_than: datetime, resolution: str = "inconclusive",
) -> int:
    """Record closed-but-never-analysed cases as unanswered.

    A case closes the moment it goes quiet, because closing is what stops the
    SLA clock, and it carries `awaiting_analysis` until the narrative task
    writes the verdict over it. That task is a model call behind a broker, so
    it can fail its retries, be dropped, or be queued behind a backlog.

    Without this the placeholder is permanent: the case is closed, has no
    resolution anyone can count, and nothing will ever look at it again
    because closing is a one-way door.

    Deliberately `inconclusive` rather than anything else. The case was never
    assessed, and an unassessed case must neither arrive in the queue as a
    confirmed intrusion nor quietly improve the false-positive rate.

    A case that does have a written analysis is read rather than written off:
    the placeholder then means the write-back failed, not that nothing was
    assessed, and discarding a verdict somebody paid a model to produce would
    be the same mistake in the other direction.

    A narrative still in flight is left alone, so a slow analysis is waited
    for rather than given up on.
    """
    from app.services import alert_case_closure_service as closure

    rows = (
        await db.execute(
            select(
                AlertCaseSpine.case_key,
                AlertCaseSpine.narrative_markdown,
            ).where(
                AlertCaseSpine.closed_at.is_not(None),
                AlertCaseSpine.closed_at < older_than,
                AlertCaseSpine.resolution == closure.AWAITING_ANALYSIS,
                func.coalesce(AlertCaseSpine.narrative_status, "") != "running",
            )
        )
    ).all()
    if not rows:
        return 0

    for case_key, markdown in rows:
        await db.execute(
            update(AlertCaseSpine)
            .where(AlertCaseSpine.case_key == case_key)
            .values(
                resolution=(
                    closure.resolution_from_analysis(markdown)
                    if (markdown or "").strip()
                    else resolution
                ),
                updated_at=func.now(),
            )
        )
    return len(rows)


async def record_closure_attempt(
    db: AsyncSession, *, case_key: str, now: datetime,
) -> None:
    """Note that reading this case back failed, so the next pass can wait.

    Not a write-off. The alerts a case is built from can come back into the
    correlation window, and closing a case because a listing did not contain
    it is the mistake that destroyed 575 cases, 504 of them within two minutes
    of being created, every one with zero alerts and a resolution nobody
    computed. This only buys time.
    """
    await db.execute(
        update(AlertCaseSpine)
        .where(AlertCaseSpine.case_key == case_key)
        .values(
            closure_attempts=func.coalesce(AlertCaseSpine.closure_attempts, 0) + 1,
            closure_attempted_at=now,
        )
    )


async def cases_awaiting_closure(
    db: AsyncSession, *, limit: int = 200, due_before: datetime | None = None,
) -> list[AlertCaseSpine]:
    """The closing job's work queue: the most overdue cases, and the newest due ones.

    Two slices, not one window, because a single oldest-first window starves
    exactly the case the ten-minute promise is about.

    A case the job cannot read stays open and keeps its place at the head of
    an oldest-first queue, so the next pass selects it again, in the same
    position, for ever. It is a blocker, not a backlog. With a hundred of them
    the hundred-row window is entirely blockers and a case that went quiet two
    minutes ago is never selected at all — measured live as
    `{'open': 6, 'closed': 0, 'not_in_listing': 6}` every minute, which is
    zero throughput, and as a median of 127 minutes from last alert to close
    on a day when the promise was ten.

    So half the budget goes to the oldest, which drains a genuine backlog, and
    half to the most recently due, which is reachable however deep the head is
    stuck. A fresh case now waits one pass instead of waiting for the blockers
    to be cleared by hand.

    `due_before` pushes the quiet period into SQL so a case that cannot
    possibly be due does not consume a slot. Omitted, the behaviour is as
    before and the caller filters.
    """
    half = max(1, limit // 2)
    open_rows = (
        AlertCaseSpine.status == "open",
        AlertCaseSpine.closed_at.is_(None),
    )
    due = open_rows + (
        (AlertCaseSpine.last_activity_at <= due_before,) if due_before else ()
    )

    # The most overdue. Drains a real backlog, oldest first, as before.
    oldest = (
        await db.execute(
            select(AlertCaseSpine).where(*due)
            .order_by(AlertCaseSpine.last_activity_at.asc())
            .limit(half)
        )
    ).scalars().all()

    # The newest that is nonetheless due. This is the slice that makes the
    # ten minutes true.
    newest = (
        await db.execute(
            select(AlertCaseSpine).where(*due)
            .order_by(AlertCaseSpine.last_activity_at.desc())
            .limit(half)
        )
    ).scalars().all()

    # Deduplicated on the key, because with fewer cases than the budget both
    # slices return the same rows. Newest first: when the budget binds, the
    # promise that has a deadline is the one kept.
    merged: dict[str, AlertCaseSpine] = {}
    for row in list(newest) + list(oldest):
        merged.setdefault(row.case_key, row)
    return list(merged.values())


async def case_reference(db: AsyncSession, case_key: str | None) -> dict[str, Any] | None:
    """`#12 — EXP-01 / jdoe — Repeated injection-capable access`, for a link."""
    if not case_key:
        return None
    row = await db.get(AlertCaseSpine, case_key)
    if row is None:
        return None
    return {
        "case_key": row.case_key,
        "case_number": row.case_number,
        "title": row.title,
        "status": row.status,
        "resolution": row.resolution,
        "closed_at": row.closed_at.isoformat() if row.closed_at else None,
    }


async def spines_for_entity(
    db: AsyncSession, *, source: str, client: str, host: str,
) -> dict[str, AlertCaseSpine]:
    """Every spine row this entity already has, in one query.

    Correlation reads a spine row twice per cluster — once to ask whether the
    case is closed, once to upsert it — and a *missing* row costs a round trip
    just the same, because `db.get` has nothing to find. At 27 cases that was
    noise; at 941 it was 1,403 round trips and most of a nine-second page
    load, almost all of them misses.

    Loading the entity's rows up front answers both questions from memory: a
    key in the map is the row, a key not in it is a new case. It also tells
    `absorb_superseded` whether there is anything to absorb before it asks.
    """
    rows = await db.execute(
        select(AlertCaseSpine).where(
            AlertCaseSpine.alert_source == source,
            AlertCaseSpine.alert_client == client,
            AlertCaseSpine.entity_host == host,
        )
    )
    return {row.case_key: row for row in rows.scalars().all()}
