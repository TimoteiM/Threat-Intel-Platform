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
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func, select, update
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertCaseSnapshot, AlertCaseSpine
from app.services.alert_session_service import SCORE_VERSION

logger = logging.getLogger(__name__)

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
) -> AlertCaseSpine:
    """Create or refresh the persisted spine for one session.

    Only the fields a recompute owns are touched. status and assignee are
    written by people, so a recompute that overwrote them would silently undo an
    analyst's work every time the page was opened.
    """
    row = await db.get(AlertCaseSpine, case_key)
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
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        return row

    row.session_seq = session_seq
    row.last_activity_at = max(row.last_activity_at, last_activity_at)
    row.updated_at = now

    # A peak is only a peak of the formula that produced it. Carrying one across
    # a scoring change compares two different questions: the Stealth fix moved a
    # real case 75 -> 100 with no new alerts. On a version change the peak is
    # re-based rather than compared.
    if row.peak_score_version != score_version:
        row.peak_score = score
        row.peak_score_version = score_version
        row.peak_at = now
    elif score > row.peak_score:
        row.peak_score = score
        row.peak_at = now
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
) -> list[str]:
    """Point every dead key inside this session's span at the live one.

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
    dead = (
        await db.execute(
            select(AlertCaseSpine).where(
                AlertCaseSpine.alert_source == source,
                AlertCaseSpine.alert_client == client,
                AlertCaseSpine.entity_host == host,
                AlertCaseSpine.session_started_at >= session_started_at,
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
            .where(AlertCaseSpine.superseded_by_case_key.in_(dead_keys))
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
