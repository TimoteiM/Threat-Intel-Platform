"""When a case is worth interrupting someone, and which interruption it is.

Two events, not two intensities of one. `case.escalated` says something you are
already watching got worse; `case.opened_high` says something arrived already
bad. A consumer routes those differently — one to a queue, one to a page — and
if they cannot tell them apart at subscribe time they tell them apart with a
parser, which is where a real escalation gets classified as noise.

Every decision below is a query against recorded emissions and version-stamped
snapshots. None of it reads a boolean flag, and none of it compares against
now. Every silent bug this feature has produced has been the same bug in
different clothes — a value that depended on when someone looked instead of on
what happened — and escalation, which fires exactly once and then never
re-examines itself, is where that bug would hide best.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertCaseSpine
from app.services.alert_case_store import SnapshotOutcome

logger = logging.getLogger(__name__)

EVENT_ESCALATED = "case.escalated"
EVENT_OPENED_HIGH = "case.opened_high"


@dataclass(frozen=True)
class CaseEvent:
    """One emission, carrying what it was measured against."""

    event: str
    case_key: str
    score: int
    score_version: str
    # What the score is being compared to. None for opened_high, which is not a
    # comparison — that is the whole reason it is a separate event.
    reference_score: int | None
    delta_config: int | None
    min_score_config: int
    reason: str


async def decide_emission(
    db: AsyncSession,
    *,
    case_key: str,
    outcome: SnapshotOutcome,
    score: int,
    score_version: str,
    escalation_delta: int,
    escalation_min_score: int,
    opened_high_min_score: int,
) -> CaseEvent | None:
    """Decide whether this recompute should tell anyone, and which thing to say.

    Returns None far more often than not, which is the point.
    """
    # Nothing moved, so there is nothing to say. A recompute that emitted here
    # would be reporting that someone opened the page.
    if outcome.snapshot is None:
        return None

    if outcome.is_baseline:
        return await _opened_high(
            db, case_key=case_key, outcome=outcome, score=score,
            score_version=score_version, min_score=opened_high_min_score,
        )

    return _escalated(
        outcome=outcome, case_key=case_key, score=score,
        score_version=score_version, delta=escalation_delta,
        min_score=escalation_min_score,
    )


async def _opened_high(
    db: AsyncSession,
    *,
    case_key: str,
    outcome: SnapshotOutcome,
    score: int,
    score_version: str,
    min_score: int,
) -> CaseEvent | None:
    """A case that arrived already bad — three gates, all of them exclusions.

    The trigger looks like "this case's first snapshot", and that naive reading
    is wrong twice over.

    A score_version bump writes one baseline per existing case, and every one of
    those is a first snapshot *at that version* with a high score. Gating on
    "no prior snapshot at this version" would page once per existing high case
    the first time new weights deploy — rebuilding the deploy flood that the
    version-baseline rule was built to prevent, through the other door. The gate
    is therefore "no prior snapshot at ANY version".

    And a late-arriving alert that re-anchors a session produces a genuinely new
    case_key with no prior snapshot at any version — which satisfies that gate
    while not being a new incident at all. It is the same intrusion under a new
    identity, and its history is reachable through the pointer on the key it
    replaced. With 46.8% of anchor walks exhausting history and the rule-1002
    flood on mvapsupm01 already logged, this will happen, and it will happen
    first on the noisiest host in the estate — the worst possible place for a
    spurious page. So a reborn key is excluded too.
    """
    if outcome.had_prior_any_version:
        # A re-baseline under a new scoring version. The case is not new; only
        # the formula measuring it is.
        return None

    reborn = (
        await db.execute(
            select(AlertCaseSpine.case_key)
            .where(AlertCaseSpine.superseded_by_case_key == case_key)
            .limit(1)
            .execution_options(query_name="spine_inbound_supersession")
        )
    ).scalar_one_or_none()
    if reborn is not None:
        logger.info(
            "case %s is the survivor of a supersession, not a new case — "
            "opened_high suppressed", case_key[:12],
        )
        return None

    if score < min_score:
        return None

    return CaseEvent(
        event=EVENT_OPENED_HIGH,
        case_key=case_key,
        score=score,
        score_version=score_version,
        reference_score=None,
        delta_config=None,
        min_score_config=min_score,
        reason=f"first seen already at {score}, at or above the arrival bar of {min_score}",
    )


def _escalated(
    *,
    outcome: SnapshotOutcome,
    case_key: str,
    score: int,
    score_version: str,
    delta: int,
    min_score: int,
) -> CaseEvent | None:
    """A case that got worse than it was.

    Measured from the last score this case actually EMITTED at, not from the
    previous snapshot. That distinction is what the provenance columns were
    added for. Suppose a case moved 40 -> 70 while the delta was set to 40: no
    emission, correctly. Someone later lowers the delta to 20. Comparing
    against the previous snapshot would measure 70 -> 70 and stay silent
    forever, silently swallowing a crossing that is now worth reporting.
    Comparing against the last emission — and falling back to this version's
    baseline when nothing has ever been emitted — surfaces it the next time the
    case moves at all.

    It is idempotent in the other direction too: after emitting at 90 the
    reference becomes 90, so repeated recomputes at 90 say nothing. That
    idempotency is a stored value, never a flag.
    """
    if score < min_score:
        return None

    reference = outcome.last_emission_score
    if reference is None:
        reference = outcome.version_baseline_score
    if reference is None:
        # No comparison point at this version. Cannot be a climb.
        return None

    if (score - reference) < delta:
        return None

    measured = (
        "last emitted at" if outcome.last_emission_score is not None
        else "first recorded at this scoring version as"
    )
    return CaseEvent(
        event=EVENT_ESCALATED,
        case_key=case_key,
        score=score,
        score_version=score_version,
        reference_score=reference,
        delta_config=delta,
        min_score_config=min_score,
        reason=f"climbed to {score} from {reference} ({measured} {reference}), "
               f"a rise of {score - reference} against a threshold of {delta}",
    )


def record_emission(outcome: SnapshotOutcome, event: CaseEvent) -> None:
    """Stamp the emission onto the snapshot that caused it.

    The thresholds in force are written alongside the scores compared, so that
    "have we already fired for this crossing" stays answerable after someone
    edits the config. A boolean alone cannot answer it: retuning the delta would
    either re-notify the backlog or swallow new crossings, with nothing in the
    record to say which happened.
    """
    row = outcome.snapshot
    if row is None:
        return
    row.escalated = True
    row.emitted_event = event.event
    row.escalated_from_score = event.reference_score
    row.escalated_to_score = event.score
    row.escalated_delta_config = event.delta_config
    row.escalated_min_score_config = event.min_score_config
