"""Recording which alerts a read was taken over, and spotting divergence.

The decision this implements: a case freezes on **judgement** — a resolution,
a close, a supersession, an analyst's own conclusion. An AI narrative
commissioned early does **not** freeze it, because `analyse_case_now` exists
so an analyst can ask for a read on a live incident, and making that silently
stop the case accepting alerts would give the feature an invisible cost at the
point of use.

So a narrative does not freeze the case. It records what it read.

Why that is worth doing at all, measured
----------------------------------------
Of 1,698 narratives in this estate, **zero** name a single alert — no run id,
no Wazuh alert id — and the five analyst-closed cases name no more than the
1,674 automatic ones. Nothing has ever recorded which alerts a judgement was
formed over.

And the set moves. Simulating today's freeze rule against the real alert
stream over 1,014 derived cases:

    cases that accrete after the freeze       236  (23.3%)
    alert memberships arriving after one    3,197  (57.9%)
    by size: 1 alert 0%, 2-5 48.9%, 6-20 63.2%, 21+ 95.5%
    last late arrival lands median 2.4h after the freeze, p90 13h, max 2.0d

The cause is a mismatch between two constants, not a rare event: the close
window is 10 minutes from opening while `SESSION_GAP` is 6 hours, so an alert
can still belong to the same case long after that case was closed. On cases
holding 21 or more alerts, growing after the freeze is the norm at 95.5%.

A narrative therefore describes a set that changes underneath it most of the
time, and until this table existed there was no way to notice.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import CaseReadSet
from app.services.absence import UNCLASSIFIED, absent

logger = logging.getLogger(__name__)

#: Which derivation produced a read set. Bumped when the membership rules
#: change, so an old set is comparable rather than silently superseded — the
#: same discipline as CASE_KEY_VERSION, which exists because a formula changed
#: once with no migration and orphaned 881 rows.
DERIVATION_VERSION = "2026.10.1-session-gap-6h"

#: Why a read was taken.
NARRATIVE_AUTO = "narrative_auto"            # the quiet-period job
NARRATIVE_REQUESTED = "narrative_requested"  # an analyst pressed "analyse now"
JUDGEMENT = "judgement"                      # a resolution, close or sign-off

REASONS = frozenset({NARRATIVE_AUTO, NARRATIVE_REQUESTED, JUDGEMENT})


async def record_read_set(
    db: AsyncSession,
    *,
    case_key: str,
    run_ids: Iterable[Any],
    reason: str,
    requested_by: str | None = None,
    narrative_fingerprint: str | None = None,
) -> CaseReadSet:
    """Store the alerts this read covered. Non-binding by design."""
    ids = [str(r) for r in run_ids if r]
    row = CaseReadSet(
        id=uuid.uuid4(),
        case_key=case_key,
        read_at=datetime.now(timezone.utc),
        reason=reason if reason in REASONS else JUDGEMENT,
        requested_by=requested_by,
        derivation_version=DERIVATION_VERSION,
        run_ids=ids,
        alert_count=len(ids),
        narrative_fingerprint=narrative_fingerprint,
    )
    db.add(row)
    return row


async def divergence_for(
    db: AsyncSession, *, case_key: str, current_run_ids: Sequence[Any]
) -> dict[str, Any] | None:
    """How the case has changed since its last recorded read.

    Returns None when no read was ever recorded — which is the state of every
    case closed before this table existed, and is reported as an absence
    rather than as "no divergence". Those are different claims: one says the
    set has not moved, the other says nobody wrote down where it started.
    """
    latest = (
        await db.execute(
            select(CaseReadSet)
            .where(CaseReadSet.case_key == case_key)
            .order_by(CaseReadSet.read_at.desc())
            .limit(1)
        )
    ).scalars().first()
    if latest is None:
        return {
            "read_set": absent(
                UNCLASSIFIED,
                "No read set was recorded for this case, so there is nothing "
                "to compare its current alerts against. Every case judged "
                "before this was recorded is in that position: of 1,698 "
                "narratives in this estate, none names the alerts it was "
                "written over.",
            ).as_json()
        }

    read = {str(r) for r in (latest.run_ids or [])}
    now = {str(r) for r in current_run_ids if r}
    added = sorted(now - read)
    removed = sorted(read - now)
    return {
        "read_at": latest.read_at.isoformat(),
        "reason": latest.reason,
        "requested_by": latest.requested_by,
        "derivation_version": latest.derivation_version,
        "alerts_read": len(read),
        "alerts_now": len(now),
        "added_since": added,
        "removed_since": removed,
        "diverged": bool(added or removed),
        # Said in words, because a reader seeing only counts would take the
        # conclusion as current. 57.9% of all alert memberships in this estate
        # arrive after a freeze, so divergence is the normal case and not an
        # anomaly.
        "note": (
            (
                f"{len(added)} alert(s) joined this case after its conclusion "
                "was written, so that conclusion describes "
                f"{len(read)} alerts and the case now holds {len(now)}. The "
                "conclusion has not been revised."
            )
            if added
            else (
                f"{len(removed)} alert(s) that the conclusion covered are no "
                "longer in this case."
            )
            if removed
            else None
        ),
    }


def divergence_is_material(divergence: dict[str, Any] | None) -> bool:
    """Whether a reader needs telling. Any addition is material: the point is
    that a judgement no longer covers everything in the case."""
    if not divergence or divergence.get("read_set"):
        return False
    return bool(divergence.get("added_since") or divergence.get("removed_since"))
