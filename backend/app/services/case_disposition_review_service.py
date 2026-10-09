"""Cases whose disposition was formed on fewer alerts than they now hold.

Thirty cases in this estate are in that position: 25 `false_positive`, 3
`needs_review`, 2 `inconclusive`. The worst was judged on 2 of the 57 alerts
it now holds. Nothing about them is reopened and no verdict is touched — the
context is made visible and the decision stays with a person.

Whose judgement this is about
-----------------------------
Not the analyst's. **All thirty closed automatically**, with no `closed_by`
recorded, so no human formed any of these verdicts. The flag says so in as
many words, because an analyst reading "this verdict was formed on 5 of the 20
alerts this case now holds" will reasonably ask whose work is being
questioned, and the answer is the platform's.

Two causes, and the larger one is not the one found first
--------------------------------------------------------
    17 of 30   the close anchor: a case was answered CASE_WINDOW after it
               OPENED rather than after its last alert, so alerts the
               correlation was still right to give it arrived afterwards.
               Fixed by moving the anchor; 9,731 of 12,064 memberships
               (80.7%) had been landing after their case closed.
     13 of 30  `opened_at` holding the session's start rather than the case's
               own first alert, so 172 cases were born already past their
               close window and answered on the first pass with no quiet
               period at all. Fixed separately.

Both fixes are forward-looking. They stop the thirty becoming thirty-one; they
cannot revise a conclusion that was already written, which is why these
surface for review rather than being corrected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from app.services.absence import UNPARSED, absent

#: The old member-list cap. `alerts_at_close` was recorded from a list capped
#: at 100, so a row reading exactly 100 is a floor and not a count: the case
#: held at least that many and nothing recorded how many. 24 of the 56 cases
#: flagged here are in that state, and printing "judged on 100" for them
#: asserts a number known to be wrong.
MEMBER_LIST_CAP = 100

#: Resolutions that represent a judgement about the case. `expired` and
#: `merged` are excluded throughout: every such row has `alerts_at_close = 0`,
#: which means the alerts were never counted rather than counted as none, so
#: there is no disposition to have been formed on partial evidence. 199 cases
#: are in that state and they carry `membership_unknown` instead.
DISPOSITIONS = frozenset({
    "true_positive", "false_positive", "needs_review", "inconclusive",
})


@dataclass(frozen=True)
class DispositionReview:
    case_number: int | None
    resolution: str
    judged_on: int
    holds_now: int
    closed_by: str | None
    closed_at: str | None

    @property
    def judged_on_is_known(self) -> bool:
        """Whether the count the verdict was formed on is a count at all.

        Exactly 100 means the recording hit the member-list cap, so the true
        figure is unknown and at least 100. Treating it as 100 understates the
        gap and, worse, states a number we know to be wrong.
        """
        return self.judged_on != MEMBER_LIST_CAP

    @property
    def proportion(self) -> float | None:
        if not self.judged_on_is_known:
            return None
        return self.judged_on / max(self.holds_now, 1)

    @property
    def automatic(self) -> bool:
        return not self.closed_by

    def as_json(self) -> dict[str, Any]:
        return {
            "needs_review": True,
            "resolution": self.resolution,
            "judged_on": (
                self.judged_on
                if self.judged_on_is_known
                else absent(
                    UNPARSED,
                    "How many alerts this verdict was formed on was recorded "
                    f"from a list capped at {MEMBER_LIST_CAP}, so it reads "
                    f"exactly {MEMBER_LIST_CAP} and the true number is "
                    "unknown — at least that many. The gap below is therefore "
                    "a floor.",
                    raw=str(self.judged_on),
                ).as_json()
            ),
            "holds_now": self.holds_now,
            "proportion_judged": (
                round(self.proportion, 3) if self.proportion is not None else None
            ),
            "closed_at": self.closed_at,
            "closed_by": self.closed_by,
            "decided_automatically": self.automatic,
            "attribution": self._attribution(),
            "whose_judgement": self._whose(),
            "what_to_do": (
                "Nothing has been reopened and the resolution is unchanged. "
                "Re-read the case and either confirm the conclusion over its "
                "full set of alerts or change it."
            ),
        }

    def _attribution(self) -> str:
        dated = f" on {self.closed_at[:10]}" if self.closed_at else ""
        if not self.judged_on_is_known:
            return (
                f"This case was resolved {self.resolution.replace('_', ' ')}"
                f"{dated}. How many alerts that conclusion covered was never "
                f"recorded — the count hit a list cap of {MEMBER_LIST_CAP} and "
                f"reads exactly that — so all that is known is: at least "
                f"{MEMBER_LIST_CAP}, against the {self.holds_now} the case "
                "holds now."
            )
        return (
            f"This case was resolved {self.resolution.replace('_', ' ')}"
            f"{dated} over {self.judged_on} alert"
            f"{'' if self.judged_on == 1 else 's'}. It now holds "
            f"{self.holds_now}, so the conclusion covers "
            f"{round((self.proportion or 0) * 100)}% of what is in the case."
        )

    def _whose(self) -> str:
        if self.automatic:
            return (
                "This conclusion was reached automatically, not by an analyst. "
                "The case was answered before the rest of its alerts arrived — "
                "a platform defect in when a case closed, since fixed — so "
                "nobody's assessment is in question here."
            )
        return (
            f"{self.closed_by} signed this case off over {self.judged_on} "
            "alerts. The remainder arrived afterwards because of a platform "
            "defect in when a case closed, since fixed, so the additional "
            "evidence was never available to them."
        )


def review_for(
    *,
    case_number: int | None,
    resolution: str | None,
    alerts_at_close: int | None,
    current_run_ids: Sequence[Any],
    closed_by: str | None = None,
    closed_at: Any = None,
) -> DispositionReview | None:
    """Whether this case's conclusion covers everything it now holds.

    Returns None when there is nothing to say — which is the common case and
    must stay cheap, since this is asked on every case page.
    """
    if resolution not in DISPOSITIONS:
        return None
    if not alerts_at_close or alerts_at_close <= 0:
        # Never counted. Reported as unknown membership elsewhere, not here:
        # a case that was never assessed cannot have been assessed on partial
        # evidence, and saying otherwise would inflate this finding with 199
        # cases that carry no verdict.
        return None
    holds = len({str(r) for r in current_run_ids if r})
    if holds <= alerts_at_close:
        return None
    return DispositionReview(
        case_number=case_number,
        resolution=resolution,
        judged_on=int(alerts_at_close),
        holds_now=holds,
        closed_by=closed_by,
        closed_at=(
            closed_at.isoformat() if hasattr(closed_at, "isoformat") else closed_at
        ),
    )
