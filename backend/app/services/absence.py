"""A value that is not there, carrying the reason it is not there.

This is a type rather than a convention because the convention kept being
re-decided. Five places in this platform had independently arrived at the same
answer — report the absence, never render it as zero or blank:

    a case whose alerts come from a source with no field map   (#1106)
    an identifier that failed its shape check                   (unparsed)
    a host nobody has classified                                (crown jewel)
    a case key that no longer resolves to anything              (target unknown)
    an alert whose source states no severity                    (unrated)
    a threat feed that has never once answered                  (check failed)

and each one was implemented separately. A sixth would have been implemented
as a blank, because a doc comment cannot stop that and a type can: a renderer
handed an `Absent` has nothing to display except the reason, so there is no
path by which "we did not look" renders identically to "we looked and found
nothing".

The distinction matters more here than in most software. Every one of the five
came from a real defect where a blank was read as a measurement: a case key's
404 reading as "no attack here", 7,260 unscored alerts ranking as least
severe, 175 cases whose `alerts_at_close = 0` meaning "never counted" and
rejecting 209 valid matches, and a graph that drew nothing on an unreadable
source. Absence and zero are different claims and this makes them different
types.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Why a value is missing. Each one is a distinct claim about what happened,
#: and none of them means "the measured value is zero".
NO_FIELD_MAP = "no_field_map"          # this platform cannot read this source
UNPARSED = "unparsed"                  # a value was present and failed its shape check
UNCLASSIFIED = "unclassified"          # nobody has made this judgement yet
TARGET_UNKNOWN = "target_unknown"      # the thing it points at cannot be found
UNRATED = "unrated"                    # the source states no value
NEVER_OBSERVED = "never_observed"      # the check ran and has never once matched
CHECK_FAILED = "check_failed"          # the check could not run at all
#: There is not enough history to measure the thing being asked for. Distinct
#: from `never_observed`, which says a check ran and never matched, and from
#: `unrated`, which says a source states no value: here the check is sound and
#: the subject simply has too short a record to be judged. Added for the ingest
#: freshness alarm, where a source seen twice has no cadence to be late against
#: and calling that "fresh" would be the blank-as-measurement bug the whole
#: convention exists to stop.
TOO_LITTLE_HISTORY = "too_little_history"
#: An absence whose kind this code did not recognise. Its own bucket, because
#: degrading an unrecognised kind into `unparsed` would file it under a kind
#: that *means* something — the convention's own failure mode implemented
#: inside the convention. The original string travels as `raw`.
UNRECOGNISED = "unrecognised_absence"

KINDS = frozenset({
    NO_FIELD_MAP, UNPARSED, UNCLASSIFIED, TARGET_UNKNOWN, UNRATED,
    NEVER_OBSERVED, CHECK_FAILED, TOO_LITTLE_HISTORY, UNRECOGNISED,
})


@dataclass(frozen=True)
class Absent:
    """Not a value. A reason there is no value.

    `reason` is a sentence an analyst reads, not a code. It says what was not
    done, because the failure mode being prevented is a reader concluding that
    something was checked and came back clean.

    `raw` carries what was actually there when something was — the one-character
    account name, the unreadable source's own name — so a parser bug stays
    visible instead of being swallowed by the guard that caught it.
    """

    kind: str
    reason: str
    raw: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            # Not an exception: an unanticipated kind is still an absence, and
            # raising here would turn "we could not describe why" into a 500.
            #
            # But not `unparsed` either. Filing an unrecognised kind under a
            # kind that means something is this convention's own failure mode
            # committed inside the convention, so it gets its own bucket and
            # the original string is kept.
            original = self.kind
            object.__setattr__(self, "kind", UNRECOGNISED)
            if self.raw is None:
                object.__setattr__(self, "raw", str(original)[:200])

    def as_json(self) -> dict[str, Any]:
        """The shape every renderer handles. Deliberately not a bare string:
        a string would be rendered as a value."""
        return {
            "absent": True,
            "kind": self.kind,
            "reason": self.reason,
            "raw": self.raw,
        }


def absent(kind: str, reason: str, raw: Any = None) -> Absent:
    return Absent(kind=kind, reason=reason, raw=None if raw is None else str(raw)[:200])


def is_absent(value: Any) -> bool:
    return isinstance(value, Absent) or (
        isinstance(value, dict) and value.get("absent") is True
    )


def value_or_absence(value: Any) -> Any:
    """What goes in a payload: the value, or the absence as JSON.

    Note what this does *not* do: it never converts an absence to 0, "", or
    null. A null in a payload is indistinguishable from a field the caller
    forgot to set, which is how the five cases above each became a blank.
    """
    if isinstance(value, Absent):
        return value.as_json()
    return value


#: Why a historical case's membership cannot be recovered.
#:
#: Written as a constant, and at length, so that nobody repeats the
#: measurement in six months. Every source that could have named the alerts a
#: closed case was judged over was checked on 2026-10-09:
#:
#:   alert_case_spine.narrative_markdown   1,698 of 1,701 rows with a positive
#:                                         alerts_at_close carry a narrative;
#:                                         zero contain a run id or a Wazuh
#:                                         alert id
#:   assistant_entries via
#:   spine.narrative_session_id            all 1,811 sessions resolve and all
#:                                         1,698 candidates have stored prompt
#:                                         text; 60 prompts contain a UUID and
#:                                         none of those is a real run id —
#:                                         they are processGuids and session
#:                                         ids from log content
#:   alert_case_snapshots (5,203)          holds member_count: a count, not a set
#:   reports (3,153),
#:   investigation_case_chat_messages (38),
#:   client_alerts (26)                    keyed on investigation_id, the
#:                                         indicator path, not on case_key
#:   analyst_feedback                      5 rows in total
#:   watchlist_alerts, email_investigations  empty
#:   alert_graph_entity / alert_graph_edge link run to entity, not case to run,
#:                                         and were written by a 2026-10-09
#:                                         backfill, so they are today's
#:                                         derivation and not evidence
#:   the outbound callback payload         sent and never persisted; no
#:                                         outbound log table exists
#:
#: Breakdown by closure kind, which kills the obvious hypothesis that
#: human-judged cases recorded more: auto 1,674 rows, inherited 22, analyst 5
#: — all three name zero. This platform has never recorded which alerts a
#: person was looking at when they made a judgement, and that is the gap
#: freezing membership closes going forward rather than one a backfill can
#: close backwards.
MEMBERSHIP_UNRECOVERABLE = (
    "The alerts this case was judged over were never recorded. Its narrative, "
    "the prompt that produced it, the score snapshots and every other stored "
    "artefact give a count and never a set — checked exhaustively on "
    "2026-10-09 across narratives, assistant prompts, case snapshots, reports, "
    "chat messages, analyst feedback and the graph tables. Re-deriving "
    "membership today would produce today's answer, not the set that was "
    "assessed, so it is reported as unknown rather than reconstructed."
)


def membership_unknown(case_number: int | None = None) -> Absent:
    """The absence a historical case carries in place of a frozen member set."""
    return absent(
        UNCLASSIFIED,
        MEMBERSHIP_UNRECOVERABLE,
        raw=f"case #{case_number}" if case_number is not None else None,
    )


def reason_of(value: Any) -> str | None:
    if isinstance(value, Absent):
        return value.reason
    if isinstance(value, dict) and value.get("absent"):
        return str(value.get("reason") or "") or None
    return None
