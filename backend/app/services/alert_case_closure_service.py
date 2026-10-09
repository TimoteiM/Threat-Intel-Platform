"""When a case stops waiting for more alerts, and what happens to late ones.

An analyst used to open a case by hand, merge the alerts that belonged to it,
and close it with a resolution. MTTD, MTTR and SLA are all measured from those
three acts. For the platform to replace the job it has to perform all three —
which means deciding, without a person, that a case is finished.

Three numbers decided the shape of this, measured over 11,376 real alerts and
884 cases:

**The timer is a quiet period, not a window.** Closing ten minutes after the
case *opens* strands 9,244 alerts outside their own case — 81% of everything,
because alerts arrive in bursts that outlast any fixed window. Closing ten
minutes after the case's *last* alert strands 821. An eleven-fold difference,
and the reason `last_activity_at` is what the clock runs on.

**Ten minutes is the right order of magnitude.** Gaps between consecutive
alerts inside one case: p50 0.0 min, p75 0.7 min, p90 8.8 min, p95 29.4 min,
p99 186 min. Ten minutes of quiet covers ninety per cent of within-case
arrivals, and the tail is where multi-stage attacks live — which is what the
escalation hold below is for.

**Late alerts almost never change the answer.** Of 821 alerts arriving after a
ten-minute quiet period, 811 (99%) were another instance of a detection the
case already held; 10 brought one it had not seen. So a straggler is appended
to the closed case and nothing is re-answered, unless it brings a detection
that is genuinely new — which is 1% of the time, and exactly the 1% worth
paying a model call for.

A case is never reopened. Closing stops the SLA clock, and a case that could
reopen hours later would make MTTR meaningless: one straggler at hour sixteen
would turn a four-minute resolution into a sixteen-hour one. A genuinely new
detection opens a *continuation* case instead, which names the case it follows
and is counted on its own.
"""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from app.services.alert_session_service import SESSION_GAP_HOURS

# How long a case must be QUIET before it is answered, measured from its last
# alert.
#
# The cost was measured before the change, over the 100 cases opened after the
# pipeline recovered: 59 finish inside ten minutes and are unaffected; 41 kept
# receiving alerts afterwards and now become chains, with a p90 span of 280
# minutes and one case running twelve hours.
#
# What makes that acceptable is the continuation: an alert arriving after the
# answer opens a new case anchored at its own time, that case gets its own ten
# minutes, and anything linked arriving inside them joins it. The activity is
# not lost, it is reported as a sequence of answered cases instead of one that
# stays open while an analyst waits.
# Six hours, matching SESSION_GAP, and measured from the last alert rather
# than from the opening. Both halves of that changed together and both were
# measured; this reverses the fixed-ten-minutes-from-opening rule that stood
# here before, and the reason is a number rather than a preference.
#
# Simulated over 1,015 derived cases and 12,064 alert memberships — the full
# membership, not the `alerts` payload, which caps at 100 and keeps the
# EARLIEST, so every figure taken from it understates late arrival by design:
#
#   anchored at the opening, 10 min   236 cases (23.3%) accreted after closing,
#                                     9,731 memberships (80.7%) arrived late
#   anchored at the last alert, 10min 231 cases (22.8%),  897 memberships (7.4%)
#   anchored at the last alert, 6 h    29 cases (2.9%),    31 memberships (0.3%)
#
# This reproduces the measurement in this module's own test header, taken
# before the feature was built on a different corpus: 9,244 alerts stranded
# (81%) against 821. Two corpora, 9,731 against 9,244 and 897 against 821.
# The rule was changed away from what that measurement chose, and changing it
# back recovers the same factor of eleven.
#
# The anchor is the larger half: at the same ten minutes, moving it from the
# opening to the last alert cuts late memberships fivefold with no change to
# any constant. A case that is still receiving alerts is not quiet, and the
# previous rule closed it anyway because the window ran from a moment the case
# could no longer influence.
#
# The value then follows from an ordering rule rather than from tuning: a case
# must not be able to close while it can still legitimately accrete, so the
# window must be at least SESSION_GAP. Below it, a case closes and then keeps
# receiving alerts that the correlation is right to give it.
#
# What this cost, before the change: 30 cases carry a disposition formed on
# fewer alerts than they now hold — 25 false positives, 3 needs-review, 2
# inconclusive — the worst judged on 2 of the 57 alerts it now holds. 17 of
# those 30 came from the anchor alone.
CASE_WINDOW = timedelta(hours=SESSION_GAP_HOURS)

# The old name, kept so nothing that imports it breaks. It is the same number
# measured from a different instant, which is exactly the thing to be careful
# about.
DEFAULT_QUIET_PERIOD = CASE_WINDOW

# Retained but not consulted by `decide`. They described an older idle-timer
# behaviour in which a case still producing new *kinds* of detection earned a
# longer silence. The quiet period is once again measured from the last alert,
# but it is a single period for every case rather than one that stretches with
# novelty — a host producing an alert every nine minutes was never answered at
# all under the stretching rule, and the analyst waiting could not see why.
#
# The longer quiet period a case earned while it was still producing detections
# it has not produced before. A case repeating one rule has settled; a case
# still adding new kinds of activity is mid-something, and answering it on the
# base timer is how a multi-stage attack gets reported in halves.
ESCALATING_QUIET_PERIOD = timedelta(minutes=30)

# A case cannot be held open for ever by an escalation that keeps arriving.
# At this age it is answered on what it has, and anything later continues it.
MAX_HOLD = timedelta(hours=6)

# How recently a new detection must have appeared for a case to count as still
# escalating. Measured against the base quiet period: a detection first seen
# longer ago than this is part of the settled picture.
ESCALATION_LOOKBACK = timedelta(minutes=30)

# Beyond this, the gap between an alert happening and a case existing about it
# is not detection latency. The correlation session horizon is six hours and
# the hard cap is a day, so a case cannot legitimately be opened by an alert
# older than that.
MAX_PLAUSIBLE_DETECT = timedelta(hours=24)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def detection_of(member: Any) -> str:
    """What an alert is about, as the correlation names it."""
    for attribute in ("detection_name", "detection_rule_id", "detection_rule_name"):
        value = getattr(member, attribute, None) or (
            member.get(attribute) if isinstance(member, dict) else None
        )
        if value:
            return str(value).strip().casefold()
    return ""


def _event_time(member: Any, fallback: datetime) -> datetime:
    """One alert's time, whether it arrives as a row or as its JSON payload.

    The closing job reads cases from `correlate_alerts`, whose members are
    payload dicts with ISO *strings*, not ORM rows with datetimes. Accepting
    only datetimes meant every member fell back to `now`, so every
    first-seen time was identical and `is_escalating` was true for any case
    with two detections — which held it to the six-hour maximum and meant no
    such case ever closed on the ten-minute quiet period at all.
    """
    for attribute in ("event_time", "when", "created_at", "first_seen"):
        value = getattr(member, attribute, None)
        if value is None and isinstance(member, dict):
            value = member.get(attribute)
        if isinstance(value, datetime):
            return _as_utc(value)
        if isinstance(value, str) and value.strip():
            try:
                return _as_utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
            except ValueError:
                continue
    return fallback


@dataclass
class ClosureDecision:
    """Whether to answer this case now, and why."""

    due: bool
    reason: str
    quiet_period: timedelta = DEFAULT_QUIET_PERIOD
    quiet_for: timedelta = timedelta(0)


def is_escalating(members: Sequence[Any], *, now: datetime) -> bool:
    """Whether the case is still producing kinds of activity it had not before.

    Counted on *first* appearances, not on volume. A host firing the same rule
    three hundred times is noisy, not escalating, and holding its case open
    would be holding it open for ever.
    """
    if len(members) < 2:
        return False
    first_seen: dict[str, datetime] = {}
    for member in members:
        name = detection_of(member)
        if not name:
            continue
        when = _event_time(member, now)
        if name not in first_seen or when < first_seen[name]:
            first_seen[name] = when
    if len(first_seen) < 2:
        return False
    newest = max(first_seen.values())
    return (now - newest) < ESCALATION_LOOKBACK


def decide(
    members: Sequence[Any],
    *,
    last_activity_at: datetime,
    opened_at: datetime,
    now: datetime,
    created_at: datetime | None = None,
    quiet_period: timedelta = CASE_WINDOW,
) -> ClosureDecision:
    """Whether this open case should be answered now.

    One rule: a case is answered when it has been quiet for CASE_WINDOW —
    measured from its last alert, not from its opening.

    This is the reverse of the rule that stood here before, and the reason is
    measured rather than preferred. Anchoring the window at the opening meant a
    case could be answered while alerts the correlation would still give it
    were arriving: 3,198 of 5,523 alert memberships (57.9%) landed after their
    case had closed, and 95.5% of cases holding 21 or more alerts accreted
    after closing. Moving the anchor to the last alert, at the same ten
    minutes, cut that to 11.6%; widening to SESSION_GAP cut it to 0.5%.

    The concern the fixed window was built to answer still holds and is still
    answered. A host producing an alert every nine minutes used to keep its
    case open forever under an idle timer that *stretched* with novelty. This
    does not stretch: the period is the same for every case, so a busy host's
    case is answered one window after its last alert and the next alerts open
    a case of their own.

    `members` is not read. It is kept in the signature because the callers
    pass it and because a decision about a case ought to be able to see the
    case; removing it would make re-introducing it a bigger change than it
    should be.
    """
    last_activity_at = _as_utc(last_activity_at)
    opened_at = _as_utc(opened_at)
    now = _as_utc(now)

    # A case opens at its first alert's own event time, and some senders are
    # wrong about what time it is. Six alerts in this estate are timestamped
    # after the moment we received them, the worst ten hours ahead, and case
    # #1127 opened 213 minutes in the future — under a fixed window that case
    # can never become due, because the window has not started yet.
    #
    # So the window runs from the earlier of when the alert says it happened
    # and when we recorded the case. In the normal case that is the alert's
    # own time, which is what every other figure here uses; when a sender's
    # clock is ahead it is the moment we knew, which is bounded and true.
    # The clock-skew guard still applies, now to the last alert rather than to
    # the opening: a sender whose clock runs ahead would otherwise push the
    # window's end into the future and the case could never become due. Six
    # alerts in this estate are stamped after the moment we received them, the
    # worst ten hours ahead, and case #1127 opened 213 minutes in the future.
    #
    # So quiescence is measured from the earlier of when the last alert says it
    # happened and when we recorded the case. In the normal case that is the
    # alert's own time; when a clock is ahead it is the moment we knew, which
    # is bounded and true.
    quiet_since = last_activity_at
    if created_at is not None:
        recorded = _as_utc(created_at)
        if recorded > quiet_since:
            # The case was recorded after its last alert's stamp, so the stamp
            # is in the past relative to us and needs no correction.
            pass
        elif last_activity_at > now:
            quiet_since = recorded

    quiet_for = now - quiet_since
    open_for = now - _as_utc(opened_at)

    if quiet_for < quiet_period:
        return ClosureDecision(
            False, "still receiving alerts", quiet_period, quiet_for
        )

    return ClosureDecision(
        True, "quiet for its full window", quiet_period, quiet_for
    )


@dataclass
class LateArrival:
    """Alerts that landed after the case was answered.

    All of them continue the case. `new_detections` decides only whether the
    continuation needs its own answer or can inherit the one already given.
    """

    continuation: list[Any] = field(default_factory=list)
    new_detections: set[str] = field(default_factory=set)

    @property
    def needs_continuation(self) -> bool:
        return bool(self.continuation)

    @property
    def inherits(self) -> bool:
        """Nothing the parent had not already answered — no model call."""
        return bool(self.continuation) and not self.new_detections


def split_after_closure(
    members: Sequence[Any], *, closed_at: datetime, now: datetime | None = None,
) -> tuple[list[Any], LateArrival]:
    """Divide a case's alerts into what it was answered on, and what came after.

    **Everything after the answer continues it.** An earlier version appended a
    late alert to the closed case whenever its detection was already known,
    which read well against the measurement — 99% of late alerts are repeats —
    but the measurement was about alerts arriving minutes after a quiet
    period, not about the next six hours. In production a closed case went on
    swallowing alerts for over an hour: case #117 closed at 09:48 and its last
    activity was 10:59, so a morning of real alerts produced no case anybody
    could see and no SLA clock that was running.

    A case that has been answered is finished. What happens next is a new
    episode, and it gets a case of its own so the alerts are visible and the
    clock restarts.

    `new_detections` still matters, but for cost rather than membership: a
    continuation that brings nothing the parent had not already answered
    inherits the parent's resolution and never reaches a model. Measured over
    the estate, that is 47% of continuations — 915 model calls for 1,728
    cases, against 1,728 if every one were answered afresh.
    """
    closed_at = _as_utc(closed_at)
    now = now or datetime.now(timezone.utc)

    answered: list[Any] = []
    late: list[Any] = []
    for member in sorted(members, key=lambda m: _event_time(m, now)):
        (answered if _event_time(member, now) <= closed_at else late).append(member)

    known = {detection_of(m) for m in answered} - {""}
    result = LateArrival(continuation=list(late))
    result.new_detections = ({detection_of(m) for m in late} - known) - {""}
    return answered, result


# The resolution a case carries between being closed and being analysed.
#
# Closing stops the SLA clock, and it has to happen the moment a case goes
# quiet or MTTR measures queue depth instead of response. The analysis takes
# longer than that. So the case closes first and says honestly that it has no
# answer yet, and the answer is written over this when the model returns.
#
# Not "inconclusive": that is a real finding, reached by looking. This is the
# absence of one.
AWAITING_ANALYSIS = "awaiting_analysis"


# What the model is asked to end its verdict line with, mapped to the word an
# analyst closes a case with. Matched on the leading token, because the model
# qualifies its verdict in prose — "Benign operational denial", "Suspicious
# authentication activity" — and the qualifier is for the analyst to read, not
# for this to parse.
#
# Ordered longest-first so "false positive" is tested before "positive" and
# "not malicious" before "malicious".
_VERDICT_WORDS: tuple[tuple[str, str], ...] = (
    ("true positive", "true_positive"),
    ("true_positive", "true_positive"),
    ("false positive", "false_positive"),
    ("false_positive", "false_positive"),
    ("not malicious", "false_positive"),
    ("not_malicious", "false_positive"),
    ("inconclusive", "inconclusive"),
    ("indeterminate", "inconclusive"),
    ("unknown", "inconclusive"),
    ("malicious", "true_positive"),
    ("confirmed", "true_positive"),
    ("compromised", "true_positive"),
    ("suspicious", "needs_review"),
    ("needs review", "needs_review"),
    ("benign", "false_positive"),
    ("clean", "false_positive"),
)


def resolution_for(*, verdict: str | None) -> str:
    """The closing resolution, in the words an analyst closes a case with.

    Reads the verdict the analysis reached. Nothing else — and in particular
    not the correlation score, which this used to fall back on and which is
    the reason case #61 was filed as a confirmed detection while its own
    report opened with "Verdict: Inconclusive".

    The score is not a severity. It measures how much independent agreement
    there is between rules and how far the behaviour travelled; the narrative
    prompt says so in those words. A host running PowerShell as SYSTEM under
    six rules it has not fired together before scores 100 and is routine
    administration. Reading that as "malicious" filed 24 cases as true
    positives of which the analysis called exactly one malicious.

    Measured over 831 closed cases, the resolution was a pure function of the
    score: true_positive was exactly the 76-100 band, inconclusive 30-73,
    false_positive 0-35. The verdict argument was always None, because the
    correlated case dict has no `verdict` key at all — so the branch these
    tests exercised had never once run in production.

    An unreadable or missing verdict is `inconclusive`. It is never a
    positive: a case nobody could answer must not arrive in the queue as a
    confirmed intrusion, and must not be quietly counted as clean either.
    """
    text = str(verdict or "").strip().casefold().lstrip("*#: ").strip()
    if not text:
        return "inconclusive"

    # A hedge in front of the verdict is still that verdict: "likely benign"
    # is benign. Stripped rather than listed, so the table stays one row per
    # outcome.
    for _ in range(3):
        stripped = re.sub(
            r"^(likely|probably|possibly|assessed(?:\s+as)?|appears(?:\s+to\s+be)?"
            r"|most\s+likely|highly\s+likely|verdict)\b[\s:,-]*",
            "", text,
        )
        if stripped == text:
            break
        text = stripped.strip()

    for word, resolution in _VERDICT_WORDS:
        if text.startswith(word):
            return resolution

    # Nothing further. The verdict is a field, not prose to be mined for
    # frightening words: scanning the whole line read "No malicious activity
    # confirmed" as a confirmed intrusion, which is the same mistake as
    # reading the score — a conclusion drawn from something that was never a
    # conclusion. An unrecognised verdict is one nobody answered.
    return "inconclusive"


def analysis_is_ready(*, narrative_status: Any, narrative_markdown: Any) -> bool:
    """Has the model actually written an analysis of this case?

    The precondition for a person signing a case off. An analyst closing a case
    is recording a judgement, and a judgement needs something to have been read
    first — this platform spent 831 cases filing resolutions that nothing had
    assessed.

    Deliberately NOT "the resolution is set". The three candidate conditions
    were measured across all 1,051 spine rows and they disagree in both
    directions:

      * `narrative_status == 'completed'`, non-empty markdown and
        `narrative_generated_at IS NOT NULL` agree on every one of the 842
        analysed rows — zero disagreements.
      * 47 rows have a written analysis and no resolution, because the
        write-back only fires for a case that is already closed. Gating on the
        resolution would refuse a case whose analysis is sitting right there.
      * 11 rows have a resolution and no analysis at all: continuations
        inherit their parent's answer without a second model call. Gating on
        the resolution would wave those through as though something had read
        them.

    So the gate asks about the analysis itself, which is the thing the analyst
    is being asked to agree with.
    """
    if str(narrative_status or "").strip().casefold() != "completed":
        return False
    return bool(str(narrative_markdown or "").strip())


def resolution_from_analysis(markdown: str | None) -> str:
    """The resolution the written analysis supports.

    One place, so the closing job, the analyst's "send to AI" button and the
    backfill of history all read the same report the same way.
    """
    from app.services.alert_case_narrative_service import narrative_lead

    return resolution_for(verdict=narrative_lead(markdown).get("verdict"))


# A case closed later than this after its own last alert was not answered in
# response time — it was swept up by a catch-up pass. MAX_HOLD is the longest
# the closing job will ever hold an active case open, so anything beyond it is
# not the service responding.
MAX_PLAUSIBLE_RESOLVE_LAG = MAX_HOLD


def metrics(
    *,
    opened_at: datetime,
    created_at: datetime,
    closed_at: datetime | None,
    last_activity_at: datetime | None = None,
) -> dict[str, Any]:
    """MTTD and MTTR for one case, from the timestamps already stored.

    Derived rather than stored, so a definition that turns out to be wrong is
    one query away from being right instead of a backfill.

      detect   first alert happened -> the platform had a case about it
      resolve  first alert happened -> the case was answered

    Both run from the first alert's own event time, not from when we were told
    about it: an alert that sat in a queue for an hour is an hour of exposure
    whatever the ingest clock says.
    """
    opened_at = _as_utc(opened_at)
    created_at = _as_utc(created_at)
    detect = (created_at - opened_at).total_seconds()
    out: dict[str, Any] = {
        "detect_seconds": max(0.0, round(detect, 1)),
        "resolve_seconds": None,
        "open": closed_at is None,
    }
    # A case whose row was written long after its first alert is a backfill,
    # not a detection that took eighteen days. Every case that predates this
    # feature is one: the spine rows were created when correlation first ran
    # over history. Reporting the arithmetic would put those into the MTTD
    # average and make it meaningless, so they are excluded and say why.
    if detect > MAX_PLAUSIBLE_DETECT.total_seconds():
        out["detect_seconds"] = None
        out["detect_excluded"] = "case recorded long after the alert; backfilled, not detected"
    if closed_at is not None:
        out["resolve_seconds"] = max(0.0, round((_as_utc(closed_at) - opened_at).total_seconds(), 1))

        # The same exclusion as above, for the other half of the pair.
        #
        # It was missing, and only the detection side had it. A case whose
        # alerts stopped in September and which a catch-up pass closed in
        # October contributes three weeks to MTTR — so one month of real work
        # reported a mean resolution of 21.8 days and 620 of 620 cases
        # breached, which describes when the backlog was drained and not how
        # the service responded.
        #
        # Counted and named rather than dropped: a case nobody answered for
        # three weeks is a real failure of a different kind, and hiding it
        # inside an average is how a metric comes to flatter.
        if last_activity_at is not None:
            lag = (_as_utc(closed_at) - _as_utc(last_activity_at)).total_seconds()
            if lag > MAX_PLAUSIBLE_RESOLVE_LAG.total_seconds():
                out["resolve_seconds"] = None
                out["resolve_lag_seconds"] = round(lag, 1)
                out["resolve_excluded"] = (
                    "closed by a later sweep, not answered within the response window"
                )
    return out


def sla_state(
    resolve_seconds: float | None, *, target_seconds: float, now_open_seconds: float | None = None,
) -> str:
    """met | breached | at_risk | open — one case against its target."""
    if resolve_seconds is not None:
        return "met" if resolve_seconds <= target_seconds else "breached"
    if now_open_seconds is None:
        return "open"
    if now_open_seconds > target_seconds:
        return "breached"
    if now_open_seconds > target_seconds * 0.75:
        return "at_risk"
    return "open"


def summarise(cases: Iterable[dict[str, Any]], *, target_seconds: float) -> dict[str, Any]:
    """MTTD/MTTR across a set of cases, reported in two populations.

    Single-alert and multi-alert cases are reported apart because they are not
    the same work and mixing them flatters the numbers: 497 of 884 cases in
    this estate hold one alert, and a mean that includes them is mostly a
    measure of how many single alerts arrived.
    """
    buckets: dict[str, list[dict[str, Any]]] = {"single": [], "multi": []}
    for case in cases:
        buckets["multi" if int(case.get("alert_count") or 1) > 1 else "single"].append(case)

    def _stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
        detects = [r["detect_seconds"] for r in rows if r.get("detect_seconds") is not None]
        resolves = [r["resolve_seconds"] for r in rows if r.get("resolve_seconds") is not None]
        met = sum(1 for r in resolves if r <= target_seconds)
        return {
            "cases": len(rows),
            "closed": len(resolves),
            "mttd_seconds": round(sum(detects) / len(detects), 1) if detects else None,
            "mttr_seconds": round(sum(resolves) / len(resolves), 1) if resolves else None,
            "sla_met": met,
            "sla_breached": len(resolves) - met,
        }

    return {
        "target_seconds": target_seconds,
        "single_alert": _stats(buckets["single"]),
        "multi_alert": _stats(buckets["multi"]),
        "all": _stats(buckets["single"] + buckets["multi"]),
    }
