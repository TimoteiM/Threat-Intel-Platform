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

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

# How long a case must be quiet before it is answered.
DEFAULT_QUIET_PERIOD = timedelta(minutes=10)

# The longer quiet period a case earns while it is still producing detections
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
    for attribute in ("event_time", "when", "created_at"):
        value = getattr(member, attribute, None) or (
            member.get(attribute) if isinstance(member, dict) else None
        )
        if isinstance(value, datetime):
            return _as_utc(value)
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
    quiet_period: timedelta = DEFAULT_QUIET_PERIOD,
) -> ClosureDecision:
    """Whether this open case should be answered now."""
    last_activity_at = _as_utc(last_activity_at)
    opened_at = _as_utc(opened_at)
    now = _as_utc(now)
    quiet_for = now - last_activity_at

    if quiet_for < quiet_period:
        return ClosureDecision(False, "still active", quiet_period, quiet_for)

    if is_escalating(members, now=now):
        if (now - opened_at) >= MAX_HOLD:
            # Held as long as it is reasonable to hold anything. Answer it on
            # what it has; what comes next continues it.
            return ClosureDecision(
                True, "held to the maximum while still escalating",
                ESCALATING_QUIET_PERIOD, quiet_for,
            )
        if quiet_for < ESCALATING_QUIET_PERIOD:
            return ClosureDecision(
                False, "still producing new detections", ESCALATING_QUIET_PERIOD, quiet_for,
            )
        return ClosureDecision(
            True, "quiet for the escalation period", ESCALATING_QUIET_PERIOD, quiet_for,
        )

    return ClosureDecision(True, "quiet for the standard period", quiet_period, quiet_for)


@dataclass
class LateArrival:
    """What to do with alerts that land after the case was answered."""

    appended: list[Any] = field(default_factory=list)
    continuation: list[Any] = field(default_factory=list)
    new_detections: set[str] = field(default_factory=set)

    @property
    def needs_continuation(self) -> bool:
        return bool(self.continuation)


def split_after_closure(
    members: Sequence[Any], *, closed_at: datetime, now: datetime | None = None,
) -> tuple[list[Any], LateArrival]:
    """Divide a case's alerts into what it was answered on, and what came after.

    A late alert whose detection the case already held is appended to it: the
    resolution does not change, so re-answering would cost a model call to
    produce the same sentence. Ninety-nine per cent of late alerts are this.

    One bringing a detection the case has not seen goes to a continuation —
    along with every later alert, including repeats, because once a case has
    moved on its subsequent activity belongs with the part that moved.
    """
    closed_at = _as_utc(closed_at)
    now = now or datetime.now(timezone.utc)

    answered: list[Any] = []
    late: list[Any] = []
    for member in sorted(members, key=lambda m: _event_time(m, now)):
        (answered if _event_time(member, now) <= closed_at else late).append(member)

    known = {detection_of(m) for m in answered} - {""}
    result = LateArrival()
    for index, member in enumerate(late):
        name = detection_of(member)
        if name and name not in known:
            # From here on it is a different case, repeats included.
            result.continuation = late[index:]
            result.new_detections = {
                detection_of(m) for m in result.continuation
            } - known - {""}
            break
        result.appended.append(member)
    return answered, result


def resolution_for(*, verdict: str | None, risk_score: int | None) -> str:
    """The closing resolution, in the words an analyst closes a case with.

    Deliberately not a copy of the verdict: a case is closed as a true or
    false positive, and "unknown" is a real outcome that must not be recorded
    as either.
    """
    text = str(verdict or "").strip().casefold()
    if text in {"malicious", "true_positive", "confirmed"}:
        return "true_positive"
    if text in {"benign", "false_positive", "clean", "not_malicious"}:
        return "false_positive"
    if text == "suspicious":
        return "needs_review"
    if risk_score is not None and risk_score >= 75:
        return "true_positive"
    if risk_score is not None and risk_score <= 20:
        return "false_positive"
    return "inconclusive"


def metrics(
    *, opened_at: datetime, created_at: datetime, closed_at: datetime | None,
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
