"""
Shared enums — single source of truth for all status/classification values.

These are used by Pydantic models, SQLAlchemy models, and API responses.
"""

import enum


class InvestigationState(str, enum.Enum):
    """Investigation lifecycle states."""
    CREATED = "created"
    GATHERING = "gathering"           # Collectors running
    EVALUATING = "evaluating"         # Claude analyzing evidence
    INSUFFICIENT_DATA = "insufficient_data"  # Claude needs more evidence
    CONCLUDED = "concluded"           # Analysis complete
    CANCELLED = "cancelled"           # Cancelled by analyst
    FAILED = "failed"                 # Unrecoverable error


class Classification(str, enum.Enum):
    """Analyst classification of the domain."""
    BENIGN = "benign"                 # Fully explained by legitimate operation
    SUSPICIOUS = "suspicious"         # Unusual but attacker not required
    MALICIOUS = "malicious"           # Requires attacker-controlled infrastructure
    INCONCLUSIVE = "inconclusive"     # Evidence insufficient to decide


class Confidence(str, enum.Enum):
    """Analyst confidence in the classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SOCAction(str, enum.Enum):
    """Recommended SOC response action."""
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    BLOCK = "block"
    HUNT = "hunt"


class CollectorStatus(str, enum.Enum):
    """Individual collector execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, enum.Enum):
    """Finding / signal severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(str, enum.Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"

class CaseResolution(str, enum.Enum):
    """How a correlated case was answered.

    The vocabulary lived as bare strings across the closing job, the API, two
    migrations and the Cases table, which is how `needs_review` came to be
    reachable in the backend with no label anywhere in the UI. This is the one
    place it is written down.

    A resolution is NOT a copy of the analysis verdict. The verdict says what
    the behaviour was; the resolution says how the case was disposed of, and
    "nobody answered it" is a real disposition that must not be recorded as
    either a finding or a clean bill.

    **`str(member)` does not give the value.** These inherit `str, enum.Enum`
    to match the rest of this module, and that spelling keeps `Enum.__str__`,
    so `str(CaseResolution.TRUE_POSITIVE)` is "CaseResolution.TRUE_POSITIVE"
    while `CaseResolution.TRUE_POSITIVE == "true_positive"` is True. JSON is
    safe — Pydantic and `json.dumps` both emit the value — but an f-string on
    the way to the database would persist the member name. Pass `.value`
    whenever the destination is a column or a log line.
    """

    # Reached by looking at the evidence.
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    # The analysis called it suspicious: real enough to keep, not confirmed.
    NEEDS_REVIEW = "needs_review"
    # Looked at, and the evidence did not decide. A real outcome, and the only
    # honest home for an analysis that failed or could not be read.
    INCONCLUSIVE = "inconclusive"

    # --- not findings; nobody reached these by assessing anything -----------

    # Closed on the quiet period, waiting for the model to answer. Written over
    # by the narrative task; it is never where a case comes to rest.
    AWAITING_ANALYSIS = "awaiting_analysis"
    # Its alerts fell out of the correlation window, so no alert can ever join
    # it again and no analysis can be produced for it.
    EXPIRED = "expired"
    # Historical. Written by a closing rule that has been removed: it closed
    # cases merely for being absent from a listing, which destroyed 575 of
    # them. Kept so the stored values still have a name.
    AGED_OUT = "aged_out"

    @classmethod
    def analyst_choices(cls) -> tuple["CaseResolution", ...]:
        """The resolutions a person may close a case under.

        The others describe what happened *to* a case rather than what anyone
        concluded about it, so offering them as a choice would let an analyst
        sign a case off as "expired".
        """
        return (cls.TRUE_POSITIVE, cls.FALSE_POSITIVE, cls.NEEDS_REVIEW, cls.INCONCLUSIVE)


class CaseClosureKind(str, enum.Enum):
    """Who or what closed a case. See CaseResolution on `str(member)`."""

    # The quiet period elapsed and the job closed it.
    AUTO = "auto"
    # A person closed it, and `closed_by` says who.
    ANALYST = "analyst"
    # A continuation that brought nothing its parent had not already answered,
    # so it carries the parent's resolution without a second model call.
    INHERITED = "inherited"
    # Its alerts left the correlation window before it could be answered.
    EXPIRED = "expired"
    # Historical; see CaseResolution.AGED_OUT.
    AGED_OUT = "aged_out"
