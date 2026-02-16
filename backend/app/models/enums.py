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
