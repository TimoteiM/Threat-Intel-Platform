"""
Prior-investigation lookup for extracted indicators.

Before an alert-body run spends collector quota on a domain (or URL/IP/hash), it
asks this service whether the platform already investigated that exact value. A
recent concluded investigation is reused instead of re-collected: the alert-body
pipeline can fan out over dozens of indicators, and the same corporate domains
show up in alert after alert.

Two entry points, one query:
    find_prior_investigations()       — async, for the FastAPI request path
    find_prior_investigations_sync()  — sync, for the Celery worker

Both return a map keyed by `history_key(observable_type, value)`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import Investigation

logger = logging.getLogger(__name__)

# Only a finished investigation carries a verdict worth reusing.
REUSABLE_STATES = frozenset({"concluded"})

# Investigations older than this are reported to the analyst but never reused —
# reputation, hosting and registration data all drift.
DEFAULT_MAX_AGE_DAYS = 7

# How long a verdict stays reusable depends on what it said, because the two
# directions of drift are not equally dangerous:
#
#   benign → malicious   is the one that hurts. A domain parked and clean today
#                        and weaponised on Friday is how staged phishing works,
#                        so a benign verdict gets half the base window.
#   malicious → benign   only ever costs an unnecessary look at something we
#                        already called bad, and re-collecting known-bad burns
#                        the quota this whole path exists to save.
#   inconclusive         is not a verdict. Reusing one saves a lookup and
#                        answers nothing; the collector that was rate-limited
#                        last time may well succeed now.
#
# Multipliers on ALERT_PRIOR_INVESTIGATION_MAX_AGE_DAYS, so one setting still
# governs how much staleness the deployment tolerates overall.
REUSE_AGE_MULTIPLIER = {
    "malicious": 4.0,
    "suspicious": 0.5,
    "benign": 0.5,
    "inconclusive": 0.0,
}

# A verdict the engine itself was unsure of should not outlive a confident one.
LOW_CONFIDENCE_MULTIPLIER = 0.25

# Guard against a pathological IN-list on a huge indicator set.
MAX_ROWS = 500


def history_key(observable_type: str, value: str) -> str:
    """Stable map key for one (type, value) pair."""
    return f"{str(observable_type or '').strip().lower()}:{str(value or '').strip().lower()}"


def find_prior_investigations_sync(
    pairs: Iterable[tuple[str, str]],
) -> dict[str, dict[str, Any]]:
    """Blocking variant for Celery workers. Never raises — a DB hiccup is not fatal."""
    statement = _statement(pairs)
    if statement is None:
        return {}
    try:
        with Session(sync_engine) as db:
            rows = db.execute(statement).all()
    except Exception as exc:
        logger.warning("Prior-investigation lookup failed: %s", exc)
        return {}
    return _summarize(rows)


async def find_prior_investigations(
    db: AsyncSession,
    pairs: Iterable[tuple[str, str]],
) -> dict[str, dict[str, Any]]:
    """Async variant for API handlers. Never raises."""
    statement = _statement(pairs)
    if statement is None:
        return {}
    try:
        result = await db.execute(statement)
        rows = result.all()
    except Exception as exc:
        logger.warning("Prior-investigation lookup failed: %s", exc)
        return {}
    return _summarize(rows)


def pairs_from_indicators(indicators: Sequence[dict[str, Any]]) -> list[tuple[str, str]]:
    """(observable_type, value) pairs for every investigable extracted indicator."""
    pairs: list[tuple[str, str]] = []
    for indicator in indicators or []:
        if not indicator.get("investigable"):
            continue
        kind = str(indicator.get("type") or "")
        value = str(indicator.get("value") or "")
        if kind and value:
            pairs.append((kind, value))
    return pairs


def annotate_indicators(
    indicators: Sequence[dict[str, Any]],
    history: dict[str, dict[str, Any]],
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> None:
    """Attach `prior_investigation` to each indicator that has one (in place)."""
    for indicator in indicators or []:
        prior = history.get(history_key(str(indicator.get("type") or ""), str(indicator.get("value") or "")))
        if not prior:
            continue
        indicator["prior_investigation"] = {
            **prior,
            "reusable": is_reusable(prior, max_age_days=max_age_days),
            # Says *why* a prior verdict was or was not reused, so a re-collection
            # of something investigated yesterday is explainable rather than odd.
            "reuse_max_age_days": round(reuse_ceiling_days(prior, max_age_days=max_age_days), 2),
        }


def is_reusable(prior: dict[str, Any] | None, *, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> bool:
    """
    A prior investigation stands in for a fresh one only if concluded and recent.

    "Recent" is graded by the verdict — see REUSE_AGE_MULTIPLIER — so a benign
    answer expires well before a malicious one and an inconclusive one is never
    reused at all.
    """
    if not prior:
        return False
    if str(prior.get("state") or "") not in REUSABLE_STATES:
        return False
    if not prior.get("classification"):
        return False
    age = prior.get("age_days")
    if age is None:
        return False
    return float(age) <= reuse_ceiling_days(prior, max_age_days=max_age_days)


def reuse_ceiling_days(
    prior: dict[str, Any],
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> float:
    """How old this particular verdict may be and still be reused, in days."""
    classification = str(prior.get("classification") or "").strip().lower()
    ceiling = float(max_age_days) * REUSE_AGE_MULTIPLIER.get(classification, 1.0)
    if str(prior.get("confidence") or "").strip().lower() == "low":
        ceiling *= LOW_CONFIDENCE_MULTIPLIER
    return ceiling


# ── Internals ─────────────────────────────────────────────────────────────────


def _statement(pairs: Iterable[tuple[str, str]]):
    normalized = {
        (str(kind).strip().lower(), str(value).strip().lower())
        for kind, value in pairs
        if str(kind or "").strip() and str(value or "").strip()
    }
    if not normalized:
        return None

    values = sorted({value for _kind, value in normalized})
    types = sorted({kind for kind, _value in normalized})
    # Domains are stored normalized, but hashes keep the caller's casing — match
    # case-insensitively so a SHA256 pasted in upper case still finds its run.
    return (
        select(
            Investigation.id,
            Investigation.domain,
            Investigation.observable_type,
            Investigation.state,
            Investigation.classification,
            Investigation.confidence,
            Investigation.risk_score,
            Investigation.recommended_action,
            Investigation.created_at,
            Investigation.concluded_at,
        )
        .where(
            func.lower(Investigation.domain).in_(values),
            Investigation.observable_type.in_(types),
        )
        .order_by(Investigation.created_at.desc())
        .limit(MAX_ROWS)
    )


def _summarize(rows: Sequence[Any]) -> dict[str, dict[str, Any]]:
    """Keep the newest investigation per (type, value) and count the rest."""
    now = datetime.now(timezone.utc)
    summaries: dict[str, dict[str, Any]] = {}

    for row in rows:  # already ordered newest first
        key = history_key(str(row.observable_type or "domain"), str(row.domain or ""))
        existing = summaries.get(key)
        if existing is not None:
            existing["total_investigations"] += 1
            continue
        created = _aware(row.created_at)
        summaries[key] = {
            "investigation_id": str(row.id),
            "value": row.domain,
            "observable_type": row.observable_type or "domain",
            "state": row.state,
            "classification": row.classification,
            "confidence": row.confidence,
            "risk_score": row.risk_score,
            "recommended_action": row.recommended_action,
            "created_at": created.isoformat() if created else None,
            "concluded_at": (_aware(row.concluded_at).isoformat() if row.concluded_at else None),
            "age_days": round((now - created).total_seconds() / 86400.0, 2) if created else None,
            "total_investigations": 1,
        }
    return summaries


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
