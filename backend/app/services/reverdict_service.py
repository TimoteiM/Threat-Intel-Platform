"""
Tell the sender when a verdict we already gave them turns out to be wrong.

A report is a snapshot. A domain investigated as benign on Tuesday and weaponised
on Friday leaves every SOAR that received that report holding an answer nobody
will ever correct — the platform knew, and said nothing.

Two halves close that loop:

    auto-enrolment   an indicator an alert run concluded something about is put
                     on the watchlist, so it is re-checked on a schedule instead
                     of only when it happens to appear in another alert
    re-notification  when a re-check changes the classification, the alert runs
                     that reported the old verdict are found and their original
                     `callback_url` is called again with `alert.updated`

Only genuine changes notify. A re-check that agrees with itself is silence, and
a move between two flavours of "not actionable" is not a correction worth
waking a SOAR for.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun, WatchlistEntry
from app.utils.domain_utils import normalize_domain, validate_domain

logger = logging.getLogger(__name__)

# Ranked by how much a SOC needs to hear about the change.
SEVERITY_ORDER = {"benign": 0, "inconclusive": 1, "suspicious": 2, "malicious": 3}

# Changes inside this set are re-phrasings, not corrections.
NON_ACTIONABLE = frozenset({"benign", "inconclusive", None, ""})


def enrol_indicators(
    indicator_reports: list[dict[str, Any]],
    *,
    run_id: str | None = None,
) -> int:
    """
    Put the domains this run reached a real conclusion about on the watchlist.

    Only domains: the watchlist re-check pipeline investigates domains, and
    enrolling an IP or a hash would create an entry nothing can ever re-check.
    Only above the risk threshold: the point is to re-check what mattered, not
    to watch the whole internet.
    """
    settings = get_settings()
    if not settings.alert_watchlist_autoenrol:
        return 0

    threshold = int(settings.alert_watchlist_autoenrol_min_risk)
    candidates: dict[str, dict[str, Any]] = {}

    for report in indicator_reports or []:
        if not isinstance(report, dict):
            continue
        # An excluded or skipped indicator was never investigated; a reused one
        # is already known. Neither is a new conclusion worth watching.
        if str(report.get("status")) not in ("completed", "investigating"):
            continue
        indicator = report.get("indicator") or {}
        if str(indicator.get("type")) not in ("domain", "url"):
            continue
        verdict = report.get("verdict") or {}
        if int(verdict.get("risk_score") or 0) < threshold:
            continue
        domain = normalize_domain(str(indicator.get("value") or ""))
        if not domain or not validate_domain(domain):
            continue
        candidates.setdefault(domain, {
            "classification": verdict.get("classification"),
            "risk_score": verdict.get("risk_score"),
        })

    if not candidates:
        return 0

    enrolled = 0
    try:
        with Session(sync_engine) as session:
            for domain, verdict in candidates.items():
                existing = session.execute(
                    select(WatchlistEntry).where(WatchlistEntry.domain == domain)
                ).scalar_one_or_none()
                if existing is not None:
                    continue  # never override an analyst's own entry or schedule
                session.add(
                    WatchlistEntry(
                        domain=domain,
                        notes=(
                            f"Auto-enrolled from alert run {run_id or '?'} — concluded "
                            f"{verdict.get('classification')} (risk {verdict.get('risk_score')}). "
                            f"Re-checked so a change in verdict is noticed."
                        ),
                        added_by="alert-ingest",
                        status="active",
                        schedule_interval=settings.alert_watchlist_autoenrol_interval,
                    )
                )
                enrolled += 1
            session.commit()
    except Exception as exc:  # enrolment is an improvement, never a dependency
        logger.warning("Watchlist auto-enrolment failed: %s", exc)
        return 0

    if enrolled:
        logger.info("Auto-enrolled %d domain(s) on the watchlist from run %s", enrolled, run_id)
    return enrolled


def notify_verdict_change(
    domain: str,
    *,
    previous_classification: str | None,
    current_classification: str | None,
    investigation_id: str,
    risk_score: int | None = None,
) -> int:
    """
    Re-notify the senders who were given the old verdict for this indicator.

    Returns how many callbacks were dispatched. Silent when the verdict did not
    meaningfully change, when nobody asked for a callback, or when re-notify is
    turned off.
    """
    settings = get_settings()
    if not settings.alert_reverdict_notify:
        return 0
    if not _is_meaningful_change(previous_classification, current_classification):
        return 0

    runs = _runs_reporting(domain)
    if not runs:
        return 0

    from app.tasks.alert_callback_task import deliver_alert_callback

    dispatched = 0
    for run_id, callback_url, external_ref in runs:
        try:
            deliver_alert_callback.delay(
                run_id,
                event="alert.updated",
                override_url=callback_url,
                extra={
                    "reason": "indicator_verdict_changed",
                    "indicator": domain,
                    "previous_classification": previous_classification,
                    "current_classification": current_classification,
                    "risk_score": risk_score,
                    "investigation_id": investigation_id,
                    "external_ref": external_ref,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "message": (
                        f"{domain} was reported as {previous_classification or 'unknown'} in this "
                        f"alert and has since been re-assessed as {current_classification}."
                    ),
                },
            )
            dispatched += 1
        except Exception as exc:
            logger.warning("Could not queue re-verdict callback for run %s: %s", run_id, exc)

    if dispatched:
        logger.info(
            "Verdict change on %s (%s → %s): re-notified %d sender(s)",
            domain, previous_classification, current_classification, dispatched,
        )
    return dispatched


# ── Internals ─────────────────────────────────────────────────────────────────


def _is_meaningful_change(previous: str | None, current: str | None) -> bool:
    """
    Whether this change is worth interrupting a SOAR for.

    Benign → inconclusive is not news. Anything that crosses into or out of
    actionable is, and so is a worsening between the two actionable states.
    """
    if not current or previous == current:
        return False
    if previous in NON_ACTIONABLE and current in NON_ACTIONABLE:
        return False
    return SEVERITY_ORDER.get(current, 0) != SEVERITY_ORDER.get(previous or "", 0)


def _runs_reporting(domain: str) -> list[tuple[str, str, str | None]]:
    """
    Alert runs that reported on this domain and asked to be called back.

    The indicator sits several levels down in JSONB; a text match on the
    serialised payload is exact enough for a domain and keeps this to one query.
    """
    needle = domain.lower()
    try:
        with Session(sync_engine) as session:
            rows = session.execute(
                select(
                    AlertBodyInvestigationRun.id,
                    AlertBodyInvestigationRun.callback_url,
                    AlertBodyInvestigationRun.external_ref,
                    AlertBodyInvestigationRun.result_json,
                ).where(AlertBodyInvestigationRun.callback_url.isnot(None))
            ).all()
    except Exception as exc:
        logger.warning("Could not look up runs reporting %s: %s", domain, exc)
        return []

    matches: list[tuple[str, str, str | None]] = []
    for run_id, callback_url, external_ref, payload in rows:
        blob = json.dumps(payload or {}, default=str).lower()
        if needle in blob:
            matches.append((str(run_id), str(callback_url), external_ref))
    return matches
