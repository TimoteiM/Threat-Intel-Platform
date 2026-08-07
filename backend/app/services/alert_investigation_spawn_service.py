"""
Full investigations for indicators extracted from an alert body.

A handful of collectors run inline is enough to triage an IP or a hash, but a
domain or URL deserves the real thing: the platform's investigation pipeline —
every supported collector (VirusTotal included), the AI analyst, a stored report
that an analyst can open, iterate on and export.

So for domain/url indicators the alert-body run does what an analyst would do:

    already investigated recently?  → reuse that verdict   (indicator_history_service)
    otherwise                       → create an Investigation, run the pipeline,
                                      wait for it, and fold its verdict into the
                                      alert report

An investigation that has not concluded by the run's deadline is reported as
`"status": "investigating"` with its id; `hydrate_pending_reports()` fills the
verdict in the next time the alert run is read or exported, so the exported JSON
converges on the real answer without a re-run.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import CollectorResult, Evidence, Investigation, Report
from app.services.alert_finding_builder import build_indicator_findings
from app.utils.domain_utils import normalize_domain, validate_domain

logger = logging.getLogger(__name__)

# Only these observable types get a full investigation — an IP is answered by
# the IP Lookup tool and a hash by VT/OpenCTI/threat feeds, neither of which the
# pipeline improves on. Overridable with ALERT_SPAWN_OBSERVABLE_TYPES.
DEFAULT_SPAWN_TYPES = frozenset({"domain", "url"})

# Investigation states that will never change on their own.
TERMINAL_STATES = frozenset({"concluded", "failed", "cancelled"})
FAILED_STATES = frozenset({"failed", "cancelled"})

_CONFIDENCE_SCORE = {"high": 0.9, "medium": 0.75, "low": 0.5}

# Analyst findings carried into the alert report (the full set lives on the
# investigation itself, one click away).
MAX_ANALYST_FINDINGS = 8
MAX_VERDICT_REASONS = 8


def spawn_types() -> frozenset[str]:
    """Observable types that spawn a full investigation, per settings."""
    configured = str(get_settings().alert_spawn_observable_types or "").strip()
    if not configured:
        return DEFAULT_SPAWN_TYPES
    return frozenset({part.strip().lower() for part in configured.split(",") if part.strip()})


def should_spawn(observable_type: str, *, enabled: bool | None = None) -> bool:
    settings = get_settings()
    active = settings.alert_spawn_investigations if enabled is None else bool(enabled)
    return active and str(observable_type or "").lower() in spawn_types()


# ── Spawning ──────────────────────────────────────────────────────────────────


def spawn_investigation(
    value: str,
    observable_type: str,
    *,
    context: str | None = None,
) -> str | None:
    """
    Create an Investigation row for `value` and queue the standard pipeline.

    Returns the investigation id, or None if the value cannot be investigated.
    Collectors are deliberately left unspecified: the pipeline then applies the
    platform defaults (DEFAULT_COLLECTORS + baseline), which is what makes this a
    *full* investigation — VirusTotal included, unlike the alert-body inline run.
    """
    settings = get_settings()
    target = str(value or "").strip()
    if not target:
        return None
    if observable_type == "domain":
        target = normalize_domain(target)
        if not validate_domain(target):
            logger.warning("Not spawning an investigation for invalid domain %r", value)
            return None

    with Session(sync_engine) as db:
        investigation = Investigation(
            domain=target,
            observable_type=observable_type,
            context=context,
            state="created",
            max_analyst_iterations=settings.max_analyst_iterations,
        )
        db.add(investigation)
        db.commit()
        investigation_id = str(investigation.id)

    # Imported here: app.tasks.investigation_task pulls in the whole pipeline, and
    # this module is imported by the API process too.
    from app.services.investigation_service import _store_investigation_task_id
    from app.tasks.investigation_task import run_investigation

    try:
        task = run_investigation.delay(
            investigation_id=investigation_id,
            domain=target,
            observable_type=observable_type,
            context=context,
            requested_collectors=None,  # → platform defaults, VT included
        )
        _store_investigation_task_id(investigation_id, getattr(task, "id", None))
    except Exception as exc:
        logger.exception("Failed to queue investigation for %s: %s", target, exc)
        _set_state(investigation_id, "failed")
        return investigation_id

    logger.info("Alert body spawned investigation %s for %s (%s)", investigation_id, target, observable_type)
    return investigation_id


def wait_for_investigation(
    investigation_id: str,
    *,
    deadline: float,
    poll_seconds: float | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> str:
    """
    Block until the investigation reaches a terminal state, the deadline passes,
    or the alert run is cancelled. Returns the last state seen.
    """
    interval = float(poll_seconds or get_settings().alert_investigation_poll_seconds)
    state = _current_state(investigation_id) or "created"
    while state not in TERMINAL_STATES:
        if is_cancelled and is_cancelled():
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.info(
                "Alert run stopped waiting for investigation %s (state=%s) — deadline reached",
                investigation_id,
                state,
            )
            return state
        time.sleep(min(interval, remaining))
        state = _current_state(investigation_id) or state
    return state


# ── Outcome loading ───────────────────────────────────────────────────────────


def load_outcomes_sync(investigation_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Investigation + report + evidence + collector runs, keyed by id (worker path)."""
    ids = _parse_ids(investigation_ids)
    if not ids:
        return {}
    try:
        with Session(sync_engine) as db:
            investigations = db.execute(_investigation_stmt(ids)).scalars().all()
            reports = db.execute(_report_stmt(ids)).scalars().all()
            evidence = db.execute(_evidence_stmt(ids)).scalars().all()
            collector_results = db.execute(_collector_stmt(ids)).scalars().all()
    except Exception as exc:
        logger.warning("Could not load spawned investigation outcomes: %s", exc)
        return {}
    return _assemble_outcomes(investigations, reports, evidence, collector_results)


async def load_outcomes(db: AsyncSession, investigation_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Async variant for the API request path."""
    ids = _parse_ids(investigation_ids)
    if not ids:
        return {}
    try:
        investigations = (await db.execute(_investigation_stmt(ids))).scalars().all()
        reports = (await db.execute(_report_stmt(ids))).scalars().all()
        evidence = (await db.execute(_evidence_stmt(ids))).scalars().all()
        collector_results = (await db.execute(_collector_stmt(ids))).scalars().all()
    except Exception as exc:
        logger.warning("Could not load spawned investigation outcomes: %s", exc)
        return {}
    return _assemble_outcomes(investigations, reports, evidence, collector_results)


# ── Report building ───────────────────────────────────────────────────────────


def build_investigation_report(
    *,
    schema_version: str,
    indicator: dict[str, Any],
    observable_type: str,
    investigation_id: str,
    outcome: dict[str, Any] | None,
    started_at: str,
    include_raw_evidence: bool = False,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    """One alert indicator report, built from a full investigation."""
    now = datetime.now(timezone.utc)
    state = str((outcome or {}).get("state") or "created")
    evidence = (outcome or {}).get("evidence") or {}
    report_json = (outcome or {}).get("report") or {}

    descriptor = {
        "investigation_id": investigation_id,
        "url": f"/investigations/{investigation_id}",
        "state": state,
        "value": (outcome or {}).get("value"),
        "classification": (outcome or {}).get("classification"),
        "confidence": (outcome or {}).get("confidence"),
        "risk_score": (outcome or {}).get("risk_score"),
        "recommended_action": (outcome or {}).get("recommended_action"),
        "created_at": (outcome or {}).get("created_at"),
        "concluded_at": (outcome or {}).get("concluded_at"),
        "executive_summary": _trim(report_json.get("executive_summary"), 1200),
        "spawned_by_alert": True,
    }

    if state not in TERMINAL_STATES:
        # Still running — the verdict arrives on the next read of this alert run.
        return {
            "schema_version": schema_version,
            "report_type": "indicator",
            "indicator": indicator,
            "status": "investigating",
            "investigation": descriptor,
            "verdict": {
                "classification": "not_investigated",
                "risk_score": 0,
                "confidence": 0.0,
                "reasons": [
                    f"Full investigation {investigation_id} is still running "
                    f"(state {state}) — this report updates when it concludes."
                ],
                "sources": ["investigation"],
            },
            "findings": [],
            "sources_checked": ["investigation"],
            "collector_runs": (outcome or {}).get("collector_runs") or [],
            "errors": [],
            "started_at": started_at,
            "completed_at": now.isoformat(),
            "duration_ms": duration_ms if duration_ms is not None else 0,
        }

    classification = str((outcome or {}).get("classification") or "inconclusive")
    risk_score = int((outcome or {}).get("risk_score") or 0)
    confidence = _CONFIDENCE_SCORE.get(str((outcome or {}).get("confidence") or "").lower(), 0.6)
    collector_runs = (outcome or {}).get("collector_runs") or []
    errors = [
        f"{run['collector']}: {run['error']}"
        for run in collector_runs
        if run.get("error")
    ]

    findings = build_indicator_findings(evidence)
    findings.extend(_analyst_findings(report_json))

    status = "failed" if state in FAILED_STATES else "completed"
    if state in FAILED_STATES:
        errors.append(f"Investigation {investigation_id} ended as {state}")

    return {
        "schema_version": schema_version,
        "report_type": "indicator",
        "indicator": indicator,
        "status": status,
        "investigation": descriptor,
        "verdict": {
            "classification": classification if status == "completed" else "inconclusive",
            "risk_score": risk_score,
            "confidence": confidence if status == "completed" else 0.0,
            "reasons": _verdict_reasons(report_json, investigation_id, state),
            "sources": sorted({str(run.get("collector")) for run in collector_runs if run.get("collector")})
            or ["investigation"],
        },
        "findings": findings,
        "sources_checked": ["investigation"]
        + sorted({str(run.get("collector")) for run in collector_runs if run.get("collector")}),
        "collector_runs": collector_runs,
        "errors": errors,
        "started_at": started_at,
        "completed_at": (outcome or {}).get("concluded_at") or now.isoformat(),
        "duration_ms": duration_ms if duration_ms is not None else 0,
        **({"evidence": evidence} if include_raw_evidence else {}),
    }


# ── Hydration of reports whose investigation was still running ────────────────


def pending_investigation_ids(reports: Sequence[dict[str, Any]]) -> list[str]:
    """Investigation ids of reports still waiting on a verdict."""
    ids: list[str] = []
    for report in reports or []:
        if not isinstance(report, dict) or report.get("status") != "investigating":
            continue
        investigation_id = str((report.get("investigation") or {}).get("investigation_id") or "")
        if investigation_id and investigation_id not in ids:
            ids.append(investigation_id)
    return ids


def hydrate_pending_reports(
    reports: list[dict[str, Any]],
    outcomes: dict[str, dict[str, Any]],
    *,
    schema_version: str,
) -> bool:
    """
    Replace every `investigating` report whose investigation has since concluded.

    Mutates `reports` in place; returns True when anything changed.
    """
    changed = False
    for index, report in enumerate(reports or []):
        if not isinstance(report, dict) or report.get("status") != "investigating":
            continue
        investigation_id = str((report.get("investigation") or {}).get("investigation_id") or "")
        outcome = outcomes.get(investigation_id)
        if not outcome or str(outcome.get("state")) not in TERMINAL_STATES:
            continue
        reports[index] = build_investigation_report(
            schema_version=str(report.get("schema_version") or schema_version),
            indicator=report.get("indicator") or {},
            observable_type=str((report.get("indicator") or {}).get("observable_type") or "domain"),
            investigation_id=investigation_id,
            outcome=outcome,
            started_at=str(report.get("started_at") or datetime.now(timezone.utc).isoformat()),
            duration_ms=report.get("duration_ms"),
        )
        changed = True
    return changed


# ── Internals ─────────────────────────────────────────────────────────────────


def _investigation_stmt(ids: list[uuid.UUID]):
    return select(Investigation).where(Investigation.id.in_(ids))


def _report_stmt(ids: list[uuid.UUID]):
    return (
        select(Report)
        .where(Report.investigation_id.in_(ids))
        .order_by(Report.investigation_id, Report.iteration.desc(), Report.created_at.desc())
    )


def _evidence_stmt(ids: list[uuid.UUID]):
    return select(Evidence).where(Evidence.investigation_id.in_(ids))


def _collector_stmt(ids: list[uuid.UUID]):
    return (
        select(CollectorResult)
        .where(CollectorResult.investigation_id.in_(ids))
        .order_by(CollectorResult.investigation_id, CollectorResult.collector_name)
    )


def _assemble_outcomes(investigations, reports, evidence, collector_results) -> dict[str, dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}
    for row in investigations:
        outcomes[str(row.id)] = {
            "investigation_id": str(row.id),
            "value": row.domain,
            "observable_type": row.observable_type,
            "client_domain": row.client_domain,
            "state": row.state,
            "classification": row.classification,
            "confidence": row.confidence,
            "risk_score": row.risk_score,
            "recommended_action": row.recommended_action,
            "created_at": _iso(row.created_at),
            "concluded_at": _iso(row.concluded_at),
            "report": {},
            "evidence": {},
            "collector_runs": [],
        }

    for row in reports:  # ordered newest iteration first — keep the first per investigation
        outcome = outcomes.get(str(row.investigation_id))
        if outcome is not None and not outcome["report"]:
            outcome["report"] = row.report_json or {}

    for row in evidence:
        outcome = outcomes.get(str(row.investigation_id))
        if outcome is not None:
            outcome["evidence"] = row.evidence_json or {}

    for row in collector_results:
        outcome = outcomes.get(str(row.investigation_id))
        if outcome is None:
            continue
        outcome["collector_runs"].append(
            {
                "collector": row.collector_name,
                "status": row.status,
                "duration_ms": row.duration_ms or 0,
                "error": row.error,
            }
        )
    return outcomes


def _verdict_reasons(report_json: dict[str, Any], investigation_id: str, state: str) -> list[str]:
    if state in FAILED_STATES:
        return [f"Investigation {investigation_id} ended as {state} — no verdict was produced."]
    reasons = [
        _trim(item, 400)
        for item in (report_json.get("key_evidence") or [])
        if isinstance(item, str) and item.strip()
    ]
    if not reasons:
        for key in ("primary_reasoning", "executive_summary", "risk_rationale"):
            text = _trim(report_json.get(key), 400)
            if text:
                reasons.append(text)
                break
    if not reasons:
        reasons.append(f"Investigation {investigation_id} concluded without a stated rationale.")
    return reasons[:MAX_VERDICT_REASONS]


def _analyst_findings(report_json: dict[str, Any]) -> list[dict[str, Any]]:
    """The investigation's own analyst findings, in alert-finding shape."""
    findings: list[dict[str, Any]] = []
    for item in (report_json.get("findings") or [])[:MAX_ANALYST_FINDINGS]:
        if not isinstance(item, dict):
            continue
        title = _trim(item.get("title"), 240)
        if not title:
            continue
        findings.append(
            {
                "source": "Investigation analyst",
                "collector": "investigation",
                "type": "threat_intel",
                "severity": str(item.get("severity") or "info").lower(),
                "summary": title,
                "data": _clean(
                    {
                        "description": _trim(item.get("description"), 1200),
                        "evidence_refs": item.get("evidence_refs") or None,
                        "finding_id": item.get("id"),
                    }
                ),
            }
        )
    return findings


def _current_state(investigation_id: str) -> str | None:
    try:
        with Session(sync_engine) as db:
            row = db.get(Investigation, uuid.UUID(investigation_id))
            return str(row.state) if row else None
    except Exception as exc:
        logger.warning("Could not read state of investigation %s: %s", investigation_id, exc)
        return None


def _set_state(investigation_id: str, state: str) -> None:
    try:
        with Session(sync_engine) as db:
            row = db.get(Investigation, uuid.UUID(investigation_id))
            if row:
                row.state = state
                db.commit()
    except Exception as exc:
        logger.warning("Could not set state of investigation %s: %s", investigation_id, exc)


def _parse_ids(investigation_ids: Iterable[str]) -> list[uuid.UUID]:
    parsed: list[uuid.UUID] = []
    for value in investigation_ids or []:
        try:
            candidate = uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            continue
        if candidate not in parsed:
            parsed.append(candidate)
    return parsed


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _trim(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _clean(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}
