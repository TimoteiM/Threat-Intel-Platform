"""
Alert body investigation service.

Takes a raw alert body, extracts its indicators, and answers each one:

    domain / url  → a full investigation (every collector incl. VirusTotal, the
                    AI analyst, a stored report) — reusing a recent concluded one
                    when the platform already knows the value
    ip            → inline collectors + the IP Lookup tool (AbuseIPDB, ThreatFox)
    hash          → inline collectors (VirusTotal, OpenCTI, threat feeds)

The inline path uses the same collector classes the single-observable
investigations use; the domain/url path is the very same pipeline an analyst
starts by hand, so an alert-derived domain lands in the investigations list with
its own report.

The whole alert body is additionally sent through the AI Assistant
(alert_analysis mode, with its sanitisation) so the run carries an analyst-level
reading of the alert alongside the per-indicator evidence.

The output is intentionally machine-first. `reports` is the exported list:

    [ {ai_assistant report}, {indicator report}, {indicator report}, … ]

External platforms that push alert bodies to us receive exactly this structure
back, so the contract is versioned with ALERT_REPORT_SCHEMA_VERSION.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from app.collectors.registry import get_collector, get_collectors_for_type
from app.config import get_settings
from app.services.alert_body_ai_service import run_alert_body_ai_analysis
from app.services.alert_indicator_summary_service import build_analysis_digest, build_indicator_summary
from app.services.alert_finding_builder import build_indicator_findings
from app.services.alert_ioc_extraction_service import (
    DEFAULT_MAX_INDICATORS,
    extract_alert_indicators,
)
from app.services.alert_investigation_spawn_service import (
    build_investigation_report,
    load_outcomes_sync,
    should_spawn,
    spawn_investigation,
    spawn_types,
    wait_for_investigation,
)
from app.services.exclusion_service import (
    apply_to_indicators as apply_exclusions,
    load_matcher_sync as load_exclusion_matcher_sync,
    record_hits_sync as record_exclusion_hits_sync,
)
from app.services.indicator_history_service import (
    annotate_indicators,
    find_prior_investigations_sync,
    history_key,
    is_reusable,
    pairs_from_indicators,
)
from app.services.endpoint_event_service import build_event_report, parse_endpoint_events
from app.services.ip_lookup_service import lookup_ip_with_history, perform_ip_lookup

logger = logging.getLogger(__name__)

ALERT_REPORT_SCHEMA_VERSION = "1.0"

# Collectors that submit samples/scans or burn scarce quota are opt-in: an alert
# body can carry dozens of indicators, so they are never run by default.
OPT_IN_COLLECTORS = frozenset({"hybrid_analysis", "brave_osint"})

# Collectors restricted to specific observable types regardless of what the
# caller asks for. VirusTotal's free tier is 4 requests/min · 500/day, and an
# alert body fans out over many indicators — VT is therefore spent only on file
# hashes, where no other source gives a multi-engine verdict. Domains, URLs and
# IPs already run through DNS/WHOIS/ASN/intel/threat-feeds/URLScan/OpenCTI.
# Controlled by settings.alert_vt_hash_only.
VT_ONLY_OBSERVABLE_TYPES = frozenset({"hash", "file"})

# Indicator type → observable_type understood by the collector registry.
OBSERVABLE_TYPE_BY_INDICATOR = {
    "url": "url",
    "domain": "domain",
    "ip": "ip",
    "hash": "hash",
}

MAX_PARALLEL_INDICATORS = 4
MAX_PARALLEL_COLLECTORS = 5

_MALICIOUS_THRESHOLD = 70
_SUSPICIOUS_THRESHOLD = 35


def _supported_collectors_for(observable_type: str) -> set[str]:
    """Collectors that support the type, minus the ones quota rules hold back."""
    supported = set(get_collectors_for_type(observable_type))
    if "vt" in supported and get_settings().alert_vt_hash_only:
        if observable_type not in VT_ONLY_OBSERVABLE_TYPES:
            supported.discard("vt")
    return supported


def default_collectors_for(observable_type: str) -> list[str]:
    """Baseline collector selection for one observable type (heavy ones excluded)."""
    settings = get_settings()
    supported = _supported_collectors_for(observable_type)
    selected = [
        name
        for name in settings.default_collectors_list
        if name in supported and name not in OPT_IN_COLLECTORS
    ]
    # OpenCTI is not part of DEFAULT_COLLECTORS but is cheap and highly relevant
    # for alert triage, so include it whenever it supports the type.
    if "opencti" in supported and "opencti" not in selected:
        selected.append("opencti")
    return selected


def resolve_collectors(observable_type: str, requested: Iterable[str] | None) -> list[str]:
    """Intersect the requested collectors with those supporting the observable type."""
    supported = _supported_collectors_for(observable_type)
    requested_list = [str(name).strip() for name in (requested or []) if str(name).strip()]
    if not requested_list:
        return default_collectors_for(observable_type)
    selected: list[str] = []
    for name in requested_list:
        if name in supported and name not in selected:
            selected.append(name)
    return selected


def run_alert_body_investigation(
    *,
    alert_body: str,
    run_id: str | None = None,
    title: str | None = None,
    context: str | None = None,
    requested_collectors: list[str] | None = None,
    max_indicators: int = DEFAULT_MAX_INDICATORS,
    run_ip_lookup: bool = True,
    run_ai: bool = True,
    include_raw_evidence: bool = False,
    persist_ip_lookup_history: bool = True,
    collector_timeout: int | None = None,
    ai_model: str | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    reuse_prior_investigations: bool | None = None,
    prior_investigation_lookup: Callable[[list[tuple[str, str]]], dict[str, Any]] | None = None,
    spawn_investigations: bool | None = None,
) -> dict[str, Any]:
    """
    Extract indicators from `alert_body` and investigate each one.

    Returns the aggregated run payload. `reports` is the reusable list-of-JSON
    output described in the module docstring: the AI assistant analysis of the
    whole alert first, then one report per indicator.
    """
    started = datetime.now(timezone.utc)
    t_start = time.perf_counter()
    settings = get_settings()
    timeout = int(collector_timeout or settings.collector_timeout)
    investigation_ref = f"alert-body:{run_id}" if run_id else "alert-body"

    extraction = extract_alert_indicators(alert_body, max_indicators=max_indicators)
    indicators = extraction["indicators"]

    # The exclusion list answers before anything else does. The API applied it
    # too, but the worker re-extracts from the stored body, so without this pass
    # an excluded indicator would be collected anyway — and the list may have
    # grown between the alert arriving and the run starting.
    exclusion_matcher = load_exclusion_matcher_sync()
    excluded_total = apply_exclusions(indicators, exclusion_matcher)
    if excluded_total:
        extraction["investigable_total"] = sum(1 for item in indicators if item.get("investigable"))
        record_exclusion_hits_sync(
            item["exclusion"]["id"] for item in indicators if item.get("exclusion")
        )
    extraction["excluded_total"] = excluded_total

    # Endpoint telemetry (Sysmon/EDR) carries almost nothing to look up, but the
    # process story itself is the evidence — parse it and score its behaviour.
    event_reports = [
        build_event_report(
            event,
            schema_version=ALERT_REPORT_SCHEMA_VERSION,
            started_at=started.isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        for event in parse_endpoint_events(alert_body)
    ]

    # Has the platform already investigated these exact indicators? A recent
    # concluded investigation answers the question without touching a collector.
    max_age_days = int(settings.alert_prior_investigation_max_age_days)
    reuse = (
        settings.alert_reuse_prior_investigations
        if reuse_prior_investigations is None
        else bool(reuse_prior_investigations)
    )
    lookup = prior_investigation_lookup or find_prior_investigations_sync
    history: dict[str, Any] = {}
    if indicators:
        try:
            history = lookup(pairs_from_indicators(indicators)) or {}
        except Exception as exc:  # never let history lookup break a run
            logger.warning("Prior-investigation lookup unavailable: %s", exc)
            history = {}
        annotate_indicators(indicators, history, max_age_days=max_age_days)

    reports: list[dict[str, Any]] = [None] * len(indicators)  # type: ignore[list-item]
    pending: list[tuple[int, dict[str, Any]]] = []

    for index, indicator in enumerate(indicators):
        observable_type = OBSERVABLE_TYPE_BY_INDICATOR.get(str(indicator.get("type")))
        if indicator.get("exclusion"):
            reports[index] = _excluded_report(indicator, observable_type or str(indicator.get("type")))
            continue
        if not indicator.get("investigable") or not observable_type:
            reports[index] = _skipped_report(
                indicator,
                reason=str(
                    indicator.get("skip_reason") or "unsupported_indicator_type"
                ),
            )
            continue
        prior = history.get(history_key(str(indicator.get("type")), str(indicator.get("value") or "")))
        if reuse and is_reusable(prior, max_age_days=max_age_days):
            reports[index] = _reused_report(indicator, observable_type, prior)
            continue
        pending.append((index, indicator))

    # Spawned investigations run in the worker queue; the alert run waits for all
    # of them, but never past this deadline — anything still going is reported as
    # "investigating" and hydrated on the next read of the run.
    investigation_deadline = time.monotonic() + float(settings.alert_investigation_wait_seconds)

    if pending:
        workers = min(MAX_PARALLEL_INDICATORS, len(pending))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="alert-ioc") as pool:
            futures = {
                pool.submit(
                    _investigate_indicator,
                    indicator,
                    investigation_ref=investigation_ref,
                    requested_collectors=requested_collectors,
                    run_ip_lookup=run_ip_lookup,
                    include_raw_evidence=include_raw_evidence,
                    persist_ip_lookup_history=persist_ip_lookup_history,
                    timeout=timeout,
                    is_cancelled=is_cancelled,
                    context=context,
                    spawn_investigations=spawn_investigations,
                    investigation_deadline=investigation_deadline,
                ): index
                for index, indicator in pending
            }
            for future, index in futures.items():
                try:
                    reports[index] = future.result()
                except Exception as exc:  # defensive — _investigate_indicator traps its own errors
                    logger.exception("Alert indicator investigation crashed: %s", exc)
                    reports[index] = _failed_report(indicators[index], error=f"{type(exc).__name__}: {exc}")

    # The AI runs last, on the alert text *and* what the collectors found. It used
    # to run alongside them, which meant the narrative could name a hash but never
    # say whether anything flagged it. The run takes longer for a better read.
    indicator_summary = build_indicator_summary(reports)
    ai_report: dict[str, Any] | None = None
    # An alert whose every indicator was whitelisted has nothing for the analyst
    # to read: no collector output, no event behaviour, and a verdict the
    # exclusion list already decided. Spending tokens to narrate that would undo
    # the saving the list exists for.
    nothing_to_analyse = bool(excluded_total) and not event_reports and not any(
        str(report.get("status")) not in ("excluded", "skipped") for report in reports
    )
    if nothing_to_analyse:
        logger.info("Skipping AI analysis: every indicator was answered by the exclusion list")
    if run_ai and not nothing_to_analyse:
        try:
            ai_report = run_alert_body_ai_analysis(
                alert_body=alert_body,
                title=title or _fallback_title(alert_body),
                context=context,
                model=ai_model,
                schema_version=ALERT_REPORT_SCHEMA_VERSION,
                findings_digest=build_analysis_digest(
                    indicator_summary,
                    event_reports,
                    {"overall_verdict": _provisional_verdict(reports, event_reports)},
                ),
            )
        except Exception as exc:  # run_alert_body_ai_analysis traps its own errors
            logger.exception("Alert-body AI analysis crashed: %s", exc)
            ai_report = {
                "schema_version": ALERT_REPORT_SCHEMA_VERSION,
                "report_type": "ai_assistant",
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }

    completed = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "source": "alert_body",
        "run_id": run_id,
        "context": (context or "").strip() or None,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_ms": int((time.perf_counter() - t_start) * 1000),
        "extraction": {
            "counts": extraction["counts"],
            "total": extraction["total"],
            "investigable_total": extraction["investigable_total"],
            "excluded_total": excluded_total,
            "truncated": extraction["truncated"],
            "dropped": extraction["dropped"],
            "characters": extraction["characters"],
            "max_indicators": max_indicators,
        },
        "exclusions": {
            "applied": excluded_total,
            "list_size": len(exclusion_matcher),
        },
        "prior_investigations": {
            "checked": bool(indicators),
            "reuse_enabled": reuse,
            "max_age_days": max_age_days,
            "matched": len(history),
        },
        "spawned_investigations": {
            "enabled": (
                settings.alert_spawn_investigations
                if spawn_investigations is None
                else bool(spawn_investigations)
            ),
            "observable_types": sorted(spawn_types()),
            "wait_seconds": int(settings.alert_investigation_wait_seconds),
        },
        "ai_report": ai_report,
        "indicator_summary": indicator_summary,
        "event_reports": event_reports,
        "indicator_reports": reports,
        # The exported contract: AI analysis of the whole alert first, then the
        # endpoint events it described, then one report per indicator.
        "reports": ([ai_report] if ai_report else []) + event_reports + reports,
    }
    payload["summary"] = summarize_indicator_reports(reports)
    _merge_event_summary(payload["summary"], event_reports)
    payload["summary"]["ai_analysis"] = (ai_report or {}).get("status") or "skipped"
    logger.info(
        "alert-body investigation %s — %d indicators, %d investigated "
        "(%d reused, %d spawned, %d still running), verdict=%s, %.1fs",
        investigation_ref,
        payload["summary"]["indicators_total"],
        payload["summary"]["indicators_investigated"],
        payload["summary"]["indicators_reused"],
        len(payload["summary"]["investigation_ids"]),
        payload["summary"]["indicators_investigating"],
        payload["summary"]["overall_verdict"],
        (time.perf_counter() - t_start),
    )
    return payload


def _provisional_verdict(
    reports: list[dict[str, Any]], event_reports: list[dict[str, Any]]
) -> str:
    """The run verdict as it stands before the AI reads it — context for the prompt."""
    summary = summarize_indicator_reports(reports)
    _merge_event_summary(summary, event_reports)
    return str(summary.get("overall_verdict") or "inconclusive")


def _merge_event_summary(summary: dict[str, Any], event_reports: list[dict[str, Any]]) -> None:
    """
    Fold endpoint-event verdicts into the run summary.

    An alert whose only content is a Sysmon event has no indicators at all, so the
    run verdict has to come from behaviour — otherwise a process deleting shadow
    copies would roll up as "inconclusive, nothing found".
    """
    summary["events_total"] = len(event_reports)
    if not event_reports:
        summary.setdefault("events_flagged", 0)
        return

    counts = summary.setdefault(
        "classification_counts", {"malicious": 0, "suspicious": 0, "benign": 0, "inconclusive": 0}
    )
    flagged = 0
    for report in event_reports:
        verdict = report.get("verdict") or {}
        classification = str(verdict.get("classification") or "inconclusive")
        if classification in counts:
            counts[classification] += 1
        if classification in ("malicious", "suspicious"):
            flagged += 1
        summary["highest_risk_score"] = max(
            int(summary.get("highest_risk_score") or 0), int(verdict.get("risk_score") or 0)
        )

    summary["events_flagged"] = flagged
    if counts.get("malicious"):
        summary["overall_verdict"] = "malicious"
    elif counts.get("suspicious"):
        summary["overall_verdict"] = "suspicious"
    elif counts.get("benign"):
        summary["overall_verdict"] = "benign"


def summarize_indicator_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll per-indicator verdicts up into the run-level summary."""
    counts = {"malicious": 0, "suspicious": 0, "benign": 0, "inconclusive": 0}
    investigated = 0
    excluded = 0
    skipped = 0
    failed = 0
    reused = 0
    investigating = 0
    highest = 0
    investigation_ids: list[str] = []
    malicious_values: list[str] = []
    suspicious_values: list[str] = []

    for report in reports:
        if not isinstance(report, dict):
            continue
        status = str(report.get("status") or "")
        if status == "skipped":
            skipped += 1
            continue
        if status == "excluded":
            # Benign by policy, so it counts towards the verdict — but nothing
            # was investigated, and saying otherwise would overstate the run.
            excluded += 1
            counts["benign"] += 1
            continue
        if status == "failed":
            failed += 1
        if status == "reused":
            reused += 1
        if status == "investigating":
            investigating += 1
        investigated += 1
        verdict = report.get("verdict") or {}
        classification = str(verdict.get("classification") or "inconclusive")
        if classification in counts:
            counts[classification] += 1
        score = int(verdict.get("risk_score") or 0)
        highest = max(highest, score)
        investigation_id = str((report.get("investigation") or {}).get("investigation_id") or "")
        if investigation_id and investigation_id not in investigation_ids:
            investigation_ids.append(investigation_id)
        value = str((report.get("indicator") or {}).get("value") or "")
        if classification == "malicious" and value:
            malicious_values.append(value)
        elif classification == "suspicious" and value:
            suspicious_values.append(value)

    if counts["malicious"]:
        overall = "malicious"
    elif counts["suspicious"]:
        overall = "suspicious"
    elif counts["benign"]:
        overall = "benign"
    else:
        overall = "inconclusive"

    return {
        "indicators_total": len(reports),
        "indicators_investigated": investigated,
        "indicators_excluded": excluded,
        "indicators_skipped": skipped,
        "indicators_failed": failed,
        "indicators_reused": reused,
        "indicators_investigating": investigating,
        "investigation_ids": investigation_ids,
        "classification_counts": counts,
        "highest_risk_score": highest,
        "overall_verdict": overall,
        "malicious_indicators": malicious_values[:25],
        "suspicious_indicators": suspicious_values[:25],
    }


# ── Per-indicator investigation ───────────────────────────────────────────────


def _investigate_indicator(
    indicator: dict[str, Any],
    *,
    investigation_ref: str,
    requested_collectors: list[str] | None,
    run_ip_lookup: bool,
    include_raw_evidence: bool,
    persist_ip_lookup_history: bool,
    timeout: int,
    is_cancelled: Callable[[], bool] | None,
    context: str | None = None,
    spawn_investigations: bool | None = None,
    investigation_deadline: float | None = None,
) -> dict[str, Any]:
    if is_cancelled and is_cancelled():
        return _skipped_report(indicator, reason="run_cancelled")

    started = datetime.now(timezone.utc)
    t_start = time.perf_counter()
    value = str(indicator.get("value") or "")
    observable_type = OBSERVABLE_TYPE_BY_INDICATOR[str(indicator.get("type"))]

    # Domains and URLs get the real pipeline, not a handful of inline collectors.
    if should_spawn(observable_type, enabled=spawn_investigations):
        return _investigate_via_full_investigation(
            indicator,
            observable_type=observable_type,
            value=value,
            context=context,
            started=started,
            t_start=t_start,
            deadline=investigation_deadline,
            include_raw_evidence=include_raw_evidence,
            is_cancelled=is_cancelled,
        )

    collectors = resolve_collectors(observable_type, requested_collectors)

    evidence: dict[str, Any] = {}
    runs: list[dict[str, Any]] = []
    errors: list[str] = []

    if collectors:
        workers = min(MAX_PARALLEL_COLLECTORS, len(collectors))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="alert-collector") as pool:
            futures = {
                pool.submit(
                    _run_collector,
                    name,
                    value=value,
                    observable_type=observable_type,
                    investigation_ref=investigation_ref,
                    timeout=timeout,
                ): name
                for name in collectors
            }
            for future, name in futures.items():
                collector_evidence, run_meta = future.result()
                if collector_evidence is not None:
                    evidence[name] = collector_evidence
                runs.append(run_meta)
                if run_meta.get("error"):
                    errors.append(f"{name}: {run_meta['error']}")

    runs.sort(key=lambda item: str(item.get("collector") or ""))

    ip_lookup: dict[str, Any] | None = None
    if observable_type == "ip" and run_ip_lookup:
        try:
            ip_lookup = (
                lookup_ip_with_history(value, timeout=timeout)
                if persist_ip_lookup_history
                else perform_ip_lookup(value, timeout=timeout)
            )
        except Exception as exc:
            errors.append(f"ip_lookup: {type(exc).__name__}: {exc}")
            ip_lookup = {"ip": value, "errors": [f"{type(exc).__name__}: {exc}"]}

    completed = datetime.now(timezone.utc)
    verdict = assess_indicator(evidence, ip_lookup=ip_lookup)
    all_failed = bool(runs) and all(run.get("status") == "failed" for run in runs)

    findings = build_indicator_findings(evidence, ip_lookup=ip_lookup)
    report: dict[str, Any] = {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "indicator",
        "indicator": _indicator_descriptor(indicator, observable_type),
        "status": "failed" if (all_failed and not ip_lookup) else "completed",
        "verdict": verdict,
        # What was actually found — sources that saw nothing contribute nothing.
        "findings": findings,
        "sources_checked": collectors + (["ip_lookup"] if ip_lookup else []),
        "collector_runs": runs,
        "errors": errors,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_ms": int((time.perf_counter() - t_start) * 1000),
    }
    if include_raw_evidence:
        report["evidence"] = evidence
        report["ip_lookup"] = ip_lookup
    return report


def _investigate_via_full_investigation(
    indicator: dict[str, Any],
    *,
    observable_type: str,
    value: str,
    context: str | None,
    started: datetime,
    t_start: float,
    deadline: float | None,
    include_raw_evidence: bool,
    is_cancelled: Callable[[], bool] | None,
) -> dict[str, Any]:
    """Create a full investigation for this indicator, wait for it, report it."""
    descriptor = _indicator_descriptor(indicator, observable_type)
    investigation_id = spawn_investigation(value, observable_type, context=context)
    if not investigation_id:
        return _failed_report(indicator, error=f"Could not start an investigation for {value}")

    wait_for_investigation(
        investigation_id,
        deadline=deadline if deadline is not None else time.monotonic(),
        is_cancelled=is_cancelled,
    )
    outcome = load_outcomes_sync([investigation_id]).get(investigation_id)

    return build_investigation_report(
        schema_version=ALERT_REPORT_SCHEMA_VERSION,
        indicator=descriptor,
        observable_type=observable_type,
        investigation_id=investigation_id,
        outcome=outcome,
        started_at=started.isoformat(),
        include_raw_evidence=include_raw_evidence,
        duration_ms=int((time.perf_counter() - t_start) * 1000),
    )


def _run_collector(
    name: str,
    *,
    value: str,
    observable_type: str,
    investigation_ref: str,
    timeout: int,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    collector_cls = get_collector(name)
    if not collector_cls:
        return None, {"collector": name, "status": "skipped", "error": "Unknown collector", "duration_ms": 0}

    try:
        collector = collector_cls(
            domain=value,
            investigation_id=investigation_ref,
            observable_type=observable_type,
            timeout=timeout,
        )
        collected, meta, _artifacts = collector.run()
        payload = collected.model_dump(mode="json") if hasattr(collected, "model_dump") else {}
        payload.pop("meta", None)
        return payload, {
            "collector": name,
            "status": getattr(meta.status, "value", str(meta.status)),
            "duration_ms": meta.duration_ms or 0,
            "error": meta.error,
        }
    except Exception as exc:
        logger.warning("Alert-body collector %s failed for %s: %s", name, value, exc)
        return None, {
            "collector": name,
            "status": "failed",
            "duration_ms": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _fallback_title(alert_body: str) -> str:
    first_line = next((line.strip() for line in str(alert_body or "").splitlines() if line.strip()), "")
    return (first_line or "Alert body")[:255]


def _indicator_descriptor(indicator: dict[str, Any], observable_type: str | None = None) -> dict[str, Any]:
    descriptor = {
        "value": indicator.get("value"),
        "type": indicator.get("type"),
        "observable_type": observable_type,
        "occurrences": indicator.get("occurrences", 1),
        "defanged_in_source": bool(indicator.get("defanged_in_source")),
        "matched_text": indicator.get("matched_text"),
    }
    for optional in ("host", "hostnames", "hash_type", "ip_version", "derived_from", "prior_investigation"):
        if indicator.get(optional) is not None:
            descriptor[optional] = indicator[optional]
    return descriptor


# Investigation.confidence is a label; the alert verdict carries a number.
_CONFIDENCE_SCORE = {"high": 0.9, "medium": 0.75, "low": 0.5}
_SEVERITY_BY_CLASSIFICATION = {"malicious": "high", "suspicious": "medium", "benign": "info"}


def _reused_report(
    indicator: dict[str, Any],
    observable_type: str,
    prior: dict[str, Any],
) -> dict[str, Any]:
    """Report built from an existing investigation of the same indicator."""
    now = datetime.now(timezone.utc).isoformat()
    classification = str(prior.get("classification") or "inconclusive")
    risk_score = int(prior.get("risk_score") or 0)
    confidence = _CONFIDENCE_SCORE.get(str(prior.get("confidence") or "").lower(), 0.6)
    age = prior.get("age_days")
    when = f"{float(age):.1f} day(s) ago" if age is not None else "previously"
    reason = (
        f"Already investigated {when}: {classification}"
        f"{f' (risk {risk_score})' if risk_score else ''}"
        f" — investigation {prior.get('investigation_id')}"
    )
    return {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "indicator",
        "indicator": _indicator_descriptor(indicator, observable_type),
        "status": "reused",
        "prior_investigation": prior,
        "verdict": _verdict(
            classification,
            risk_score,
            confidence,
            [reason],
            sources=["prior_investigation"],
        ),
        "findings": [
            {
                "source": "Prior investigation",
                "collector": "prior_investigation",
                "type": "threat_intel",
                "severity": _SEVERITY_BY_CLASSIFICATION.get(classification, "info"),
                "summary": reason,
                "data": prior,
            }
        ],
        "sources_checked": ["prior_investigation"],
        "collector_runs": [],
        "errors": [],
        "started_at": now,
        "completed_at": now,
        "duration_ms": 0,
    }


def _excluded_report(indicator: dict[str, Any], observable_type: str) -> dict[str, Any]:
    """
    Report for an indicator the exclusion list answered.

    Benign, because that is what the exclusion asserts — but never silent: the
    entry that decided it, and who added it, are on the report, so a wrong
    verdict leads straight back to the row that caused it.
    """
    now = datetime.now(timezone.utc).isoformat()
    exclusion = indicator.get("exclusion") or {}
    matched = exclusion.get("matched") or indicator.get("value")
    note = str(exclusion.get("reason") or "").strip()
    reason = f"On the exclusion list as {matched} — treated as benign without collection"
    if note:
        reason = f"{reason}: {note}"
    return {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "indicator",
        "indicator": _indicator_descriptor(indicator, observable_type),
        "status": "excluded",
        "exclusion": exclusion,
        "verdict": _verdict("benign", 0, 1.0, [reason], sources=["exclusion"]),
        "findings": [
            {
                "source": "Exclusion list",
                "collector": "exclusion",
                "type": "policy",
                "severity": "info",
                "summary": reason,
                "data": exclusion,
            }
        ],
        "sources_checked": ["exclusion"],
        "collector_runs": [],
        "errors": [],
        "started_at": now,
        "completed_at": now,
        "duration_ms": 0,
    }


def _skipped_report(indicator: dict[str, Any], *, reason: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "indicator",
        "indicator": _indicator_descriptor(
            indicator, OBSERVABLE_TYPE_BY_INDICATOR.get(str(indicator.get("type")))
        ),
        "status": "skipped",
        "skip_reason": reason,
        "verdict": _verdict("not_investigated", 0, 0.0, []),
        "findings": [],
        "sources_checked": [],
        "collector_runs": [],
        "errors": [],
        "started_at": now,
        "completed_at": now,
        "duration_ms": 0,
    }


def _failed_report(indicator: dict[str, Any], *, error: str) -> dict[str, Any]:
    report = _skipped_report(indicator, reason="investigation_error")
    report["status"] = "failed"
    report["errors"] = [error]
    report["verdict"] = _verdict("inconclusive", 0, 0.0, [])
    return report


# ── Deterministic verdict ─────────────────────────────────────────────────────


def assess_indicator(
    evidence: dict[str, Any],
    *,
    ip_lookup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Derive a deterministic verdict for one indicator from its collector evidence.

    No AI involved: alert-body triage must be fast, repeatable and explainable,
    so the score is the strongest reputation signal any collector returned.
    """
    signals: list[tuple[int, str, str]] = []  # (score, source, reason)

    # Thresholds mirror app.services.decision_engine so an indicator triaged from
    # an alert body lands on the same verdict as a full investigation would.
    vt = evidence.get("vt") if isinstance(evidence.get("vt"), dict) else {}
    if vt:
        malicious = int(vt.get("malicious_count") or 0)
        suspicious = int(vt.get("suspicious_count") or 0)
        if malicious >= 5:
            signals.append((min(95, 85 + malicious), "vt", f"VirusTotal: {malicious} engine(s) flag this as malicious"))
        elif malicious >= 2:
            signals.append((60, "vt", f"VirusTotal: {malicious} engine(s) flag this as malicious"))
        elif malicious == 1:
            signals.append((45, "vt", "VirusTotal: 1 engine flags this as malicious"))
        elif suspicious >= 5:
            signals.append((55, "vt", f"VirusTotal: {suspicious} engine(s) flag this as suspicious"))
        elif suspicious > 0:
            signals.append((35, "vt", f"VirusTotal: {suspicious} engine(s) flag this as suspicious"))
        elif int(vt.get("total_vendors") or 0) > 0:
            signals.append((5, "vt", "VirusTotal: no engine detections"))

    feeds = evidence.get("threat_feeds") if isinstance(evidence.get("threat_feeds"), dict) else {}
    if feeds:
        phishtank = feeds.get("phishtank") or {}
        if isinstance(phishtank, dict) and phishtank.get("in_database"):
            if phishtank.get("verified"):
                signals.append((90, "threat_feeds", "PhishTank: verified phishing listing"))
            else:
                # Unverified PhishTank entries are frequently stale submissions.
                signals.append((30, "threat_feeds", "PhishTank: unverified listing (needs manual confirmation)"))
        if feeds.get("openphish_listed"):
            signals.append((90, "threat_feeds", "OpenPhish: listed as a phishing URL"))
        gsb = feeds.get("google_safe_browsing") or {}
        if isinstance(gsb, dict) and gsb.get("listed"):
            threat_types = ", ".join(gsb.get("threat_types") or []) or "listed"
            signals.append((85, "threat_feeds", f"Google Safe Browsing: {threat_types}"))
        threatfox = feeds.get("threatfox_matches") or []
        if threatfox:
            malware = ", ".join(
                sorted({str(row.get("malware")) for row in threatfox if isinstance(row, dict) and row.get("malware")})
            )
            signals.append((
                90,
                "threat_feeds",
                f"ThreatFox: {len(threatfox)} match(es){f' — {malware}' if malware else ''}",
            ))
        abuse = feeds.get("abuseipdb") or {}
        if isinstance(abuse, dict) and abuse.get("abuse_confidence_score") is not None:
            signals.extend(_abuse_signals(int(abuse.get("abuse_confidence_score") or 0), int(abuse.get("total_reports") or 0), "threat_feeds"))
        otx = feeds.get("otx") or {}
        pulse_count = int((otx or {}).get("pulse_count") or 0) if isinstance(otx, dict) else 0
        if pulse_count > 0:
            # OTX pulses are noisy on their own — only a cluster of them is a lead.
            signals.append((
                40 if pulse_count >= 3 else 30,
                "threat_feeds",
                f"AlienVault OTX: {pulse_count} pulse(s) reference this indicator",
            ))

    urlscan = evidence.get("urlscan") if isinstance(evidence.get("urlscan"), dict) else {}
    if urlscan:
        verdict = str(urlscan.get("verdict") or "").lower()
        if verdict == "malicious":
            signals.append((80, "urlscan", "URLScan verdict: malicious"))
        elif verdict == "suspicious":
            signals.append((50, "urlscan", "URLScan verdict: suspicious"))

    opencti = evidence.get("opencti") if isinstance(evidence.get("opencti"), dict) else {}
    if opencti and opencti.get("found"):
        score = int(opencti.get("score") or 0)
        indicators = opencti.get("indicators") or []
        if score >= 70 or indicators:
            signals.append((max(65, min(90, score)), "opencti", f"OpenCTI knows this observable (score {score})"))
        else:
            signals.append((40, "opencti", f"OpenCTI knows this observable (score {score})"))

    anyrun = evidence.get("hybrid_analysis") if isinstance(evidence.get("hybrid_analysis"), dict) else {}
    for item in (anyrun.get("items") or []) if anyrun else []:
        if not isinstance(item, dict):
            continue
        verdict = str(item.get("verdict") or "").lower()
        if verdict == "malicious":
            signals.append((85, "hybrid_analysis", "AnyRun: malicious verdict"))
        elif verdict == "suspicious":
            signals.append((50, "hybrid_analysis", "AnyRun: suspicious verdict"))

    intel = evidence.get("intel") if isinstance(evidence.get("intel"), dict) else {}
    if intel and intel.get("blocklist_hits"):
        signals.append((60, "intel", f"Blocklist hits: {len(intel['blocklist_hits'])}"))

    osint = evidence.get("brave_osint") if isinstance(evidence.get("brave_osint"), dict) else {}
    if osint and str(osint.get("risk_level") or "").lower() == "high":
        signals.append((45, "brave_osint", "Public OSINT reports flag this indicator"))

    whois = evidence.get("whois") if isinstance(evidence.get("whois"), dict) else {}
    if whois and whois.get("domain_age_days") is not None:
        age = int(whois["domain_age_days"])
        if 0 <= age <= 30:
            signals.append((45, "whois", f"Domain registered {age} day(s) ago"))

    if ip_lookup:
        abuse = ip_lookup.get("abuseipdb") or {}
        if isinstance(abuse, dict) and abuse.get("abuse_confidence_score") is not None:
            signals.extend(
                _abuse_signals(
                    int(abuse.get("abuse_confidence_score") or 0),
                    int(abuse.get("total_reports") or 0),
                    "ip_lookup",
                )
            )
        threatfox = ip_lookup.get("threatfox") or []
        if threatfox:
            signals.append((80, "ip_lookup", f"IP Lookup / ThreatFox: {len(threatfox)} match(es)"))

    if not signals:
        return _verdict("inconclusive", 0, 0.0, ["No collector returned a reputation signal for this indicator."])

    risk_score = max(score for score, _source, _reason in signals)
    contributing = sorted({source for score, source, _reason in signals if score >= _SUSPICIOUS_THRESHOLD})
    reasons = [reason for score, _source, reason in sorted(signals, key=lambda item: -item[0])][:8]

    if risk_score >= _MALICIOUS_THRESHOLD:
        classification = "malicious"
    elif risk_score >= _SUSPICIOUS_THRESHOLD:
        classification = "suspicious"
    else:
        classification = "benign"

    sources_with_data = sorted({source for _score, source, _reason in signals})
    confidence = round(min(0.95, 0.45 + 0.15 * len(contributing or sources_with_data)), 2)

    return _verdict(classification, risk_score, confidence, reasons, sources=sources_with_data)


def _abuse_signals(score: int, reports: int, source: str) -> list[tuple[int, str, str]]:
    label = f"AbuseIPDB confidence {score}% ({reports} report(s))"
    if score >= 50:
        return [(min(90, 60 + score // 4), source, label)]
    if score >= 25:
        return [(50, source, label)]
    if score > 0:
        return [(20, source, label)]
    return [(5, source, "AbuseIPDB: no abuse reports")]


def _verdict(
    classification: str,
    risk_score: int,
    confidence: float,
    reasons: list[str],
    *,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": reasons,
        "sources": sources or [],
    }
