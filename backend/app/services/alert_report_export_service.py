"""
Build the alert-run export documents.

One list shape, three depths (see the /export endpoint):

    reports  → [ {ai_assistant}, {indicator}, … ]                 (the run payload as stored)
    report   → [ {executive_summary}, {indicator + soc_report}, … ]
    full     → [ {executive_summary}, {indicator + investigation report + evidence}, … ]

These builders are pure: they take the run payload plus a map of investigation
outcomes and return documents. The API loads outcomes with the async session, the
callback task loads them synchronously — both then call `build_documents()`, so an
integrator polling the endpoint and one receiving a webhook get identical JSON.
"""

from __future__ import annotations

from typing import Any

from app.services.alert_body_investigation_service import ALERT_REPORT_SCHEMA_VERSION
from app.services.alert_indicator_summary_service import build_indicator_summary
from app.services.export_service import build_soc_report_document

# How many IOC-quality rows the report-ready export carries — the SOC report
# template prints the first 30 (templates/soc_report.html).
IOC_QUALITY_ROWS = 30


def investigation_ids_in(payload: dict[str, Any]) -> list[str]:
    """Every investigation referenced by this run, spawned or reused."""
    ids: list[str] = []
    for report in payload.get("indicator_reports") or []:
        _key, investigation_id = investigation_ref(report)
        if investigation_id and investigation_id not in ids:
            ids.append(investigation_id)
    return ids


def build_documents(
    payload: dict[str, Any],
    outcomes: dict[str, dict[str, Any]],
    *,
    shape: str = "report",
    include_evidence: bool = True,
) -> list[dict[str, Any]]:
    """The export list: executive summary first, then one document per indicator."""
    if shape == "reports":
        return list(payload.get("reports") or [])

    documents: list[dict[str, Any]] = [executive_summary_document(payload)]
    # Endpoint events sit between the summary and the indicators: they describe
    # what happened on the host, the indicators describe what it touched.
    documents.extend(
        report for report in (payload.get("event_reports") or []) if isinstance(report, dict)
    )
    for report in payload.get("indicator_reports") or []:
        if not isinstance(report, dict):
            continue
        if shape == "report":
            documents.append(_report_ready_document(report, outcomes))
        else:
            documents.append(_detailed_document(report, outcomes, include_evidence=include_evidence))
    return documents


def investigation_ref(report: Any) -> tuple[str | None, str]:
    """
    Which investigation answers this indicator, if any.

    Returns the report key holding it — `investigation` for one this run started,
    `prior_investigation` for a reused one — and its id.
    """
    if not isinstance(report, dict):
        return None, ""
    for key in ("investigation", "prior_investigation"):
        investigation = report.get(key)
        if isinstance(investigation, dict):
            investigation_id = str(investigation.get("investigation_id") or "").strip()
            if investigation_id:
                return key, investigation_id
    return None, ""


def executive_summary_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Element 0 of the detailed export — the run at a glance, AI reading included."""
    ai_report = payload.get("ai_report") or {}
    summary = payload.get("summary") or {}
    return {
        "schema_version": payload.get("schema_version") or ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "executive_summary",
        "run_id": payload.get("run_id"),
        "title": payload.get("title"),
        "source": payload.get("source") or "alert_body",
        "status": payload.get("status"),
        "overall_verdict": summary.get("overall_verdict") or payload.get("overall_verdict"),
        "highest_risk_score": summary.get("highest_risk_score") or payload.get("highest_risk_score"),
        "started_at": payload.get("started_at") or payload.get("created_at"),
        "completed_at": payload.get("completed_at"),
        "duration_ms": payload.get("duration_ms"),
        "summary": summary,
        "extraction": payload.get("extraction"),
        "prior_investigations": payload.get("prior_investigations"),
        "spawned_investigations": payload.get("spawned_investigations"),
        "investigations": _investigation_index(payload.get("indicator_reports") or []),
        # What the sources found, stated rather than implied: the AI narrative is
        # written from the alert text alone and cannot report a detection count.
        "indicator_summary": build_indicator_summary(payload.get("indicator_reports") or []),
        "endpoint_events": len(payload.get("event_reports") or []),
        "alert_body": payload.get("alert_body"),
        "context": payload.get("context"),
        "error": payload.get("error"),
        "ai_analysis": {
            "status": ai_report.get("status") or "skipped",
            "report_markdown": ai_report.get("report_markdown"),
            "incident_graph": ai_report.get("incident_graph"),
            "assistant_session_id": ai_report.get("assistant_session_id"),
            "assistant_session_url": ai_report.get("assistant_session_url"),
            "sanitization_summary": ai_report.get("sanitization_summary"),
            "generated_at": ai_report.get("generated_at"),
            "error": ai_report.get("error"),
        },
    }


# ── Internals ─────────────────────────────────────────────────────────────────


def _investigation_index(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every investigation behind this run, so the summary alone is navigable."""
    index: list[dict[str, Any]] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        for key in ("investigation", "prior_investigation"):
            investigation = report.get(key)
            if not isinstance(investigation, dict) or not investigation.get("investigation_id"):
                continue
            index.append(
                {
                    "investigation_id": investigation["investigation_id"],
                    "url": investigation.get("url")
                    or f"/investigations/{investigation['investigation_id']}",
                    "indicator": (report.get("indicator") or {}).get("value"),
                    "observable_type": (report.get("indicator") or {}).get("observable_type"),
                    "state": investigation.get("state"),
                    "classification": investigation.get("classification"),
                    "risk_score": investigation.get("risk_score"),
                    "reused": key == "prior_investigation",
                }
            )
    return index


def _report_ready_document(
    report: dict[str, Any],
    outcomes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    One indicator, reduced to what a SOC report is rendered from.

    For a domain/URL that carries an investigation this is `soc_report`: the very
    data model our own PDF template consumes (header, executive summary, analyst
    assessment, evidence matrix, findings, IOCs, recommended actions, derived
    intelligence, signals, technical evidence sections, methodology). The raw
    collector dumps — AnyRun process trees, HAR captures, full IOC inventories —
    are left behind; everything the report prints is already summarised in here.
    """
    document = {
        "schema_version": report.get("schema_version") or ALERT_REPORT_SCHEMA_VERSION,
        "report_type": "indicator",
        "indicator": report.get("indicator") or {},
        "status": report.get("status"),
        "verdict": report.get("verdict") or {},
        "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"),
    }
    if report.get("skip_reason"):
        document["skip_reason"] = report["skip_reason"]

    key, investigation_id = investigation_ref(report)
    if not key:
        # IPs and hashes never get a SOC report — their findings are the payload.
        document["findings"] = report.get("findings") or []
        document["sources_checked"] = report.get("sources_checked") or []
        document["errors"] = report.get("errors") or []
        return document

    investigation = report.get(key) or {}
    document[key] = {
        field: investigation.get(field)
        for field in (
            "investigation_id",
            "url",
            "state",
            "value",
            "classification",
            "confidence",
            "risk_score",
            "recommended_action",
            "created_at",
            "concluded_at",
            "age_days",
            "total_investigations",
        )
        if field in investigation or field in ("investigation_id", "url", "state")
    }
    # Reused investigations are recorded without a link — add one so every
    # investigation in the export is navigable the same way.
    if not document[key].get("url"):
        document[key]["url"] = f"/investigations/{investigation_id}"

    outcome = outcomes.get(investigation_id) or {}
    if not outcome.get("report") and not outcome.get("evidence"):
        return document  # still running, or nothing stored yet

    soc_report = build_soc_report_document(
        evidence=outcome.get("evidence") or {},
        report=outcome.get("report") or {},
        detail=investigation_detail(outcome),
    )
    document["soc_report"] = trim_derived_intelligence(soc_report)
    return document


def _detailed_document(
    report: dict[str, Any],
    outcomes: dict[str, dict[str, Any]],
    *,
    include_evidence: bool,
) -> dict[str, Any]:
    """One indicator report with its investigation's analyst report and evidence."""
    document = dict(report)
    key, investigation_id = investigation_ref(document)
    if not key:
        return document

    outcome = outcomes.get(investigation_id) or {}
    detailed = dict(document.get(key) or {})
    if outcome:
        detailed["state"] = outcome.get("state") or detailed.get("state")
        detailed["report"] = outcome.get("report") or {}
        detailed["collector_runs"] = outcome.get("collector_runs") or document.get("collector_runs") or []
        if include_evidence:
            detailed["evidence"] = outcome.get("evidence") or {}
    if not detailed.get("url"):
        detailed["url"] = f"/investigations/{investigation_id}"
    document[key] = detailed
    return document


def investigation_detail(outcome: dict[str, Any]) -> dict[str, Any]:
    """The investigation row in the shape the SOC report builder expects."""
    return {
        "id": outcome.get("investigation_id"),
        "domain": outcome.get("value"),
        "observable_type": outcome.get("observable_type") or "domain",
        "state": outcome.get("state"),
        "classification": outcome.get("classification"),
        "confidence": outcome.get("confidence"),
        "risk_score": outcome.get("risk_score"),
        "recommended_action": outcome.get("recommended_action"),
        "client_domain": outcome.get("client_domain"),
        "created_at": outcome.get("created_at"),
        "concluded_at": outcome.get("concluded_at"),
    }


def trim_derived_intelligence(soc_report: dict[str, Any]) -> dict[str, Any]:
    """
    Keep the derived-intelligence pieces the report prints, drop the rest.

    The template reads `confidence_engine` and the first 30 `ioc_quality` items;
    the timeline, graph, OpenCTI resolver and report-builder blocks are working
    data for the UI, not report content, and a large investigation carries
    hundreds of IOC rows in them.
    """
    derived = soc_report.get("derived_intelligence")
    if not isinstance(derived, dict):
        return soc_report

    ioc_quality = derived.get("ioc_quality") or {}
    items = ioc_quality.get("items") or []
    soc_report["derived_intelligence"] = {
        "confidence_engine": derived.get("confidence_engine") or {},
        "ioc_quality": {
            **{key: value for key, value in ioc_quality.items() if key != "items"},
            "items": items[:IOC_QUALITY_ROWS],
            "total_items": len(items),
        },
    }
    return soc_report
