"""
Alert body investigation endpoints.

POST   /api/alert-investigations/extract    → Parse an alert body (no collectors)
POST   /api/alert-investigations            → Queue a full alert-body investigation (JSON)
POST   /api/alert-investigations/raw        → Same, with the raw alert text as the body
GET    /api/alert-investigations            → List past runs
GET    /api/alert-investigations/{run_id}   → Run status + aggregated JSON reports
GET    /api/alert-investigations/{run_id}/export → Download that report list
POST   /api/alert-investigations/{run_id}/cancel → Cancel a queued/running run
DELETE /api/alert-investigations/{run_id}   → Delete a run

The completed run payload carries `reports`: the AI assistant's reading of the
whole alert first, then one JSON report per extracted indicator. That list is
the integration contract for external platforms that send us alert bodies — see
app.services.alert_body_investigation_service. `/export` serves exactly that list
as a file so a reporting platform can pull it with one GET.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Path as FastAPIPath, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import defer
from sqlalchemy import func, or_, select

import redis as redis_lib

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import AlertBodyInvestigationRun, Investigation
from app.models.schemas import AlertBodyExtractRequest, AlertBodyInvestigationCreate
from app.services.alert_body_investigation_service import (
    ALERT_REPORT_SCHEMA_VERSION,
    summarize_indicator_reports,
)
from app.services.alert_investigation_spawn_service import (
    hydrate_pending_reports,
    load_outcomes,
    pending_investigation_ids,
)
from app.services.alert_indicator_summary_service import build_indicator_summary
from app.services.alert_ingest_service import (
    CallbackUrlError,
    alert_body_hash,
    find_duplicate_run,
    find_run_by_external_ref,
    validate_callback_url,
)
from app.services.exclusion_service import apply_to_indicators, load_matcher
from app.services.alert_ioc_extraction_service import extract_alert_indicators
from app.services.alert_payload_service import looks_like_siem_alert, normalize_alert_payload
from app.services.alert_report_export_service import build_documents, investigation_ids_in
from app.services.alert_correlation_service import case_for_run
from app.services.alert_field_service import (
    SEVERITY_ONLY_FIELDS,
    SUPPRESSIBLE_FIELDS,
    client_of,
    entity_of,
    event_time_of,
    extract_alert_fields,
    is_pre_correlated,
    source_of,
)
from app.services.endpoint_event_service import parse_endpoint_events
from app.services.indicator_history_service import (
    annotate_indicators,
    find_prior_investigations,
    pairs_from_indicators,
)
from app.tasks.alert_body_task import run_alert_body_investigation_task
from app.tasks.cancellation import find_task_ids, revoke_task_ids

router = APIRouter(prefix="/api/alert-investigations", tags=["alert-investigations"])
logger = logging.getLogger(__name__)

ACTIVE_STATUSES = {"queued", "processing", "running"}

# Synchronous ingest: how long a caller may hold the connection open. A run with
# spawned domain investigations can take far longer than any sane HTTP timeout,
# so the wait is bounded and falls back to the queued response.
DEFAULT_WAIT_TIMEOUT_SECONDS = 300
MIN_WAIT_TIMEOUT_SECONDS = 5
MAX_WAIT_TIMEOUT_SECONDS = 900
WAIT_POLL_SECONDS = 2
# Extraction is linear at roughly six seconds per megabyte, so a very large body
# is affordable in a background worker but not unbounded — a 100 MB paste would
# hold a worker thread for ten minutes. Everything is stored and accepted; only
# what is scanned for indicators is capped, and the run says when that happened.
MAX_ANALYSED_ALERT_BODY_CHARS = 10_000_000


@router.post("/extract")
async def extract_indicators(
    db: DBSession,
    payload: dict[str, Any] = Body(...),
    max_indicators: int = 30,
) -> dict[str, Any]:
    """
    Parse an alert and return what would be investigated — no collectors, no run.

    Accepts the same two shapes as the ingest route: `{"alert_body": "…"}` or the
    sender's own alert document. The dry run is how you check a new feed's format
    without spending collector or AI budget on it.
    """
    request = _request_from_payload(payload, max_indicators=max_indicators)
    alert_body = _validated_alert_body(request.alert_body)
    analysed_body = alert_body[:MAX_ANALYSED_ALERT_BODY_CHARS]
    body_truncated_for_analysis = len(alert_body) > len(analysed_body)
    extraction = extract_alert_indicators(analysed_body, max_indicators=request.max_indicators)
    excluded = await _apply_exclusions(db, extraction)
    await _attach_prior_investigations(db, extraction["indicators"])
    return {
        "schema_version": ALERT_REPORT_SCHEMA_VERSION,
        "title": request.title,
        "external_ref": request.external_ref,
        "excluded_total": excluded,
        **extraction,
    }


@router.post("")
async def create_alert_investigation(
    db: DBSession,
    payload: dict[str, Any] = Body(...),
    title: str | None = None,
    context: str | None = None,
    external_ref: str | None = None,
    callback_url: str | None = None,
    dedupe: bool | None = None,
    run_ai: bool | None = None,
    spawn_investigations: bool | None = None,
    wait: bool = True,
    wait_timeout: int = DEFAULT_WAIT_TIMEOUT_SECONDS,
) -> Any:
    """
    Investigate an alert body and return its report.

    Two request shapes are accepted:

    * **Our schema** — `{"alert_body": "…", "title": …, "callback_url": …}`.
    * **The sender's own alert document** — post the Wazuh/OpenSearch/EDR alert
      as it is. Flattened (`"data.win.system.message": …`) or nested
      (`{"data": {"win": …}}`) both work: the raw event message becomes the alert
      body under a header of the fields that identify the alert, the title comes
      from `title`/`rule.description`, and `_id`/`id` becomes `external_ref`.
      Ingest options travel as query parameters, as they do on `/raw`.

    The request is held until the investigation finishes and returns the report
    list itself — the same array as `/export?format=report` — so a sender gets a
    finished report from one call. `wait=false` returns as soon as the run is
    queued instead (what the UI does, since it navigates to the run page), and
    `wait_timeout` bounds how long the connection is held before falling back to
    that queued response with 202.

    An alert already seen returns the report the first delivery produced, rather
    than investigating it again — so a re-send costs nothing and still answers
    with a report. That it was a duplicate travels on the executive summary as
    `ingest` and in the `X-Alert-Deduplicated` header. With `wait=false` the
    queued-shaped response carries `deduplicated` and a message instead.
    """
    queued = await _create_alert_run(
        _request_from_payload(
            payload,
            title=title,
            context=context,
            external_ref=external_ref,
            callback_url=callback_url,
            dedupe=dedupe,
            run_ai=run_ai,
            spawn_investigations=spawn_investigations,
        ),
        db,
    )
    if not wait:
        return queued
    return await _wait_for_report(db, queued, timeout=wait_timeout)


def _request_from_payload(payload: dict[str, Any], **options: Any) -> AlertBodyInvestigationCreate:
    """
    Build the run request from either shape of POST body.

    Our own schema is honoured exactly as before — including its validation
    errors. Anything else is treated as the sender's alert document, and query
    parameters fill in what the document cannot say (callback URL, dedupe…),
    never overriding a value the document itself carried.
    """
    supplied = {key: value for key, value in options.items() if value is not None}

    if not looks_like_siem_alert(payload):
        fields = {**supplied, **{k: v for k, v in payload.items() if v is not None}}
        try:
            return AlertBodyInvestigationCreate(**fields)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

    max_indicators = supplied.pop("max_indicators", None)
    normalized = normalize_alert_payload(payload)
    if not (normalized.get("alert_body") or "").strip():
        raise HTTPException(
            status_code=422,
            detail=(
                "Could not read an alert out of this document: no alert_body field, and no "
                "message/event text among its keys."
            ),
        )
    return AlertBodyInvestigationCreate(
        alert_body=normalized["alert_body"],
        title=supplied.get("title") or normalized.get("title"),
        external_ref=supplied.get("external_ref") or normalized.get("external_ref"),
        detection_rule_id=supplied.get("detection_rule_id") or normalized.get("detection_rule_id"),
        detection_rule_name=supplied.get("detection_rule_name") or normalized.get("detection_rule_name"),
        context=supplied.get("context"),
        callback_url=supplied.get("callback_url"),
        dedupe=supplied.get("dedupe"),
        run_ai=supplied.get("run_ai", True),
        spawn_investigations=supplied.get("spawn_investigations"),
        **({"max_indicators": max_indicators} if max_indicators else {}),
    )


@router.post("/raw")
async def create_alert_investigation_from_raw_text(
    http_request: Request,
    db: DBSession,
    title: str | None = None,
    context: str | None = None,
    external_ref: str | None = None,
    callback_url: str | None = None,
    dedupe: bool | None = None,
    run_ai: bool = True,
    run_ip_lookup: bool = True,
    spawn_investigations: bool | None = None,
    reuse_prior_investigations: bool | None = None,
    include_raw_evidence: bool = False,
    # Plain default, not Query(...): this handler is called directly in tests and
    # a Query object would reach the model as a non-integer.
    max_indicators: int = 30,
    collectors: str | None = None,
    wait: bool = True,
    wait_timeout: int = DEFAULT_WAIT_TIMEOUT_SECONDS,
) -> Any:
    """
    Same as POST /api/alert-investigations, but the request body *is* the alert.

    Send the alert exactly as your SIEM emitted it with `Content-Type: text/plain`
    — no JSON wrapper, no escaping of the quotes and backslashes a Sysmon line or
    a Windows command line is full of. Everything the JSON form takes as a field
    is a query parameter here.

    The body is decoded as UTF-8 with replacement, because log forwarders send
    whatever encoding the source used and a mangled character is a far better
    outcome than a rejected alert.
    """
    raw = await http_request.body()
    queued = await _create_alert_run(
        AlertBodyInvestigationCreate(
            alert_body=raw.decode("utf-8", errors="replace"),
            title=title,
            context=context,
            external_ref=external_ref,
            callback_url=callback_url,
            dedupe=dedupe,
            run_ai=run_ai,
            run_ip_lookup=run_ip_lookup,
            spawn_investigations=spawn_investigations,
            reuse_prior_investigations=reuse_prior_investigations,
            include_raw_evidence=include_raw_evidence,
            max_indicators=max(1, min(100, int(max_indicators))),
            requested_collectors=(
                [name.strip() for name in collectors.split(",") if name.strip()] if collectors else None
            ),
        ),
        db,
    )
    if not wait:
        return queued
    return await _wait_for_report(db, queued, timeout=wait_timeout)


async def _create_alert_run(
    request: AlertBodyInvestigationCreate,
    db: DBSession,
) -> dict[str, Any]:
    """
    Queue an investigation for every indicator found in the alert body.

    This is also the ingest endpoint for other platforms: POST the raw alert text
    and either poll the returned `links`, or pass `callback_url` and receive the
    finished report list.

    Nothing is investigated twice. An alert carrying an id we have already run
    (`_id`/`id`/`alert_id` → `external_ref`) comes straight back as that run, at
    any age; an identical alert *body* does too, within the dedupe window. Both
    answer with `deduplicated: true` and a message saying which matched. Only
    failed and cancelled runs are re-run, and `dedupe=false` forces a fresh one.
    """
    settings = get_settings()
    alert_body = _validated_alert_body(request.alert_body)

    try:
        callback_url = validate_callback_url(request.callback_url)
    except CallbackUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    body_hash = alert_body_hash(alert_body)
    external_ref = (request.external_ref or "").strip() or None
    dedupe = settings.alert_ingest_dedupe if request.dedupe is None else bool(request.dedupe)
    if dedupe:
        # The sender's own alert id first: it survives re-formatting and added
        # enrichment, which the body hash does not.
        existing = await find_run_by_external_ref(db, external_ref)
        if existing is not None:
            logger.info("Alert ingest deduplicated onto run %s by alert id %s", existing.id, external_ref)
            return _ingest_response(existing, deduplicated=True, deduplicated_by="external_ref")
        existing = await find_duplicate_run(db, body_hash)
        if existing is not None:
            logger.info("Alert ingest deduplicated onto run %s", existing.id)
            return _ingest_response(existing, deduplicated=True, deduplicated_by="alert_body")

    analysed_body = alert_body[:MAX_ANALYSED_ALERT_BODY_CHARS]
    body_truncated_for_analysis = len(alert_body) > len(analysed_body)

    # What the alert *is*, as opposed to what it contains. Two things read this:
    # an `alert` exclusion matches on these fields, and correlation groups on
    # the entity they yield.
    alert_fields = extract_alert_fields(
        analysed_body,
        rule_id=(request.detection_rule_id or "").strip() or None,
        rule_name=(request.detection_rule_name or "").strip() or None,
    )
    entity_host, entity_user = entity_of(alert_fields)
    alert_source = source_of(alert_fields, declared=(request.source or "").strip() or None)
    alert_client = client_of(alert_fields, declared=(request.client or "").strip() or None)
    alert_kind = "incident" if is_pre_correlated(alert_fields) else "alert"
    # Falls back to now(): the run's own created_at is not assigned until the
    # row is flushed, and "when we received it" is the same instant.
    event_time = event_time_of(analysed_body, fallback=datetime.now(timezone.utc))

    matcher = await load_matcher(db)
    suppression = matcher.match_alert(alert_fields)

    extraction = extract_alert_indicators(analysed_body, max_indicators=request.max_indicators)
    excluded_total = await _apply_exclusions(db, extraction, matcher=matcher)

    if suppression is not None:
        # Suppression removes the spend, never the record. The run is still
        # created, still carries its entity and timestamp, and still counts
        # towards a correlation window — because the alert an analyst muted as
        # routine is exactly the one that turns out to be step one of a chain,
        # and a dropped alert cannot be counted later. The rule this silences
        # produced 173 malicious verdicts alongside its noise.
        logger.info(
            "Alert matched suppression %s — recording without collector spend",
            suppression.get("id"),
        )
        for indicator in extraction.get("indicators") or []:
            indicator["investigable"] = False
        extraction["investigable_total"] = 0
    await _attach_prior_investigations(db, extraction["indicators"])
    # Endpoint telemetry (Sysmon/EDR) is worth a run on its own: the process
    # behaviour is the evidence even when there is nothing to look up.
    endpoint_events = parse_endpoint_events(analysed_body)
    # An alert with no extractable indicator is still an alert. It has a raw log
    # line, a host, a user, a file, a signature name — everything an analyst
    # reads first and most of what decides the verdict. This used to answer 422
    # "nothing to investigate", which threw away every one of those: a generic
    # AV detection on a signed OS binary, or a connection between two internal
    # addresses, arrived as a refusal rather than an assessment.
    #
    # The only genuinely empty case — no payload at all — is already refused by
    # _validated_alert_body above, which is where that check belongs.

    run = AlertBodyInvestigationRun(
        title=_run_title(request.title, alert_body),
        alert_body=alert_body,
        context=(request.context or "").strip() or None,
        status="queued",
        indicator_count=extraction["total"],
        alert_body_hash=body_hash,
        external_ref=external_ref,
        detection_rule_id=(request.detection_rule_id or "").strip()[:120] or None,
        detection_rule_name=(request.detection_rule_name or "").strip()[:512] or None,
        entity_host=entity_host,
        entity_user=entity_user,
        alert_source=alert_source,
        alert_client=alert_client,
        alert_kind=alert_kind,
        event_time=event_time,
        callback_url=callback_url,
        result_json={
            "schema_version": ALERT_REPORT_SCHEMA_VERSION,
            "source": "alert_body",
            "status": "queued",
            "external_ref": external_ref,
            # Said out loud rather than left to be inferred: an analyst reading
            # a report on a 40 MB log needs to know which part of it was read.
            # Recorded so a silenced alert is visible rather than merely absent.
            # An exclusion nobody can see the effect of is how a real detection
            # stays muted for a year.
            "suppressed_by_exclusion": (
                {
                    "exclusion_id": str(suppression.get("id")),
                    "reason": suppression.get("reason"),
                    "match_fields": suppression.get("match_fields"),
                }
                if suppression is not None
                else None
            ),
            "alert_fields": alert_fields,
            "entity": {"host": entity_host, "user": entity_user},
            "alert_source": alert_source,
            "alert_client": alert_client,
            "alert_kind": alert_kind,
            "event_time": event_time.isoformat() if event_time else None,
            "alert_body_chars": len(alert_body),
            "analysed_body_chars": len(analysed_body),
            "alert_body_truncated_for_analysis": body_truncated_for_analysis,
            "extraction": {
                "counts": extraction["counts"],
                "total": extraction["total"],
                "investigable_total": extraction["investigable_total"],
                "excluded_total": excluded_total,
                "truncated": extraction["truncated"],
                "dropped": extraction["dropped"],
                "characters": extraction["characters"],
                "max_indicators": request.max_indicators,
            },
            "indicator_reports": [],
            "reports": [],
        },
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    try:
        task = run_alert_body_investigation_task.delay(
            str(run.id),
            requested_collectors=request.requested_collectors,
            max_indicators=request.max_indicators,
            run_ip_lookup=request.run_ip_lookup,
            run_ai=request.run_ai,
            include_raw_evidence=request.include_raw_evidence,
            reuse_prior_investigations=request.reuse_prior_investigations,
            spawn_investigations=request.spawn_investigations,
        )
        # The dispatch options are stored, not just the task id: if the worker
        # dies mid-run the recovery sweeper has to re-queue this run exactly as
        # it was first sent, and nothing else records what was asked for.
        run.result_json = {
            **(run.result_json or {}),
            "task_id": task.id,
            "dispatch_options": {
                "requested_collectors": request.requested_collectors,
                "max_indicators": request.max_indicators,
                "run_ip_lookup": request.run_ip_lookup,
                "run_ai": request.run_ai,
                "include_raw_evidence": request.include_raw_evidence,
                "reuse_prior_investigations": request.reuse_prior_investigations,
                "spawn_investigations": request.spawn_investigations,
            },
        }
        await db.commit()
    except Exception as exc:
        run.status = "failed"
        run.result_json = {
            **(run.result_json or {}),
            "status": "failed",
            "error": f"Queue dispatch failed: {type(exc).__name__}: {exc}",
        }
        await db.commit()
        logger.exception("Failed to queue alert-body investigation %s", run.id)
        raise HTTPException(status_code=500, detail="Failed to enqueue alert investigation.") from exc

    return _ingest_response(run, deduplicated=False, indicators=extraction["indicators"])


@router.get("")
async def list_alert_investigations(
    db: DBSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
) -> dict[str, Any]:
    # The body is deferred, not selected. _list_item never reads it, and now
    # that any size is accepted a page of 25 rows would otherwise detoast 25
    # arbitrarily large logs to render a list that shows none of them.
    query = select(AlertBodyInvestigationRun).options(defer(AlertBodyInvestigationRun.alert_body))
    count_query = select(func.count(AlertBodyInvestigationRun.id))

    normalized_search = (search or "").strip()
    if normalized_search:
        pattern = f"%{normalized_search}%"
        clause = or_(
            AlertBodyInvestigationRun.title.ilike(pattern),
            AlertBodyInvestigationRun.alert_body.ilike(pattern),
        )
        query = query.where(clause)
        count_query = count_query.where(clause)

    normalized_verdict = (verdict or "").strip().lower()
    if normalized_verdict and normalized_verdict != "all":
        clause = AlertBodyInvestigationRun.overall_verdict == normalized_verdict
        query = query.where(clause)
        count_query = count_query.where(clause)

    rows = (
        (
            await db.execute(
                query.order_by(AlertBodyInvestigationRun.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    total = int((await db.execute(count_query)).scalar() or 0)
    return {
        "items": [_list_item(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{run_id}/case")
async def get_run_case(
    run_id: uuid.UUID,
    db: DBSession,
    hours: int = Query(default=48, ge=1, le=720),
) -> dict[str, Any]:
    """
    The correlated case this alert belongs to, or nothing.

    An analyst reading one alert has no way to know it is the third detection on
    that machine tonight, and that is the fact which changes what they do next.
    """
    case = await case_for_run(db, run_id, hours=hours)
    return {"case": case}


@router.get("/{run_id}/suppression-candidate")
async def get_suppression_candidate(run_id: uuid.UUID, db: DBSession) -> dict[str, Any]:
    """
    The fields this alert could be suppressed on, and a proposed selection.

    Suppression has to be narrower than the rule. Rule 1002 accounts for 68% of
    this deployment's alerts and produced 173 malicious verdicts among them, so
    "mute the rule" is both the obvious action and the wrong one. The proposal
    therefore names the rule *and* the agent *and* the event shape — enough that
    the same rule from another machine is still investigated.

    Nothing is created here. The analyst sees exactly which conditions they are
    about to commit to before anything is silenced.
    """
    run = await db.get(AlertBodyInvestigationRun, run_id)
    if run is None:
        raise HTTPException(404, "Alert investigation not found")

    stored = (run.result_json or {}).get("alert_fields")
    fields = stored if isinstance(stored, dict) and stored else extract_alert_fields(
        run.alert_body or "",
        rule_id=run.detection_rule_id,
        rule_name=run.detection_rule_name,
    )

    available = [
        {
            "field": name,
            "value": fields[name],
            # Severity is the sender's own opinion, and this deployment has
            # alerts arriving High that resolve benign — so it is wrong in at
            # least one direction. Offered, but never proposed on its own.
            "severity_only": name in SEVERITY_ONLY_FIELDS,
        }
        for name in SUPPRESSIBLE_FIELDS
        if fields.get(name)
    ]

    # The proposal: what the alert is, where it came from, and what kind of
    # event it was. Identity before severity, and never severity alone.
    preferred = [f for f in ("rule_id", "agent", "event_id", "event_name") if fields.get(f)]
    if len(preferred) < 2:
        preferred = [f["field"] for f in available if not f["severity_only"]][:3]

    return {
        "run_id": str(run.id),
        "title": run.title,
        "fields": available,
        "proposed": {name: fields[name] for name in preferred if fields.get(name)},
        "entity": {"host": run.entity_host, "user": run.entity_user},
        "already_suppressed": bool((run.result_json or {}).get("suppressed_by_exclusion")),
    }


@router.get("/{run_id}")
async def get_alert_investigation(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    run = await _get_run(db, run_id)
    return await _hydrated_run_payload(db, run)


@router.get("/{run_id}/export")
async def export_alert_investigation(
    db: DBSession,
    run_id: str = FastAPIPath(...),
    format: str = Query(default="reports", pattern="^(reports|report|full|envelope|ndjson)$"),
    # Plain defaults, not Query(...): this handler is called directly in tests and
    # a Query object default would be truthy for every flag.
    download: bool = True,
    pretty: bool = True,
    ndjson: bool = False,
    evidence: bool = True,
) -> Response:
    """
    Export the run's JSON reports for consumption by another platform.

    Both list formats have the same shape — a JSON array of self-describing
    documents, each with its own `report_type`:

        format=reports (default)
            [ {ai_assistant}, {indicator}, {indicator}, … ]
            the lean integration contract

        format=report
            [ {executive_summary}, {indicator + soc_report}, … ]
            report-ready: element 0 folds the run metadata and the AI assistant's
            reading of the alert into one executive summary, and every domain/URL
            indicator carries `soc_report` — the exact data model our own SOC PDF
            renders (executive summary, analyst assessment, evidence matrix,
            findings, IOCs, recommended actions, derived intelligence, signals,
            technical evidence sections, methodology). No raw collector dumps:
            this is what another platform needs to rebuild the same document

        format=full
            [ {executive_summary}, {indicator + full investigation}, … ]
            everything: each investigation's complete analyst report plus its raw
            collector evidence (`evidence=false` leaves the evidence out)

        format=envelope
            the run object with `reports` nested inside — for callers that want
            the metadata as an object rather than as the list's first element

    `ndjson=true` (or format=ndjson) serialises the chosen list one document per
    line; `download=false` serves the same bytes inline.
    """
    run = await _get_run(db, run_id)
    payload = await _hydrated_run_payload(db, run)

    shape = "reports" if format == "ndjson" else format
    as_lines = ndjson or format == "ndjson"

    if shape in ("full", "report"):
        investigation_ids = investigation_ids_in(payload)
        outcomes = await load_outcomes(db, investigation_ids) if investigation_ids else {}
        documents = build_documents(payload, outcomes, shape=shape, include_evidence=evidence)
    else:
        documents = payload.get("reports") or []

    if shape == "envelope":
        body = json.dumps(payload, ensure_ascii=False, default=str, indent=2 if pretty else None)
        media_type, extension = "application/json", "json"
    elif as_lines:
        body = "".join(
            json.dumps(document, ensure_ascii=False, default=str) + "\n" for document in documents
        )
        media_type, extension = "application/x-ndjson", "ndjson"
    else:
        body = json.dumps(documents, ensure_ascii=False, default=str, indent=2 if pretty else None)
        media_type, extension = "application/json", "json"

    filename = f"{_export_slug(run)}-{shape}.{extension}"
    disposition = "attachment" if download else "inline"
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            # Lets a poller decide whether the export is final without a second call.
            "X-Alert-Run-Status": str(run.status or ""),
            "X-Alert-Report-Count": str(len(payload.get("reports") or [])),
            "X-Alert-Schema-Version": str(payload.get("schema_version") or ALERT_REPORT_SCHEMA_VERSION),
        },
    )


@router.post("/{run_id}/cancel")
async def cancel_alert_investigation(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    run = await _get_run(db, run_id)
    if str(run.status or "").lower() not in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="Only queued or running investigations can be cancelled.")

    task_ids: list[str] = []
    known = str((run.result_json or {}).get("task_id") or "").strip()
    if known:
        task_ids.append(known)
    for tid in find_task_ids(task_name="tasks.run_alert_body_investigation", first_arg_value=str(run.id)):
        if tid not in task_ids:
            task_ids.append(tid)
    revoked = revoke_task_ids(task_ids)

    run.status = "cancelled"
    run.completed_at = datetime.now(timezone.utc)
    run.result_json = {
        **(run.result_json or {}),
        "status": "cancelled",
        "error": "Cancelled by user",
    }
    await db.commit()
    return {"run_id": str(run.id), "status": "cancelled", "revoked_task_ids": revoked}


@router.delete("/{run_id}")
async def delete_alert_investigation(
    db: DBSession,
    run_id: str = FastAPIPath(...),
) -> dict[str, Any]:
    """
    Delete an alert-body run and the investigations it started.

    Only investigations this run *spawned* are removed. One it merely reused
    existed before the alert and stays, as does any investigation another alert
    run still references — deleting those would leave that run's reports pointing
    at nothing.
    """
    run = await _get_run(db, run_id)
    payload = _run_payload(run)

    spawned = _spawned_investigation_ids(payload)
    shared = await _investigations_referenced_by_other_runs(db, spawned, exclude_run_id=str(run.id))
    deletable = [i for i in spawned if i not in shared]

    deleted: list[str] = []
    for investigation_id in deletable:
        if await _delete_investigation(db, investigation_id):
            deleted.append(investigation_id)

    await db.delete(run)
    await db.commit()
    logger.info(
        "Deleted alert run %s with %d spawned investigation(s), %d kept (shared)",
        run_id,
        len(deleted),
        len(shared),
    )
    return {
        "run_id": str(run.id),
        "deleted": True,
        "deleted_investigations": deleted,
        "kept_investigations": sorted(shared),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _wait_for_report(
    db: DBSession,
    queued: dict[str, Any],
    *,
    timeout: int,
) -> Any:
    """
    Hold the request until the run finishes, then return its report list.

    The list is exactly what `/export?format=report` serves, so a synchronous
    sender and a polling one consume the same documents. If the run outlasts the
    caller's patience the queued response comes back with 202 instead — the work
    continues, and `links.report` still leads to it.

    A deduplicated delivery waits on (and returns) the run it matched. Usually
    that run is already finished, so the report comes back immediately; if the
    first delivery is still being investigated, the second waits for the same
    answer rather than starting a second copy of the work.
    """
    run_id = str(queued.get("run_id") or "")
    budget = max(MIN_WAIT_TIMEOUT_SECONDS, min(MAX_WAIT_TIMEOUT_SECONDS, int(timeout)))
    deadline = time.monotonic() + budget

    while True:
        db.expire_all()  # the run is written by the worker, not by this session
        run = await _get_run(db, run_id)
        if str(run.status or "").lower() not in ACTIVE_STATUSES:
            break
        if time.monotonic() >= deadline:
            logger.info("Synchronous alert ingest timed out after %ss for run %s", budget, run_id)
            duplicate_note = (
                "This alert was already being investigated when you re-sent it. "
                if queued.get("deduplicated")
                else ""
            )
            return JSONResponse(
                status_code=202,
                content={
                    **queued,
                    "status": run.status,
                    "message": (
                        f"{duplicate_note}Still running after {budget}s — the investigation "
                        f"continues. Fetch links.report when it finishes, or pass a larger "
                        f"wait_timeout."
                    ),
                },
                headers=_ingest_headers(queued),
            )
        await asyncio.sleep(WAIT_POLL_SECONDS)

    payload = await _hydrated_run_payload(db, run)
    investigation_ids = investigation_ids_in(payload)
    outcomes = await load_outcomes(db, investigation_ids) if investigation_ids else {}
    documents = build_documents(payload, outcomes, shape="report")

    # A duplicate gets the report the first delivery produced — that is what the
    # sender asked for by waiting. The fact that it is a re-delivery travels on
    # the executive summary and in the headers, so it is still visible without
    # changing the shape of the list.
    if queued.get("deduplicated") and documents:
        matched = (
            f"alert id {queued.get('external_ref')}"
            if queued.get("deduplicated_by") == "external_ref" and queued.get("external_ref")
            else "an identical alert body"
        )
        documents[0] = {
            **documents[0],
            "ingest": {
                "deduplicated": True,
                "deduplicated_by": queued.get("deduplicated_by"),
                "run_id": run_id,
                "external_ref": queued.get("external_ref"),
                "message": (
                    f"Duplicate delivery — {matched} was already investigated as run "
                    f"{run_id}. Nothing was re-investigated; this is that run's report."
                ),
            },
        }
    return JSONResponse(content=jsonable_encoder(documents), headers=_ingest_headers(queued))


def _ingest_headers(queued: dict[str, Any]) -> dict[str, str]:
    """
    Ingest metadata a sender can read without parsing the body.

    The synchronous response body is the report list itself, so there is no
    envelope to put this in — a SOAR that only wants to know "did you actually
    run anything?" reads the header and skips the JSON.
    """
    headers = {
        "X-Alert-Run-Id": str(queued.get("run_id") or ""),
        "X-Alert-Deduplicated": "true" if queued.get("deduplicated") else "false",
    }
    if queued.get("deduplicated_by"):
        headers["X-Alert-Deduplicated-By"] = str(queued["deduplicated_by"])
    return headers


def _spawned_investigation_ids(payload: dict[str, Any]) -> list[str]:
    """Investigations this run created — reused ones are recorded elsewhere."""
    ids: list[str] = []
    for report in payload.get("indicator_reports") or []:
        if not isinstance(report, dict):
            continue
        investigation = report.get("investigation")
        if not isinstance(investigation, dict):
            continue
        investigation_id = str(investigation.get("investigation_id") or "").strip()
        if investigation_id and investigation_id not in ids:
            ids.append(investigation_id)
    return ids


async def _investigations_referenced_by_other_runs(
    db: DBSession,
    investigation_ids: list[str],
    *,
    exclude_run_id: str,
) -> set[str]:
    """
    Of these investigations, the ones another alert run also points at.

    A run that reused an investigation renders its report from that record, so
    deleting it would gut the other run's export. The stored payload is JSONB with
    the id nested several levels down; a text match is exact enough here (ids are
    UUIDs) and the table holds one row per alert.
    """
    if not investigation_ids:
        return set()
    try:
        rows = (
            await db.execute(
                select(AlertBodyInvestigationRun.id, AlertBodyInvestigationRun.result_json).where(
                    AlertBodyInvestigationRun.id != uuid.UUID(exclude_run_id)
                )
            )
        ).all()
    except Exception as exc:
        # Better to keep an investigation than to delete one another run needs.
        logger.warning("Could not check shared investigations: %s — keeping all", exc)
        return set(investigation_ids)

    shared: set[str] = set()
    for _row_id, result_json in rows:
        blob = json.dumps(result_json or {}, default=str)
        for investigation_id in investigation_ids:
            if investigation_id in blob:
                shared.add(investigation_id)
    return shared


async def _delete_investigation(db: DBSession, investigation_id: str) -> bool:
    """Revoke any running task for the investigation, then delete it."""
    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError:
        return False

    investigation = await db.get(Investigation, parsed_id)
    if investigation is None:
        return False

    task_ids: list[str] = []
    try:
        client = redis_lib.Redis.from_url(get_settings().redis_url)
        tracked = client.get(f"investigation-task:{investigation_id}")
        if tracked:
            task_ids.append(tracked.decode("utf-8", errors="ignore"))
        client.delete(f"investigation-task:{investigation_id}")
    except Exception:
        pass
    for tid in find_task_ids(
        task_name="tasks.run_investigation",
        kwarg_key="investigation_id",
        kwarg_value=investigation_id,
    ):
        if tid not in task_ids:
            task_ids.append(tid)
    if task_ids:
        revoke_task_ids(task_ids)

    await db.delete(investigation)
    return True


def _ingest_response(
    run: AlertBodyInvestigationRun,
    *,
    deduplicated: bool,
    deduplicated_by: str | None = None,
    indicators: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    What the sending platform gets back: the run, and every way to fetch it.

    `links` are ready to use — a caller that only stores `links.report` needs to
    know nothing else about our API. On a duplicate the same shape comes back for
    the run we already have, with `deduplicated_by` saying what matched.
    """
    run_id = str(run.id)
    base = f"/api/alert-investigations/{run_id}"
    payload = run.result_json or {}
    extraction = payload.get("extraction") or {}
    callback = payload.get("callback") or {}
    external_ref = payload.get("external_ref")
    return {
        "run_id": run_id,
        "status": run.status,
        "title": run.title,
        "deduplicated": deduplicated,
        "deduplicated_by": deduplicated_by if deduplicated else None,
        "external_ref": external_ref,
        "indicators": indicators if indicators is not None else (payload.get("indicators") or []),
        "indicator_count": run.indicator_count,
        "investigable_count": extraction.get("investigable_total"),
        "excluded_count": extraction.get("excluded_total") or 0,
        "links": {
            "run": base,
            "report": f"{base}/export?format=report",
            "reports": f"{base}/export?format=reports",
            "full": f"{base}/export?format=full",
            "cancel": f"{base}/cancel",
            "ui": f"/alert-investigations/{run_id}",
        },
        "callback": (
            {"url": run.callback_url, "status": callback.get("status") or "pending"}
            if run.callback_url
            else None
        ),
        "message": _ingest_message(
            run_id,
            deduplicated=deduplicated,
            deduplicated_by=deduplicated_by,
            external_ref=external_ref,
            status=run.status,
            investigable=extraction.get("investigable_total", 0),
            excluded=extraction.get("excluded_total") or 0,
        ),
    }


def _ingest_message(
    run_id: str,
    *,
    deduplicated: bool,
    deduplicated_by: str | None,
    external_ref: str | None,
    status: str | None,
    investigable: Any,
    excluded: int = 0,
) -> str:
    """One sentence the sending platform can log or show as-is."""
    if not deduplicated:
        skipped = f" {excluded} indicator(s) skipped by the exclusion list." if excluded else ""
        return f"Alert investigation queued for {investigable} indicator(s).{skipped}"
    state = "still running" if str(status or "").lower() in ACTIVE_STATUSES else "already investigated"
    if deduplicated_by == "external_ref" and external_ref:
        return (
            f"Duplicate alert: id {external_ref} was {state} as run {run_id} — "
            f"nothing new was queued. Fetch links.report for its result."
        )
    return f"Identical alert body already investigated — returning run {run_id}."


def _validated_alert_body(value: str) -> str:
    alert_body = str(value or "").strip()
    if not alert_body:
        raise HTTPException(status_code=400, detail="Alert body cannot be empty.")
    # No size rejection. A large alert is still an alert, and a sender that gets
    # 413 is left holding an event nothing will ever look at — the platform has
    # no record of it and no way to say what it contained. Size is handled where
    # it actually costs something: the analysis window below, which truncates
    # and says so, and the list query, which no longer reads this column.
    return alert_body


def _run_payload(run: AlertBodyInvestigationRun) -> dict[str, Any]:
    """The run as the API serves it — result JSON plus the row's own metadata."""
    payload = dict(run.result_json or {})
    reports = payload.get("indicator_reports") or []
    if reports and not payload.get("summary"):
        payload["summary"] = summarize_indicator_reports(reports)
    if reports and not payload.get("reports"):
        ai_report = payload.get("ai_report")
        payload["reports"] = ([ai_report] if ai_report else []) + reports
    payload.update(_list_item(run))
    payload["alert_body"] = run.alert_body
    payload["context"] = run.context
    # One implementation of "what the sources found", shared by the run view, the
    # report preview and the export.
    payload["indicator_summary"] = build_indicator_summary(reports)
    return payload


async def _hydrated_run_payload(db: DBSession, run: AlertBodyInvestigationRun) -> dict[str, Any]:
    """
    The run payload, with any report still waiting on a spawned investigation
    refreshed from that investigation's current state.

    A domain investigation can outlive the alert run that started it. Rather than
    serving a stale "investigating" placeholder for ever, every read folds the
    finished verdict back into the run — and persists it, so the next export is
    already complete.
    """
    payload = _run_payload(run)
    reports = payload.get("indicator_reports") or []
    pending = pending_investigation_ids(reports)
    if not pending:
        return payload

    outcomes = await load_outcomes(db, pending)
    if not hydrate_pending_reports(reports, outcomes, schema_version=ALERT_REPORT_SCHEMA_VERSION):
        return payload

    summary = summarize_indicator_reports(reports)
    payload["summary"] = {**(payload.get("summary") or {}), **summary}
    ai_report = payload.get("ai_report")
    payload["indicator_reports"] = reports
    payload["reports"] = ([ai_report] if ai_report else []) + reports

    try:
        stored = dict(run.result_json or {})
        stored["indicator_reports"] = reports
        stored["reports"] = payload["reports"]
        stored["summary"] = payload["summary"]
        run.result_json = stored
        run.overall_verdict = summary.get("overall_verdict") or run.overall_verdict
        run.highest_risk_score = summary.get("highest_risk_score") or run.highest_risk_score
        await db.commit()
    except Exception as exc:  # a failed write must not break the read
        logger.warning("Could not persist hydrated alert run %s: %s", run.id, exc)
        await db.rollback()

    payload.update(_list_item(run))
    payload["alert_body"] = run.alert_body
    payload["context"] = run.context
    return payload


def _export_slug(run: AlertBodyInvestigationRun) -> str:
    """Filename stem: readable title, then the run id so exports stay unique."""
    title = re.sub(r"[^a-z0-9]+", "-", str(run.title or "").lower()).strip("-")
    stem = f"alert-{title[:48]}" if title else "alert"
    return f"{stem}-{run.id}"


async def _attach_prior_investigations(db: DBSession, indicators: list[dict[str, Any]]) -> None:
    """
    Tag each extracted indicator with the platform's most recent investigation of
    that exact value, so the analyst sees what is already known before starting —
    and so the run can reuse it instead of re-collecting.
    """
    if not indicators:
        return
    settings = get_settings()
    history = await find_prior_investigations(db, pairs_from_indicators(indicators))
    annotate_indicators(
        indicators,
        history,
        max_age_days=int(settings.alert_prior_investigation_max_age_days),
    )


async def _apply_exclusions(
    db: DBSession, extraction: dict[str, Any], *, matcher: Any | None = None
) -> int:
    """
    Mark whitelisted indicators as not-to-be-investigated, and re-count.

    Doing this before the run is created is the whole point: an excluded value
    never reaches a collector, so the quota is saved rather than refunded.
    `investigable_total` is what the pipeline reads, so it has to reflect the
    exclusions too.
    """
    indicators = extraction.get("indicators") or []
    if not indicators:
        return 0
    if matcher is None:
        matcher = await load_matcher(db)
    excluded = apply_to_indicators(indicators, matcher)
    if excluded:
        extraction["investigable_total"] = sum(1 for item in indicators if item.get("investigable"))
    return excluded


def _run_title(title: str | None, alert_body: str) -> str:
    explicit = (title or "").strip()
    if explicit:
        return explicit[:255]
    first_line = next((line.strip() for line in alert_body.splitlines() if line.strip()), "")
    return (first_line or "Alert body")[:255]


async def _get_run(db: DBSession, run_id: str) -> AlertBodyInvestigationRun:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid run id format.") from exc
    run = (
        (await db.execute(select(AlertBodyInvestigationRun).where(AlertBodyInvestigationRun.id == parsed_id)))
        .scalars()
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="Alert investigation run not found.")
    return run


def _list_item(row: AlertBodyInvestigationRun) -> dict[str, Any]:
    return {
        "run_id": str(row.id),
        "id": str(row.id),
        "title": row.title,
        "status": row.status,
        "indicator_count": row.indicator_count,
        "overall_verdict": row.overall_verdict,
        "highest_risk_score": row.highest_risk_score,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "error": (row.result_json or {}).get("error"),
        # Deleting this run deletes these too — the list needs it for the confirm.
        "spawned_investigation_count": len(_spawned_investigation_ids(row.result_json or {})),
    }
