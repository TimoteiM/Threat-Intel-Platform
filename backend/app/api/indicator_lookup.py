"""On-demand indicator lookup: one value, every source that can answer it.

**This endpoint does not and will not accept a query body, an index, a field
name, a filter or any other query fragment.** It takes a *value*; the server
decides the question. That is not a simplification to be relaxed later — it is
the property that makes the endpoint safe to expose, and the reason is written
here rather than in a tracker because this is where the request to relax it
will arrive.

Why: the log store holds 2.57 billion documents in its busiest week, every
account in this deployment carries `all_tenants = true`, and the platform
authenticates to the cluster as a superuser. The tenant boundary is a `terms`
filter the server adds, and **that filter has been omitted twice** — once
because a configuration attribute did not exist and `or []` turned "missing"
into "no filter", once in a path that still builds it conditionally. An
endpoint that let a caller shape the body would make the next such defect the
caller's to exploit rather than ours to find.

So free-form querying is **backlog 17**, and it is blocked on an enforcement
test (no body reaches the cluster without a server-side tenant filter the
caller cannot express) plus the per-customer credential work in
`docs/outbound/per-tenant-opensearch-credentials.md`. If you are here because
someone asked for a query box: that is the answer, and this endpoint is the
bounded feature that serves the real need behind it — pivoting from an
indicator into what the platform knows about it.

What it is *not* blocked on, having been parked behind both by mistake:
`EMAIL_OWN_MTA_IDENTITIES`, which gates the "before or after this email"
comparison — an on-demand lookup has no email and therefore no reference time
to establish; and backlog 17 itself, which is about caller-supplied bodies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from app.dependencies import DBSession
from app.services import absence
from app.services import indicator_lookup_service as ind
from app.services import tenant_scope

router = APIRouter(prefix="/api/indicator-lookup", tags=["indicator-lookup"])
logger = logging.getLogger(__name__)


async def _actor(request: Request | None, db: Any) -> dict[str, Any]:
    """Delegates. This carried its own copy of the resolution logic, which made
    it the second implementation of an idea specified the same day — see
    `app/services/actor_attribution.py`."""
    from app.services import actor_attribution

    return await actor_attribution.resolve(request, db)


@router.get("")
async def lookup_indicator(
    db: DBSession,
    value: str = Query(..., min_length=1, max_length=2048),
    tenant_id: str = Query(..., min_length=1),
    days: int = Query(default=7, ge=1, le=120),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """What this platform knows about one indicator, per source.

    Each source returns exactly one of three things: an answer, a named
    absence, or a statement that it cannot be asked about this kind of
    indicator and why. A source is never shown an empty result where the
    third applies — see `indicator_lookup_service`.

    `tenant_id` is required and never inferred. The scope check raises 404
    rather than 403 so the endpoint does not confirm which tenants exist.
    """
    from app.integrations import falcon_client as falcon
    from app.models.database import IndicatorLookup
    from app.services import estate_lookup_service as est
    from app.services import falcon_host_panel_service as panel
    from app.services import integration_credential_service as creds

    identity = getattr(getattr(request, "state", None), "identity", None)
    tenant_scope.assert_can_read(tenant_scope.scope_of(identity), tenant_id)

    detected = ind.detect(value)
    kind = detected["kind"]
    # Per READING, not per kind. A dotted name is validly a domain and a
    # machine name, and picking one makes the page answer a narrower question
    # than it was asked — see `indicator_lookup_service.detect`.
    routing = ind.plan_readings(detected["readings"])
    observable = detected["value"]

    out: dict[str, Any] = {
        "input": str(value)[:2048],
        "detected": detected,
        "tenant_id": tenant_id,
        "window_days": days,
        "sources": {},
    }

    # --- Falcon -----------------------------------------------------------
    falcon_plan = routing["falcon"]
    if falcon_plan["decision"] is not ind.ASK:
        out["sources"]["falcon"] = {
            "reading_used": falcon_plan["reading"],
            "question": "not applicable to this reading of the indicator",
            "answer": ind.refusal(falcon_plan["decision"], raw=kind),
        }
    else:
        out["sources"]["falcon"] = await _ask_falcon(
            kind=falcon_plan["reading"], observable=observable,
            tenant_id=tenant_id, creds=creds, falcon=falcon, panel=panel,
            # A hostname reading that is not the primary one is a guess, and
            # "this host has no EDR coverage" must not be asserted about a
            # domain.
            speculative=falcon_plan["reading"] != detected["readings"][0],
        )
        out["sources"]["falcon"]["reading_used"] = falcon_plan["reading"]
    _carry_other_reading(out["sources"]["falcon"], falcon_plan)

    # --- the estate log store --------------------------------------------
    estate_plan = routing["estate"]
    if estate_plan["decision"] is not ind.ASK:
        section: dict[str, Any] = {
            "reading_used": estate_plan["reading"],
            "question": "not applicable to this reading of the indicator",
            "answer": ind.refusal(estate_plan["decision"], raw=kind),
        }
        if kind == ind.URL:
            # The narrower claim, offered and labelled rather than silently
            # substituted for the question that was asked.
            fallback = ind.url_fallback(observable)
            if fallback:
                section["narrower_claim"] = fallback
                section["narrower_answer"] = await asyncio.to_thread(
                    _estate, fallback["asked_instead"], ind.DOMAIN, tenant_id, days, est
                )
        out["sources"]["estate"] = section
    else:
        out["sources"]["estate"] = {
            "reading_used": estate_plan["reading"],
            "question": (
                "endpoint DNS queries for this name"
                if estate_plan["reading"] == ind.DOMAIN else
                "images with this hash that were EXECUTED (Sysmon event 1)"
                if estate_plan["reading"] in (ind.SHA256, ind.SHA1, ind.MD5) else
                "perimeter traffic to this address"
            ),
            "answer": await asyncio.to_thread(
                _estate, observable, estate_plan["reading"], tenant_id, days, est
            ),
        }
    _carry_other_reading(out["sources"]["estate"], estate_plan)

    # --- the record, before the attribution schema exists -----------------
    try:
        db.add(IndicatorLookup(
            **await _actor(request, db),
            tenant_id=tenant_id, value=str(value)[:2048],
            kind=kind,
            sources_asked={
                s: {"asked": v["decision"] is ind.ASK, "reading": v["reading"]}
                for s, v in routing.items()
            },
        ))
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        # The answer is still returned. A lookup that fails because its audit
        # row failed would make the audit a denial-of-service on the feature,
        # and the failure is reported rather than swallowed.
        await db.rollback()
        logger.error("indicator lookup not recorded: %s", type(exc).__name__)
        out["recorded"] = absence.absent(
            absence.CHECK_FAILED,
            f"This lookup was answered but not recorded against its actor "
            f"({type(exc).__name__}). The answer is unaffected; the audit "
            f"trail has a gap at this timestamp.",
        ).as_json()
    else:
        out["recorded"] = True
    return out


def _carry_other_reading(section: dict[str, Any], plan: dict[str, Any]) -> None:
    """State the primary reading's refusal even when a secondary was asked.

    Without this the ambiguity fix trades one collapse for another: `aka.ms`
    asked of Falcon as a *hostname* returns a true "no such device", and the
    sentence that matters — Falcon has no field that holds a domain — would
    vanish. Someone reading a hostname miss as "the EDR has nothing on this
    domain" is the false-exculpation shape again, one reading over.
    """
    other = plan.get("also_refused_for")
    if not other:
        return
    section["not_answered_for"] = {
        "reading": other["reading"],
        "answer": ind.refusal(other["decision"], raw=other["reading"]),
    }


async def _ask_falcon(*, kind, observable, tenant_id, creds, falcon, panel,
                      speculative: bool = False) -> dict[str, Any]:
    """Falcon's answer, or why it has none. Negatives carry the control."""
    question = (
        f"Falcon alerts whose {kind} matches this value"
        if kind in ind.HASH_LENGTHS.values() else
        "whether Falcon manages a host with this name"
    )
    try:
        opened = await asyncio.to_thread(
            creds.open_for_tenant_sync, tenant_id, "falcon")
    except creds.IntegrationNotConfigured:
        return {"question": question, "answer": absence.absent(
            absence.CHECK_FAILED,
            "CrowdStrike Falcon is not configured for this customer, so no "
            "request was made. An unconfigured EDR is an absence, not a clean "
            "answer.", raw="not_configured").as_json()}
    except Exception as exc:  # noqa: BLE001
        return {"question": question, "answer": absence.absent(
            absence.CHECK_FAILED,
            f"The stored Falcon credential could not be opened "
            f"({type(exc).__name__}). No request was made.").as_json()}

    if kind == ind.HOSTNAME:
        try:
            raw = await asyncio.to_thread(
                falcon.lookup_host, hostname=observable,
                client_id=opened.client_id, client_secret=opened.client_secret,
                config=opened.config, days=panel.DETECTION_DAYS,
                row_cap=panel.DETECTION_ROW_CAP)
        except Exception as exc:  # noqa: BLE001
            return {"question": question, "answer": absence.absent(
                absence.CHECK_FAILED,
                f"The Falcon query did not complete ({type(exc).__name__}: "
                f"{falcon._redact(exc)}), so whether this host is managed is "
                f"unknown rather than no.").as_json()}
        return {
            "question": question,
            "answer": panel.panel(
                hostname=raw["hostname"], device=raw["device"],
                detections=raw["detections"], control=raw["control"],
                truncated_at=raw.get("truncated_at"),
                population=raw.get("detections_total"),
                incomplete_reason=raw.get("detections_incomplete_reason"),
                superseded=raw.get("superseded_devices"),
                retention=raw.get("retention"),
                enrolment_floor=raw.get("enrolment_floor"),
                speculative_host=speculative,
                requested_days=panel.DETECTION_DAYS),
        }

    # A hash. The field control gates the negative, exactly as on the alert
    # panel: the Alerts API answers an unknown field name with 200 and zero
    # rows, so a nil result is only a negative while the control passes.
    try:
        found = await asyncio.to_thread(
            falcon.lookup, observable=observable, observable_type="hash",
            client_id=opened.client_id, client_secret=opened.client_secret,
            config=opened.config)
    except falcon.FalconFieldUnverified as exc:
        return {"question": question, "answer": absence.absent(
            absence.CHECK_FAILED, str(exc)).as_json()}
    except Exception as exc:  # noqa: BLE001
        return {"question": question, "answer": absence.absent(
            absence.CHECK_FAILED,
            f"The Falcon query did not complete ({type(exc).__name__}: "
            f"{falcon._redact(exc)}).").as_json()}

    detections = found.get("detections")
    complete = found.get("detections_complete")
    answer: dict[str, Any] = {
        "detections": detections,
        "detection_count": len(detections) if isinstance(detections, list) else None,
        # The population these came from. `detection_count` is the number of
        # records READ; this is how many there are, and when they differ the
        # count is a floor.
        "detection_total": found.get("detections_total"),
        "detections_complete": complete,
        "field": found.get("detections_field"),
        "notes": found.get("notes") or [],
        # No negative without its warrant. Two things have to hold: the field
        # must be confirmed to filter, and the read must have covered the
        # population. A complete read of a verified field is the only state in
        # which a zero here means "the EDR has nothing".
        "negative_is_interpretable": bool(found.get("detections_field")) and complete is True,
    }
    if complete is False:
        answer["count_is_floor"] = absence.absent(
            absence.LOWER_BOUND,
            f"{len(detections or [])} detections were read of "
            f"{found.get('detections_total')} that exist, so this is a floor "
            f"and anything not found in them may be in the rest: "
            f"{found.get('detections_incomplete_reason')}",
            raw=str(len(detections or [])),
        ).as_json()
    return {"question": question, "answer": answer}


def _estate(observable: str, kind: str, tenant_id: str, days: int, est) -> dict[str, Any]:
    """The estate's answer. No reference time, so no before/after comparison.

    A hash takes its own path and its own window. The DNS and perimeter
    questions are a `term` on a keyword field; a hash is a leading wildcard
    against a composite string, so its cost grows with the window in a way
    theirs does not — hence a separate bound rather than a shared one.

    `reference_time` is deliberately not passed: an on-demand lookup has no
    email, so there is no anchor to name, and `lookup()` refuses an unnamed
    one. The raw answer — hosts, documents, first-seen, the observation floor —
    needs none of it.
    """
    client = est.estate_client_for(tenant_id)
    if kind in (ind.SHA256, ind.SHA1, ind.MD5):
        # Not clamped. A window past the measured ceiling comes back as
        # `cost_not_established` with the timings, because silently narrowing
        # the window someone asked for is a different answer presented as
        # theirs.
        return est.hash_lookup(
            observable, tenant_id=tenant_id, days=int(days), client=client)
    return est.lookup(
        observable,
        kind="domain" if kind == ind.DOMAIN else "ip",
        tenant_id=tenant_id, days=days, client=client,
    )
