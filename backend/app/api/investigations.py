"""
Investigation API endpoints.

POST /api/investigations                          → Start new investigation
POST /api/investigations/upload-file              → Upload file sample for investigation
GET  /api/investigations                          → List all investigations
GET  /api/investigations/{id}                     → Get investigation details
DELETE /api/investigations/{id}                  → Delete an investigation
GET  /api/investigations/{id}/evidence            → Get raw evidence
GET  /api/investigations/{id}/report              → Get analyst report
POST /api/investigations/{id}/rerun-collector     → Re-run a single collector and merge result
"""

from __future__ import annotations

import json
import base64
import threading
from datetime import datetime, timezone
from typing import Any
import uuid
from urllib.parse import urlparse

import redis as redis_lib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.dependencies import DBSession, Storage
from app.models.database import Artifact, Investigation, Evidence
from app.models.schemas import InvestigationCreate
from app.services.evidence_diff_service import diff_evidence
from app.services.investigation_service import InvestigationService
from app.services.investigation_intelligence import build_investigation_intelligence
from app.services.investigation_case_story_service import (
    CaseQuestionRequest,
    InvestigationCaseStoryService,
    compact_case_context,
)
from app.tasks.cancellation import find_task_ids, revoke_task_ids
from app.services.hybrid_analysis_service import evict_anyrun_cache
from app.collectors.registry import get_collector, get_collectors_for_type
from app.services.proxy_profiles import configured_proxy_profiles

router = APIRouter(prefix="/api/investigations", tags=["investigations"])
settings = get_settings()


@router.post("")
async def create_investigation(request: InvestigationCreate, session: DBSession):
    """Start a new domain investigation."""
    service = InvestigationService(session)
    try:
        result = await service.create(request)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
async def list_investigations(
    session: DBSession,
    limit: int = 10,
    offset: int = 0,
    state: str | None = None,
    search: str | None = None,
    observable_type: str | None = None,
    classification: str | None = None,
    dedupe: bool = False,
):
    """List investigations with pagination and optional search/filter."""
    service = InvestigationService(session)
    investigations = await service.list_all(
        limit=limit, offset=offset, state=state, search=search,
        observable_type=observable_type,
        classification=classification,
        dedupe=dedupe,
    )
    total = await service.count(
        state=state,
        search=search,
        observable_type=observable_type,
        classification=classification,
        dedupe=dedupe,
    )
    return {
        "items": [
            {
                "id": str(inv.id),
                "domain": inv.domain,
                "observable_type": getattr(inv, "observable_type", "domain"),
                "state": inv.state,
                "classification": inv.classification,
                "risk_score": inv.risk_score,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
            }
            for inv in investigations
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/proxy-countries")
async def list_proxy_countries():
    """Return configured outbound proxy countries without exposing proxy URLs."""
    safe_keys = {"country", "label", "configured", "local_proxy", "anyrun_residential"}
    return {
        "items": [
            {key: str(item.get(key) or "") for key in safe_keys if key in item}
            for item in configured_proxy_profiles()
            if isinstance(item, dict)
        ],
    }


@router.get("/{investigation_id}")
async def get_investigation(investigation_id: str, session: DBSession):
    """Get investigation metadata."""
    service = InvestigationService(session)
    inv = await service.get(investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return {
        "id": str(inv.id),
        "domain": inv.domain,
        "observable_type": getattr(inv, "observable_type", "domain"),
        "state": inv.state,
        "classification": inv.classification,
        "confidence": inv.confidence,
        "risk_score": inv.risk_score,
        "recommended_action": inv.recommended_action,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "concluded_at": inv.concluded_at.isoformat() if inv.concluded_at else None,
    }


@router.delete("/{investigation_id}", status_code=204)
async def delete_investigation(investigation_id: str, session: DBSession):
    """Delete an investigation and its dependent evidence/report records."""
    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid investigation id format.") from exc

    inv = (
        (
            await session.execute(
                select(Investigation).where(Investigation.id == parsed_id)
            )
        )
        .scalars()
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    task_ids: list[str] = []
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        tracked = r.get(f"investigation-task:{investigation_id}")
        if tracked:
            task_ids.append(tracked.decode("utf-8", errors="ignore"))
        r.delete(f"investigation-task:{investigation_id}")
    except Exception:
        pass

    discovered = find_task_ids(
        task_name="tasks.run_investigation",
        kwarg_key="investigation_id",
        kwarg_value=investigation_id,
    )
    for tid in discovered:
        if tid not in task_ids:
            task_ids.append(tid)
    revoke_task_ids(task_ids)

    await session.delete(inv)
    await session.commit()
    return None


@router.get("/{investigation_id}/evidence")
async def get_evidence(investigation_id: str, session: DBSession):
    """Get collected evidence JSON."""
    service = InvestigationService(session)
    evidence = await service.get_evidence(investigation_id)
    if not evidence:
        raise HTTPException(404, "Evidence not yet collected")
    return evidence


@router.get("/{investigation_id}/report")
async def get_report(investigation_id: str, session: DBSession):
    """Get analyst report."""
    service = InvestigationService(session)
    report = await service.get_report(investigation_id)
    if not report:
        raise HTTPException(404, "Report not yet generated")
    return report


@router.get("/{investigation_id}/intelligence")
async def get_intelligence(investigation_id: str, session: DBSession):
    """Get derived SOC intelligence for timeline, graph, IOC quality, and reporting."""
    service = InvestigationService(session)
    detail = await service.get(investigation_id)
    if not detail:
        raise HTTPException(404, "Investigation not found")

    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}
    detail_dict = {
        "id": str(detail.id),
        "domain": detail.domain,
        "observable_type": getattr(detail, "observable_type", "domain"),
        "state": detail.state,
        "classification": detail.classification,
        "confidence": detail.confidence,
        "risk_score": detail.risk_score,
        "recommended_action": detail.recommended_action,
        "client_domain": detail.client_domain,
        "created_at": detail.created_at.isoformat() if detail.created_at else None,
        "updated_at": detail.updated_at.isoformat() if detail.updated_at else None,
        "concluded_at": detail.concluded_at.isoformat() if detail.concluded_at else None,
    }
    intelligence = build_investigation_intelligence(evidence=evidence, report=report, detail=detail_dict)
    intelligence["similar_investigations"] = await _build_similar_investigations(
        session=session,
        current=detail,
        current_evidence=evidence,
        current_iocs=(intelligence.get("ioc_quality") or {}).get("items") or [],
    )
    intelligence["rescan_diff"] = await _build_rescan_diff(
        session=session,
        current=detail,
        current_evidence=evidence,
    )
    intelligence["summary"]["similar_investigations"] = len(intelligence["similar_investigations"].get("items") or [])
    intelligence["summary"]["rescan_changes"] = len((intelligence["rescan_diff"].get("changes") or {}))
    return intelligence


@router.post("/{investigation_id}/case-story")
async def generate_case_story(investigation_id: str, session: DBSession, storage: Storage):
    """Generate one evidence-grounded SOC narrative, timeline, correlations and handoff."""
    cache_key = f"case-story:v3:{investigation_id}"
    try:
        cached = redis_lib.Redis.from_url(settings.redis_url).get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass
    detail, evidence, report, intelligence = await _load_case_material(investigation_id, session)
    if isinstance(report.get("ai_case_story"), dict):
        return report["ai_case_story"]
    context = compact_case_context(detail=detail, evidence=evidence, report=report, intelligence=intelligence)
    images = await _load_case_images(investigation_id, evidence, session, storage)
    try:
        story = await InvestigationCaseStoryService().generate(context=context, images=images)
        payload = story.model_dump(mode="json")
        try:
            redis_lib.Redis.from_url(settings.redis_url).setex(cache_key, 604800, json.dumps(payload))
        except Exception:
            pass
        return payload
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/{investigation_id}/case-story/ask")
async def ask_case_story(investigation_id: str, request: CaseQuestionRequest, session: DBSession, storage: Storage):
    """Answer a free-form analyst question strictly from this investigation's evidence."""
    detail, evidence, report, intelligence = await _load_case_material(investigation_id, session)
    context = compact_case_context(detail=detail, evidence=evidence, report=report, intelligence=intelligence)
    images = await _load_case_images(investigation_id, evidence, session, storage)
    try:
        return await InvestigationCaseStoryService().answer(context=context, question=request.question, images=images)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc


async def _load_case_material(investigation_id: str, session: DBSession):
    service = InvestigationService(session)
    inv = await service.get(investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    evidence = await service.get_evidence(investigation_id) or {}
    report = await service.get_report(investigation_id) or {}
    detail = {
        "id": str(inv.id), "domain": inv.domain, "observable_type": getattr(inv, "observable_type", "domain"),
        "state": inv.state, "classification": inv.classification, "confidence": inv.confidence,
        "risk_score": inv.risk_score, "recommended_action": inv.recommended_action,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "concluded_at": inv.concluded_at.isoformat() if inv.concluded_at else None,
    }
    intelligence = build_investigation_intelligence(evidence=evidence, report=report, detail=detail)
    intelligence["similar_investigations"] = await _build_similar_investigations(
        session=session, current=inv, current_evidence=evidence,
        current_iocs=(intelligence.get("ioc_quality") or {}).get("items") or [],
    )
    intelligence["rescan_diff"] = await _build_rescan_diff(session=session, current=inv, current_evidence=evidence)
    return detail, evidence, report, intelligence


async def _load_case_images(investigation_id: str, evidence: dict[str, Any], session: DBSession, storage: Storage):
    """Resolve locally stored screenshot evidence to private data URLs for model vision."""
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        return []
    candidates: list[tuple[str, str]] = []
    def walk(value: Any, path: str = "evidence") -> None:
        if len(candidates) >= 8:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if isinstance(child, str) and "artifact_id" in key.lower():
                    candidates.append((child_path, child))
                else:
                    walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value[:30]):
                walk(child, f"{path}[{index}]")
    walk(evidence)
    images: list[tuple[str, str]] = []
    for ref, artifact_id in candidates:
        try:
            art_uuid = uuid.UUID(artifact_id)
        except ValueError:
            continue
        artifact = (await session.execute(select(Artifact).where(Artifact.id == art_uuid, Artifact.investigation_id == inv_uuid))).scalar_one_or_none()
        if not artifact:
            continue
        content_type = (artifact.content_type or "").lower()
        if not content_type.startswith("image/") and not artifact.artifact_name.lower().endswith(("png", "jpg", "jpeg")):
            continue
        try:
            data = await storage.load(artifact.storage_path)
        except FileNotFoundError:
            continue
        mime = content_type if content_type.startswith("image/") else "image/png"
        images.append((ref, f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"))
        if len(images) >= 3:
            break
    return images


async def _build_rescan_diff(
    *,
    session: DBSession,
    current: Investigation,
    current_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Compare this run with the previous completed run for the same observable."""
    current_id = current.id
    result = await session.execute(
        select(Investigation, Evidence)
        .join(Evidence, Evidence.investigation_id == Investigation.id)
        .where(
            Investigation.id != current_id,
            Investigation.domain == current.domain,
            Investigation.observable_type == current.observable_type,
            Investigation.state == "concluded",
        )
        .order_by(desc(Investigation.created_at))
        .limit(1)
    )
    row = result.first()
    if not row:
        return {
            "available": False,
            "previous_investigation": None,
            "changes": {},
            "summary": "No previous concluded investigation exists for this observable.",
        }

    previous, previous_evidence = row
    previous_json = previous_evidence.evidence_json if previous_evidence else {}
    changes = diff_evidence(previous_json or {}, current_evidence or {})
    return {
        "available": True,
        "previous_investigation": {
            "id": str(previous.id),
            "domain": previous.domain,
            "classification": previous.classification,
            "risk_score": previous.risk_score,
            "created_at": previous.created_at.isoformat() if previous.created_at else None,
            "concluded_at": previous.concluded_at.isoformat() if previous.concluded_at else None,
        },
        "changes": changes,
        "summary": _summarize_rescan_changes(changes),
    }


async def _build_similar_investigations(
    *,
    session: DBSession,
    current: Investigation,
    current_evidence: dict[str, Any],
    current_iocs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Find nearby cases by shared infrastructure, IOCs, OpenCTI context, and verdict profile."""
    current_fp = _case_fingerprint(current, current_evidence, current_iocs)
    result = await session.execute(
        select(Investigation, Evidence)
        .join(Evidence, Evidence.investigation_id == Investigation.id)
        .where(Investigation.id != current.id)
        .order_by(desc(Investigation.created_at))
        .limit(120)
    )
    candidates: list[dict[str, Any]] = []
    for candidate, evidence_row in result.all():
        candidate_evidence = evidence_row.evidence_json if evidence_row else {}
        candidate_fp = _case_fingerprint(candidate, candidate_evidence or {}, [])
        score, reasons, overlap = _score_case_similarity(current_fp, candidate_fp)
        if score < 20:
            continue
        candidates.append(
            {
                "id": str(candidate.id),
                "domain": candidate.domain,
                "observable_type": candidate.observable_type,
                "classification": candidate.classification,
                "risk_score": candidate.risk_score,
                "created_at": candidate.created_at.isoformat() if candidate.created_at else None,
                "concluded_at": candidate.concluded_at.isoformat() if candidate.concluded_at else None,
                "similarity_score": score,
                "reasons": reasons[:5],
                "overlap": overlap,
            }
        )

    candidates.sort(key=lambda row: (-row["similarity_score"], row.get("created_at") or ""))
    top = candidates[:12]
    return {
        "items": top,
        "summary": {
            "total_candidates": len(candidates),
            "strong_matches": sum(1 for row in candidates if row["similarity_score"] >= 65),
            "shared_ioc_matches": sum(1 for row in candidates if row["overlap"].get("iocs")),
            "shared_infrastructure_matches": sum(1 for row in candidates if row["overlap"].get("infrastructure")),
        },
    }


def _case_fingerprint(inv: Investigation, evidence: dict[str, Any], iocs: list[dict[str, Any]]) -> dict[str, set[str] | str | int | None]:
    dns = evidence.get("dns") if isinstance(evidence.get("dns"), dict) else {}
    hosting = evidence.get("hosting") if isinstance(evidence.get("hosting"), dict) else {}
    http = evidence.get("http") if isinstance(evidence.get("http"), dict) else {}
    opencti = evidence.get("opencti") if isinstance(evidence.get("opencti"), dict) else {}
    threat_feeds = evidence.get("threat_feeds") if isinstance(evidence.get("threat_feeds"), dict) else {}

    ioc_values = {
        str(row.get("value") or "").strip().lower()
        for row in iocs
        if isinstance(row, dict) and row.get("value")
    }
    for ip in (dns.get("a") or []) + (dns.get("aaaa") or []):
        if ip:
            ioc_values.add(str(ip).strip().lower())
    for row in threat_feeds.get("threatfox_matches") or []:
        if isinstance(row, dict) and row.get("ioc_value"):
            ioc_values.add(str(row["ioc_value"]).strip().lower())

    final_url = str(http.get("final_url") or "").strip().lower()
    redirect_hosts = set()
    for row in (http.get("redirect_chain") or []) + (http.get("redirects") or []):
        if isinstance(row, dict):
            host = _url_host(row.get("url") or row.get("location"))
            if host:
                redirect_hosts.add(host)
    if final_url:
        ioc_values.add(final_url)

    infra = {
        str(value).strip().lower()
        for value in [
            hosting.get("ip"),
            f"as{hosting.get('asn')}" if hosting.get("asn") else "",
            hosting.get("asn_org"),
            *(dns.get("ns") or []),
            *(dns.get("mx") or []),
            *redirect_hosts,
            _url_host(final_url),
        ]
        if value
    }
    cti = {
        str(value).strip().lower()
        for value in [
            *(opencti.get("campaigns") or []),
            *(opencti.get("intrusion_sets") or []),
            *(row.get("name") for row in (opencti.get("malware_families") or []) if isinstance(row, dict)),
            *(row.get("name") for row in (opencti.get("reports") or []) if isinstance(row, dict)),
        ]
        if value
    }
    return {
        "observable": str(inv.domain or "").strip().lower(),
        "observable_type": inv.observable_type,
        "classification": inv.classification,
        "risk_score": inv.risk_score,
        "iocs": ioc_values,
        "infrastructure": infra,
        "cti": cti,
    }


def _score_case_similarity(current: dict[str, Any], candidate: dict[str, Any]) -> tuple[int, list[str], dict[str, list[str]]]:
    current_iocs = current.get("iocs") if isinstance(current.get("iocs"), set) else set()
    candidate_iocs = candidate.get("iocs") if isinstance(candidate.get("iocs"), set) else set()
    current_infra = current.get("infrastructure") if isinstance(current.get("infrastructure"), set) else set()
    candidate_infra = candidate.get("infrastructure") if isinstance(candidate.get("infrastructure"), set) else set()
    current_cti = current.get("cti") if isinstance(current.get("cti"), set) else set()
    candidate_cti = candidate.get("cti") if isinstance(candidate.get("cti"), set) else set()

    ioc_overlap = sorted((current_iocs & candidate_iocs) - {""})
    infra_overlap = sorted((current_infra & candidate_infra) - {""})
    cti_overlap = sorted((current_cti & candidate_cti) - {""})
    score = min(45, len(ioc_overlap) * 16) + min(28, len(infra_overlap) * 10) + min(22, len(cti_overlap) * 12)
    reasons: list[str] = []
    if ioc_overlap:
        reasons.append(f"Shares {len(ioc_overlap)} IOC(s)")
    if infra_overlap:
        reasons.append(f"Shares {len(infra_overlap)} infrastructure artifact(s)")
    if cti_overlap:
        reasons.append(f"Shares {len(cti_overlap)} CTI context item(s)")
    if current.get("classification") and current.get("classification") == candidate.get("classification"):
        score += 6
        reasons.append(f"Same verdict: {current.get('classification')}")
    if current.get("observable_type") == candidate.get("observable_type"):
        score += 4
    current_score = current.get("risk_score")
    candidate_score = candidate.get("risk_score")
    if isinstance(current_score, int) and isinstance(candidate_score, int) and abs(current_score - candidate_score) <= 12:
        score += 5
        reasons.append("Similar risk score band")
    return min(100, score), reasons, {
        "iocs": ioc_overlap[:10],
        "infrastructure": infra_overlap[:10],
        "cti": cti_overlap[:10],
    }


def _summarize_rescan_changes(changes: dict[str, Any]) -> str:
    if not changes:
        return "No meaningful evidence changes were detected versus the previous run."
    labels = {
        "risk_score": "risk score changed",
        "dns_ips": "DNS answers changed",
        "hosting_ip": "hosting IP changed",
        "vt_malicious": "VirusTotal malicious count changed",
        "threatfox_added": "new ThreatFox matches appeared",
        "whois_registrar": "registrar changed",
        "whois_org": "registrant organization changed",
        "whois_country": "registrant country changed",
    }
    return "; ".join(labels.get(key, key.replace("_", " ")) for key in changes.keys())


def _url_host(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


@router.post("/upload-file")
async def upload_file_investigation(
    session: DBSession,
    file: UploadFile = File(...),
    context: str = Form(default=""),
    use_residential_proxy: bool = Form(default=False),
    proxy_country: str = Form(default=""),
):
    """
    Upload a file sample for fast hash-based analysis.

    Computes SHA-256 and investigates as observable_type='hash' so VT can do a
    direct hash lookup (faster than file submission). The uploaded binary is
    still stored as an artifact for traceability.
    """
    import hashlib
    from app.models.schemas import InvestigationCreate

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(400, "Uploaded file is empty")

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    filename = file.filename or "unknown"

    # Create the investigation via the service (hash-first for speed)
    request = InvestigationCreate(
        domain=sha256,
        observable_type="hash",
        context=context or None,
        network_profile={
            "use_residential_proxy": use_residential_proxy,
            "proxy_country": proxy_country.strip() or None,
        } if (use_residential_proxy or proxy_country.strip()) else None,
        requested_collectors=["vt", "hybrid_analysis"],
    )

    service = InvestigationService(session)
    try:
        result = await service.create_file(request, file_bytes, sha256, filename)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{investigation_id}/cancel")
async def cancel_investigation(investigation_id: str, session: DBSession):
    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid investigation id format.") from exc

    inv = (
        (
            await session.execute(
                select(Investigation).where(Investigation.id == parsed_id)
            )
        )
        .scalars()
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    state = str(inv.state or "").lower()
    if state not in {"created", "gathering", "evaluating"}:
        raise HTTPException(status_code=409, detail="Only queued or running investigations can be cancelled.")

    task_ids: list[str] = []
    try:
        r = redis_lib.Redis.from_url(settings.redis_url)
        tracked = r.get(f"investigation-task:{investigation_id}")
        if tracked:
            task_ids.append(tracked.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    discovered = find_task_ids(
        task_name="tasks.run_investigation",
        kwarg_key="investigation_id",
        kwarg_value=investigation_id,
    )
    for tid in discovered:
        if tid not in task_ids:
            task_ids.append(tid)
    revoked = revoke_task_ids(task_ids)

    inv.state = "cancelled"
    inv.updated_at = datetime.now(timezone.utc)
    inv.concluded_at = datetime.now(timezone.utc)
    await session.commit()

    return {
        "investigation_id": investigation_id,
        "status": "cancelled",
        "revoked_task_ids": revoked,
    }


class RerunCollectorRequest(BaseModel):
    collector: str


@router.post("/{investigation_id}/rerun-collector")
async def rerun_collector(
    investigation_id: str,
    body: RerunCollectorRequest,
    session: DBSession,
):
    """Re-run a single collector for an existing investigation and merge the result."""
    import asyncio

    collector_name = body.collector.strip().lower()

    try:
        parsed_id = uuid.UUID(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid investigation id format.") from exc

    collector_cls = get_collector(collector_name)
    if not collector_cls:
        raise HTTPException(status_code=400, detail=f"Unknown collector: {collector_name!r}")

    result = await session.execute(
        select(Investigation).where(Investigation.id == parsed_id)
    )
    inv = result.scalars().first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    state = str(inv.state or "").lower()
    if state not in {"concluded", "failed"}:
        raise HTTPException(
            status_code=409,
            detail="Can only re-run collectors on concluded or failed investigations.",
        )

    observable_type = str(inv.observable_type or "domain").strip()
    if observable_type not in collector_cls.supported_types:
        raise HTTPException(
            status_code=422,
            detail=f"Collector {collector_name!r} does not support observable type {observable_type!r}.",
        )

    domain = str(inv.domain or "").strip()

    # AnyRun (hybrid_analysis) needs both cache layers evicted before re-submission
    if collector_name == "hybrid_analysis":
        indicator_type = "hash" if observable_type in {"hash", "file"} else "url"
        indicator = domain if observable_type in {"hash", "file"} else (
            f"https://{domain}" if observable_type == "domain" else domain
        )
        await asyncio.get_event_loop().run_in_executor(
            None, evict_anyrun_cache, indicator, indicator_type
        )

    def _run_in_background():
        try:
            collector = collector_cls(
                domain=domain,
                investigation_id=investigation_id,
                observable_type=observable_type,
                timeout=settings.collector_timeout,
            )
            evidence, meta, _ = collector.run()
            result_dict: dict[str, Any] = {
                "collector": collector_name,
                "status": meta.status.value,
                "evidence": evidence.model_dump(mode="json"),
                "meta": meta.model_dump(mode="json"),
            }
        except Exception as exc:
            result_dict = {
                "collector": collector_name,
                "status": "failed",
                "evidence": {},
                "meta": {"error": str(exc)},
            }

        # Merge result into evidence_json
        try:
            inv_id = uuid.UUID(investigation_id)
            with Session(sync_engine) as db:
                inv_row = db.get(Investigation, inv_id)
                ev_row = db.execute(
                    select(Evidence).where(Evidence.investigation_id == inv_id)
                ).scalar_one_or_none()
                if ev_row is not None:
                    existing: dict = {}
                    if ev_row.evidence_json:
                        existing = (
                            json.loads(ev_row.evidence_json)
                            if isinstance(ev_row.evidence_json, str)
                            else dict(ev_row.evidence_json)
                        )
                    existing[collector_name] = result_dict["evidence"]
                    ev_row.evidence_json = existing
                    if inv_row:
                        inv_row.updated_at = datetime.now(timezone.utc)
                    db.commit()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "rerun-collector: failed to persist %s result: %s", collector_name, exc
            )
            return

        try:
            from app.tasks.analysis_task import recompute_report_for_existing_investigation

            recomputed = recompute_report_for_existing_investigation(
                investigation_id,
                reason=f"collector_rerun:{collector_name}",
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "rerun-collector: failed to recompute report after %s result: %s",
                collector_name,
                exc,
            )
            recomputed = None

        # Notify frontend via SSE
        try:
            r = redis_lib.Redis.from_url(settings.redis_url)
            r.publish(
                f"investigation:{investigation_id}",
                json.dumps({
                    "type": "evidence_updated",
                    "investigation_id": investigation_id,
                    "collector": collector_name,
                    "report_recomputed": bool(recomputed),
                    "message": (
                        f"{collector_name} re-run complete — evidence and report updated"
                        if recomputed else
                        f"{collector_name} re-run complete — evidence updated; report recompute failed"
                    ),
                }),
            )
        except Exception:
            pass

    t = threading.Thread(
        target=_run_in_background,
        daemon=True,
        name=f"rerun-{collector_name}-{investigation_id[:8]}",
    )
    t.start()

    return {"investigation_id": investigation_id, "collector": collector_name, "status": "rerun_started"}
