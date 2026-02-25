"""
Analysis Task — aggregates collector results and runs the Claude analyst.

This task is the callback of the collector chord:
  chord(collector_tasks)(run_analysis.s(...))

It:
1. Merges all collector evidence into a single object
2. Generates signals and detects data gaps
3. Calls the Claude analyst (with follow-up iterations if needed)
4. Persists the report to the database
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from celery.exceptions import SoftTimeLimitExceeded

from app.tasks.celery_app import celery_app
from app.collectors.signals import generate_signals, detect_data_gaps
from app.models.enums import InvestigationState

logger = logging.getLogger(__name__)

# Map collector names to evidence field names when they differ
COLLECTOR_FIELD_MAP = {
    "asn": "hosting",
}


@celery_app.task(
    bind=True,
    name="tasks.run_analysis",
    time_limit=300,       # Hard kill after 5 min (Playwright steps can be slow)
    soft_time_limit=270,  # Soft limit at 4.5 min — gives time to persist partial results
)
def run_analysis(
    self,
    collector_results: list[dict],
    domain: str,
    investigation_id: str,
    context: str | None = None,
    client_domain: str | None = None,
    investigated_url: str | None = None,
    client_url: str | None = None,
    external_context: dict | None = None,
    max_iterations: int = 3,
) -> dict:
    """
    Aggregate evidence and run Claude analysis.

    Args:
        collector_results: List of dicts from collector tasks
        domain: Target domain
        investigation_id: UUID string
        context: User-provided context/notes
        client_domain: Optional client domain for similarity comparison
        external_context: CTI enrichment data
        max_iterations: Max analyst follow-up rounds

    Returns:
        Full investigation result dict with evidence + report
    """
    logger.info(f"[{investigation_id}] Aggregating evidence for {domain}")

    # ── 1. Build evidence object ──
    evidence_data = {
        "domain": domain,
        "investigation_id": investigation_id,
        "timestamps": {
            "started": datetime.now(timezone.utc).isoformat(),
        },
    }

    all_artifact_hashes = {}
    collector_statuses = {}

    for result in collector_results:
        name = result["collector"]
        field_name = COLLECTOR_FIELD_MAP.get(name, name)
        collector_statuses[name] = result["status"]
        evidence_data[field_name] = result["evidence"]
        # Track artifact hashes
        for artifact_name, hex_data in result.get("artifacts", {}).items():
            import hashlib
            raw = bytes.fromhex(hex_data)
            all_artifact_hashes[artifact_name] = hashlib.sha256(raw).hexdigest()
            # TODO: Persist raw artifacts to storage via ArtifactRepository

    evidence_data["artifact_hashes"] = all_artifact_hashes

    # ── 1b. Subdomain enumeration (post-processing on intel results) ──
    intel_subdomains = evidence_data.get("intel", {}).get("related_subdomains", [])
    if intel_subdomains:
        try:
            from app.collectors.subdomain_collector import enumerate_subdomains
            subdomain_result = enumerate_subdomains(domain, intel_subdomains)
            evidence_data["subdomains"] = subdomain_result
            logger.info(
                f"[{investigation_id}] Subdomain enumeration: "
                f"{len(subdomain_result['resolved'])} resolved, "
                f"{len(subdomain_result['interesting_subdomains'])} interesting"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Subdomain enumeration failed: {e}")

    # ── 1c. Email security analysis (post-processing on DNS results) ──
    dns_data = evidence_data.get("dns", {})
    if dns_data.get("meta", {}).get("status") == "completed":
        try:
            from app.collectors.email_security import analyze_email_security
            email_result = analyze_email_security(domain, dns_data)
            evidence_data["email_security"] = email_result
            logger.info(
                f"[{investigation_id}] Email security: score={email_result.get('email_security_score')}, "
                f"spoofability={email_result.get('spoofability_score')}, "
                f"DKIM selectors={len(email_result.get('dkim_selectors_found', []))}"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Email security analysis failed: {e}")

    # ── 1d. Redirect chain analysis (multi-UA cloaking detection) ──
    http_data = evidence_data.get("http", {})
    if http_data.get("reachable"):
        try:
            from app.collectors.redirect_analysis import analyze_redirects
            redirect_result = analyze_redirects(domain, timeout=15)
            evidence_data["redirect_analysis"] = redirect_result
            logger.info(
                f"[{investigation_id}] Redirect analysis: "
                f"cloaking={redirect_result.get('cloaking_detected')}, "
                f"max_chain={redirect_result.get('max_chain_length')}, "
                f"evasion={len(redirect_result.get('evasion_techniques', []))}"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Redirect analysis failed: {e}")

    # ── 1e. Standalone screenshot (always captured) ──
    try:
        from app.collectors.visual_comparison import capture_screenshot

        screenshot_target = investigated_url or domain
        logger.info(f"[{investigation_id}] Capturing screenshot of {screenshot_target}")
        ss_bytes, ss_final_url = capture_screenshot(screenshot_target, timeout=45)

        ss_art_id = _save_artifact_sync(
            investigation_id, "screenshot",
            "screenshot_domain.png",
            ss_bytes, "image/png",
        )
        if ss_art_id:
            evidence_data["screenshot"] = {
                "artifact_id": ss_art_id,
                "final_url": ss_final_url,
            }
        else:
            evidence_data["screenshot"] = {
                "capture_error": "Screenshot captured but failed to save artifact",
                "final_url": ss_final_url,
            }
        logger.info(
            f"[{investigation_id}] Screenshot captured: {len(ss_bytes)} bytes, "
            f"final_url={ss_final_url}"
        )
    except SoftTimeLimitExceeded:
        evidence_data["screenshot"] = {"capture_error": "Task time limit reached during screenshot"}
        logger.warning(f"[{investigation_id}] Screenshot aborted: task soft time limit reached")
        # Don't re-raise — let the task continue to persist partial results
    except Exception as e:
        evidence_data["screenshot"] = {"capture_error": str(e)}
        logger.warning(f"[{investigation_id}] Screenshot capture failed: {e}")

    # ── 1f. JavaScript behavior analysis (Playwright sandbox) ──
    if evidence_data.get("http", {}).get("reachable"):
        try:
            from app.collectors.js_analysis import analyze_js_behavior
            js_target = investigated_url or domain
            logger.info(f"[{investigation_id}] Starting JS behavior analysis of {js_target}")
            js_result = analyze_js_behavior(
                js_target,
                investigation_id,
                save_artifact_fn=_save_artifact_sync,
                timeout=45,
            )
            evidence_data["js_analysis"] = js_result
            logger.info(
                f"[{investigation_id}] JS analysis: "
                f"requests={js_result.get('total_requests')}, "
                f"external={js_result.get('external_requests')}, "
                f"POST endpoints={len(js_result.get('post_endpoints', []))}, "
                f"fingerprinting={len(js_result.get('fingerprinting_apis', []))}"
            )
        except SoftTimeLimitExceeded:
            logger.warning(f"[{investigation_id}] JS analysis aborted: task soft time limit reached")
            # Don't re-raise — continue to persist partial results
        except Exception as e:
            logger.warning(f"[{investigation_id}] JS behavior analysis failed: {e}")

    # ── 2. Domain similarity analysis (if client_domain provided) ──
    if client_domain:
        try:
            from app.collectors.domain_similarity import analyze_similarity
            similarity_result = analyze_similarity(domain, client_domain)
            evidence_data["domain_similarity"] = similarity_result.model_dump()
            logger.info(
                f"[{investigation_id}] Domain similarity: {similarity_result.overall_similarity_score}/100 "
                f"vs client '{client_domain}'"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Domain similarity analysis failed: {e}")

        # ── 2b. Visual comparison (screenshot-based) ──
        try:
            from app.collectors.visual_comparison import compare_websites

            # Check for uploaded reference image
            reference_image = _load_reference_image_sync(client_domain)

            # Use specific URLs if provided, otherwise fall back to domains
            inv_target = investigated_url or domain
            cli_target = client_url or client_domain

            logger.info(f"[{investigation_id}] Starting visual comparison: {inv_target} vs {cli_target}")
            visual_result = compare_websites(
                inv_target, cli_target,
                client_reference_image=reference_image,
                timeout=45,
            )

            # Persist screenshots as artifacts and get their IDs
            inv_screenshot_bytes = visual_result.pop("_investigated_screenshot_bytes", None)
            cli_screenshot_bytes = visual_result.pop("_client_screenshot_bytes", None)

            if inv_screenshot_bytes:
                art_id = _save_artifact_sync(
                    investigation_id, "visual_comparison",
                    "screenshot_investigated.png",
                    inv_screenshot_bytes, "image/png",
                )
                if art_id:
                    visual_result["investigated_screenshot_artifact_id"] = art_id

            if cli_screenshot_bytes:
                art_id = _save_artifact_sync(
                    investigation_id, "visual_comparison",
                    "screenshot_client.png",
                    cli_screenshot_bytes, "image/png",
                )
                if art_id:
                    visual_result["client_screenshot_artifact_id"] = art_id

            evidence_data["visual_comparison"] = visual_result

            overall = visual_result.get("overall_visual_similarity")
            if overall is not None:
                logger.info(
                    f"[{investigation_id}] Visual similarity: {overall:.0%} "
                    f"(clone={visual_result.get('is_visual_clone')})"
                )
        except SoftTimeLimitExceeded:
            logger.warning(f"[{investigation_id}] Visual comparison aborted: task soft time limit reached")
            # Don't re-raise — continue to persist partial results
        except Exception as e:
            logger.warning(f"[{investigation_id}] Visual comparison failed: {e}")

    # ── Infrastructure Pivot ──
    try:
        from app.collectors.infrastructure_pivot import collect_infrastructure_pivot
        pivot_result = collect_infrastructure_pivot(evidence_data, domain, investigation_id)
        if pivot_result:
            evidence_data["infrastructure_pivot"] = pivot_result
            logger.info(
                f"[{investigation_id}] Infrastructure pivot: {pivot_result.get('total_related_domains', 0)} related domains"
            )
    except Exception as e:
        logger.warning(f"[{investigation_id}] Infrastructure pivot failed: {e}")

    # ── Certificate Transparency Timeline ──
    try:
        from app.collectors.intel_collector import build_cert_timeline
        cert_timeline = build_cert_timeline(evidence_data, domain)
        if cert_timeline:
            evidence_data["cert_timeline"] = cert_timeline
            logger.info(
                f"[{investigation_id}] Cert timeline: {cert_timeline.get('total_certs', 0)} certs, "
                f"burst={cert_timeline.get('cert_burst_detected', False)}"
            )
    except Exception as e:
        logger.warning(f"[{investigation_id}] Cert timeline failed: {e}")

    # ── Favicon Hash Intelligence (Shodan pivot) ──
    try:
        from app.collectors.favicon_intel import collect_favicon_intel
        favicon_result = collect_favicon_intel(evidence_data, domain, investigation_id)
        if favicon_result:
            evidence_data["favicon_intel"] = favicon_result
            logger.info(
                f"[{investigation_id}] Favicon intel: {favicon_result.get('total_hosts_sharing', 0)} hosts sharing hash"
            )
    except Exception as e:
        logger.warning(f"[{investigation_id}] Favicon intel failed: {e}")

    # ── 3. Generate signals and detect gaps ──
    signals = generate_signals(evidence_data)
    gaps = detect_data_gaps(evidence_data)

    evidence_data["signals"] = [s.model_dump() for s in signals]
    evidence_data["data_gaps"] = [g.model_dump() for g in gaps]

    if external_context:
        evidence_data["external_context"] = external_context

    evidence_data["timestamps"]["collected"] = datetime.now(timezone.utc).isoformat()

    # ── 3. Publish evaluating state ──
    _publish_progress(investigation_id, InvestigationState.EVALUATING, collector_statuses,
                      "Evidence collected. Running analyst...", 70)

    # ── 4. Run Claude analyst ──
    try:
        report_data = _run_analyst_sync(evidence_data, max_iterations)
    except Exception as e:
        logger.error(f"[{investigation_id}] Analyst failed: {e}")
        report_data = {
            "classification": "inconclusive",
            "confidence": "low",
            "investigation_state": "concluded",
            "primary_reasoning": f"Analyst error: {e}",
            "legitimate_explanation": "",
            "malicious_explanation": "",
            "recommended_action": "investigate",
            "recommended_steps": ["Review evidence manually — analyst encountered an error"],
            "risk_score": None,
        }

    evidence_data["timestamps"]["analyzed"] = datetime.now(timezone.utc).isoformat()

    # ── 5. Build final result ──
    result = {
        "investigation_id": investigation_id,
        "domain": domain,
        "state": "concluded",
        "evidence": evidence_data,
        "report": report_data,
        "collector_statuses": collector_statuses,
    }

    # ── 6. Persist to database ──
    _persist_results(investigation_id, evidence_data, report_data, collector_statuses)

    # ── 7. Publish completion ──
    _publish_progress(investigation_id, InvestigationState.CONCLUDED, collector_statuses,
                      "Investigation complete", 100)

    return result


def _run_analyst_sync(evidence_data: dict, max_iterations: int) -> dict:
    """
    Synchronous wrapper for the async Claude analyst call.
    Celery workers are sync, so we run the async code in a new event loop.
    """
    import asyncio
    from app.models.schemas import CollectedEvidence
    from app.analyst.orchestrator import run_analyst

    evidence_obj = CollectedEvidence(**evidence_data)

    loop = asyncio.new_event_loop()
    try:
        report = loop.run_until_complete(
            run_analyst(evidence_obj, iteration=0, max_iterations=max_iterations)
        )
        report_dict = report.model_dump(mode="json")

        # Enrich findings with MITRE ATT&CK metadata
        try:
            from app.analyst.attack_mapping import enrich_findings_with_attack
            if report_dict.get("findings"):
                report_dict["findings"] = enrich_findings_with_attack(report_dict["findings"])
        except Exception:
            pass  # ATT&CK enrichment is non-critical

        return report_dict
    finally:
        loop.close()


def _persist_results(
    investigation_id: str,
    evidence_data: dict,
    report_data: dict,
    collector_statuses: dict,
) -> None:
    """
    Persist results to Postgres using sync session.
    (Celery workers use sync DB access.)
    """
    try:
        from sqlalchemy import select
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from app.models.database import Investigation, Evidence, Report, CollectorResult, IOCRecord, WHOISHistory
        import uuid

        inv_id = uuid.UUID(investigation_id)

        with Session(sync_engine) as session:
            # Update investigation state
            inv = session.get(Investigation, inv_id)
            if inv:
                inv.state = "concluded"
                inv.concluded_at = datetime.now(timezone.utc)
                inv.classification = report_data.get("classification")
                inv.confidence = report_data.get("confidence")
                inv.risk_score = report_data.get("risk_score")
                inv.recommended_action = report_data.get("recommended_action")

            # Save evidence
            ev = Evidence(
                investigation_id=inv_id,
                evidence_json=evidence_data,
                signals=evidence_data.get("signals", []),
                data_gaps=evidence_data.get("data_gaps", []),
                external_context=evidence_data.get("external_context"),
            )
            session.merge(ev)

            # Save report
            report = Report(
                investigation_id=inv_id,
                iteration=0,
                report_json=report_data,
                executive_summary=report_data.get("executive_summary"),
                technical_narrative=report_data.get("technical_narrative"),
                recommendations=report_data.get("recommendations_narrative"),
            )
            session.add(report)

            # Save collector results
            for name, status in collector_statuses.items():
                field_name = COLLECTOR_FIELD_MAP.get(name, name)
                col_evidence = evidence_data.get(field_name, {})
                cr = CollectorResult(
                    investigation_id=inv_id,
                    collector_name=name,
                    status=status,
                    evidence_json=col_evidence,
                    duration_ms=col_evidence.get("meta", {}).get("duration_ms"),
                )
                session.merge(cr)

            # Extract IOCs from report and persist to iocs table
            for ioc in report_data.get("iocs", []):
                session.add(IOCRecord(
                    investigation_id=inv_id,
                    type=ioc.get("type", "domain"),
                    value=ioc.get("value", ""),
                    context=ioc.get("context"),
                    confidence=ioc.get("confidence"),
                ))

            # Save WHOIS history snapshot
            domain = evidence_data.get("dns", {}).get("queried_domain") or (inv.domain if inv else None)
            whois_data = evidence_data.get("whois", {})
            if domain and whois_data and whois_data.get("meta", {}).get("status") == "completed":
                from app.services.whois_history_service import compute_whois_diff
                prev = session.execute(
                    select(WHOISHistory)
                    .where(WHOISHistory.domain == domain)
                    .order_by(WHOISHistory.captured_at.desc())
                    .limit(1)
                ).scalar_one_or_none()
                changes = compute_whois_diff(prev.whois_json, whois_data) if prev else None
                session.add(WHOISHistory(
                    domain=domain,
                    whois_json=whois_data,
                    investigation_id=inv_id,
                    changes_from_previous=changes,
                ))

            session.commit()

            # Update batch progress if this investigation belongs to a batch
            if inv and inv.batch_id:
                _update_batch_progress(session, inv.batch_id)

    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to persist results: {e}")


def _update_batch_progress(session, batch_id) -> None:
    """Increment batch completed_count and mark complete if all done."""
    try:
        from app.models.database import Batch
        batch = session.get(Batch, batch_id)
        if batch:
            batch.completed_count += 1
            if batch.completed_count >= batch.total_domains:
                batch.status = "completed"
                batch.completed_at = datetime.now(timezone.utc)
            session.commit()
    except Exception as e:
        logger.warning(f"Failed to update batch progress: {e}")


def _mark_failed(investigation_id: str, reason: str) -> None:
    """Mark investigation as failed in the database."""
    try:
        import uuid
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from app.models.database import Investigation

        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            if inv:
                inv.state = "failed"
                session.commit()
    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to mark investigation as failed: {e}")


def _load_reference_image_sync(client_domain: str) -> bytes | None:
    """Load an uploaded reference image for a client domain, if one exists."""
    import re
    from pathlib import Path
    from app.config import get_settings

    settings = get_settings()
    safe_domain = re.sub(r"[^a-zA-Z0-9.\-]", "_", client_domain.lower().strip())

    if settings.artifact_storage == "local":
        path = Path(settings.artifact_local_path) / "reference" / f"{safe_domain}.png"
        if path.exists():
            return path.read_bytes()
    return None


def _save_artifact_sync(
    investigation_id: str,
    collector_name: str,
    artifact_name: str,
    data: bytes,
    content_type: str,
) -> str | None:
    """
    Persist an artifact to storage and record it in the database.
    Returns the artifact UUID string, or None on failure.
    """
    try:
        import hashlib
        import uuid as uuid_mod
        from pathlib import Path
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from app.models.database import Artifact
        from app.config import get_settings

        settings = get_settings()
        sha256 = hashlib.sha256(data).hexdigest()

        # Save to local storage (sync)
        if settings.artifact_storage == "local":
            base = Path(settings.artifact_local_path)
            dest = base / investigation_id / artifact_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            storage_path = str(dest)
        else:
            # For S3, we'd need async — for now store locally as fallback
            base = Path(settings.artifact_local_path)
            dest = base / investigation_id / artifact_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            storage_path = str(dest)

        # Record in database
        inv_id = uuid_mod.UUID(investigation_id)
        art_id = uuid_mod.uuid4()

        with Session(sync_engine) as session:
            artifact = Artifact(
                id=art_id,
                investigation_id=inv_id,
                collector_name=collector_name,
                artifact_name=artifact_name,
                sha256_hash=sha256,
                content_type=content_type,
                size_bytes=len(data),
                storage_path=storage_path,
            )
            session.add(artifact)
            session.commit()

        return str(art_id)

    except Exception as e:
        logger.warning(f"[{investigation_id}] Failed to save artifact {artifact_name}: {e}")
        return None


def _publish_progress(
    investigation_id: str,
    state: InvestigationState,
    collector_statuses: dict,
    message: str,
    percent: int,
) -> None:
    """Push progress event to Redis for SSE."""
    import redis as redis_lib
    try:
        from app.config import get_settings
        r = redis_lib.Redis.from_url(get_settings().redis_url)
        r.publish(
            f"investigation:{investigation_id}",
            json.dumps({
                "type": "state_change",
                "investigation_id": investigation_id,
                "state": state.value,
                "collectors": collector_statuses,
                "message": message,
                "percent_complete": percent,
            }),
        )
    except Exception as e:
        logger.warning(f"Failed to publish progress: {e}")
