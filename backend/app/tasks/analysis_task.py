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
    time_limit=180,       # Analysis can take longer (Claude API call)
    soft_time_limit=150,
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
        except Exception as e:
            logger.warning(f"[{investigation_id}] Visual comparison failed: {e}")

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
        return report.model_dump(mode="json")
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
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from app.models.database import Investigation, Evidence, Report, CollectorResult
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

            session.commit()

    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to persist results: {e}")


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
