"""
Analysis Task  -  aggregates collector results and runs the Claude analyst.

This task is the callback of the collector chord:
  chord(collector_tasks)(run_analysis.s(...))

It:
1. Merges all collector evidence into a single object
2. Generates signals and detects data gaps
3. Calls the Claude analyst (with follow-up iterations if needed)
4. Persists the report to the database
"""

from __future__ import annotations

import copy
import json
import logging
import time
import concurrent.futures
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from celery.exceptions import SoftTimeLimitExceeded

from app.tasks.celery_app import celery_app
from app.collectors.signals import generate_signals, detect_data_gaps
from app.models.enums import InvestigationState
from app.config import get_settings
from app.services.decision_engine import apply_decision_to_report, build_decision_report
from app.services.proxy_profiles import selected_proxy_summary
from app.utils.domain_utils import extract_registered_domain

logger = logging.getLogger(__name__)
settings = get_settings()

MAX_IOC_VALUE_LENGTH = 512
MAX_IOCS_PER_REPORT = 150
MAX_ANYRUN_EXTRACTED_IOCS = 40
MAX_ANYRUN_RAW_IOCS = 25
ALLOWED_IOC_TYPES = {"domain", "ip", "url", "hash", "email"}

# Map collector names to evidence field names when they differ
COLLECTOR_FIELD_MAP = {
    "asn": "hosting",
}


def _truncate_ioc_value(value: object, max_length: int = MAX_IOC_VALUE_LENGTH) -> str:
    """
    Fit IOC values into the database column without failing the whole investigation.
    The full source evidence remains available in evidence_json/report_json.
    """
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + "..."


def _normalize_ioc_for_storage(ioc: dict | None) -> dict | None:
    if not isinstance(ioc, dict):
        return None
    ioc_type = str(ioc.get("type") or "domain").strip().lower()
    if ioc_type not in ALLOWED_IOC_TYPES:
        ioc_type = "domain"
    value = _truncate_ioc_value(ioc.get("value"))
    if not value:
        return None
    confidence = str(ioc.get("confidence") or "medium").strip().lower()[:20] or "medium"
    return {
        "type": ioc_type,
        "value": value,
        "context": ioc.get("context"),
        "confidence": confidence,
    }


def _build_lexical_target(*, observable_type: str, domain: str, evidence_data: dict) -> str:
    """
    Build the URL-like target string passed to lexical scoring.
    Domain investigations prefer HTTP final URL when available.
    """
    if observable_type == "url":
        return str(domain or "")
    http_data = evidence_data.get("http") or {}
    final_url = str(http_data.get("final_url") or "").strip()
    if final_url:
        return final_url
    base = str(domain or "").strip()
    if base.startswith("http://") or base.startswith("https://"):
        return base
    return f"https://{base}" if base else ""


def _collect_redirect_destination_intel(
    *,
    domain: str,
    investigation_id: str,
    observable_type: str,
    evidence_data: dict,
) -> dict | None:
    """
    Enrich cross-domain redirect destinations to support impersonation comparisons.
    """
    http = evidence_data.get("http") or {}
    final_url = str(http.get("final_url") or "").strip()
    if not final_url:
        # Fallback 1: redirect-analysis browser probe final URL.
        redirect_analysis = evidence_data.get("redirect_analysis") or {}
        probes = redirect_analysis.get("probes") or []
        if isinstance(probes, list):
            browser_probe = next(
                (
                    p for p in probes
                    if isinstance(p, dict) and str(p.get("user_agent_type") or "").lower() in {"browser", "default"}
                ),
                None,
            )
            if isinstance(browser_probe, dict):
                final_url = str(browser_probe.get("final_url") or "").strip()
            elif probes and isinstance(probes[0], dict):
                final_url = str(probes[0].get("final_url") or "").strip()
    if not final_url:
        # Fallback 2: URLScan page URL (often available even when HTTP probe fails).
        urlscan = evidence_data.get("urlscan") or {}
        final_url = str(urlscan.get("page_url") or "").strip()
    if not final_url:
        # Fallback 3: captured screenshot final URL.
        screenshot = evidence_data.get("screenshot") or {}
        final_url = str(screenshot.get("final_url") or "").strip()
    if not final_url:
        return None

    try:
        destination_host = (urlparse(final_url).hostname or "").strip().lower()
    except Exception:
        destination_host = ""
    if not destination_host:
        return None

    investigated_host = str(domain or "").strip().lower()
    if observable_type == "url":
        try:
            investigated_host = (urlparse(investigated_host).hostname or investigated_host).strip().lower()
        except Exception:
            pass

    investigated_root = extract_registered_domain(investigated_host) or investigated_host
    destination_root = extract_registered_domain(destination_host) or destination_host
    if not investigated_root or not destination_root or investigated_root == destination_root:
        return None

    out: dict[str, object] = {
        "final_url": final_url,
        "investigated_host": investigated_host,
        "investigated_root": investigated_root,
        "destination_host": destination_host,
        "destination_root": destination_root,
    }

    # WHOIS comparison
    try:
        from app.collectors.whois_collector import WHOISCollector

        whois_collector = WHOISCollector(
            domain=destination_root,
            investigation_id=investigation_id,
            observable_type="domain",
            timeout=min(settings.collector_timeout, 20),
        )
        whois_ev, whois_meta, _ = whois_collector.run()
        out["whois"] = {
            "status": whois_meta.status.value,
            "error": whois_meta.error,
            "registrar": whois_ev.registrar,
            "domain_age_days": whois_ev.domain_age_days,
            "created_date": whois_ev.created_date.isoformat() if whois_ev.created_date else None,
            "expiry_date": whois_ev.expiry_date.isoformat() if whois_ev.expiry_date else None,
            "name_servers": whois_ev.name_servers,
            "registrant_org": whois_ev.registrant_org,
            "registrant_country": whois_ev.registrant_country,
        }
    except Exception as exc:
        out["whois"] = {"status": "failed", "error": str(exc)}

    # VT comparison
    try:
        from app.collectors.vt_collector import VTCollector

        vt_collector = VTCollector(
            domain=destination_root,
            investigation_id=investigation_id,
            observable_type="domain",
            timeout=min(settings.collector_timeout, 25),
        )
        vt_ev, vt_meta, _ = vt_collector.run()
        out["vt"] = {
            "status": vt_meta.status.value,
            "error": vt_meta.error,
            "found": vt_ev.found,
            "malicious_count": vt_ev.malicious_count,
            "suspicious_count": vt_ev.suspicious_count,
            "total_vendors": vt_ev.total_vendors,
            "reputation_score": vt_ev.reputation_score,
            "categories": vt_ev.categories,
        }
    except Exception as exc:
        out["vt"] = {"status": "failed", "error": str(exc)}

    # DNS context
    try:
        from app.collectors.dns_collector import DNSCollector

        dns_collector = DNSCollector(
            domain=destination_root,
            investigation_id=investigation_id,
            observable_type="domain",
            timeout=min(settings.collector_timeout, 20),
        )
        dns_ev, dns_meta, _ = dns_collector.run()
        out["dns"] = {
            "status": dns_meta.status.value,
            "error": dns_meta.error,
            "a": dns_ev.a,
            "aaaa": dns_ev.aaaa,
            "mx": dns_ev.mx,
            "ns": dns_ev.ns,
        }
    except Exception as exc:
        out["dns"] = {"status": "failed", "error": str(exc)}

    # Hosting/ASN context
    try:
        from app.collectors.asn_collector import ASNCollector

        asn_collector = ASNCollector(
            domain=destination_root,
            investigation_id=investigation_id,
            observable_type="domain",
            timeout=min(settings.collector_timeout, 20),
        )
        asn_ev, asn_meta, _ = asn_collector.run()
        out["hosting"] = {
            "status": asn_meta.status.value,
            "error": asn_meta.error,
            "ip": asn_ev.ip,
            "asn": asn_ev.asn,
            "asn_org": asn_ev.asn_org,
            "country": asn_ev.country,
            "is_cdn": asn_ev.is_cdn,
            "is_cloud": asn_ev.is_cloud,
        }
    except Exception as exc:
        out["hosting"] = {"status": "failed", "error": str(exc)}

    # Compact comparison summary
    src_age = (evidence_data.get("whois") or {}).get("domain_age_days")
    dst_age = ((out.get("whois") or {}).get("domain_age_days") if isinstance(out.get("whois"), dict) else None)
    out["comparison"] = {
        "source_age_days": src_age,
        "destination_age_days": dst_age,
        "source_vs_destination_root": f"{investigated_root} -> {destination_root}",
    }
    return out


_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def _build_attachment_analysis_for_file_hash(*, investigation_id: str, domain: str, evidence_data: dict) -> dict | None:
    """
    Build static attachment analysis for file/hash observables.
    Uses uploaded artifact metadata when present; falls back to submitted hash.
    """
    from sqlalchemy.orm import Session
    from uuid import UUID
    from app.db.session import sync_engine
    from app.models.database import Artifact, Investigation
    from app.services.ml_attachment_analyzer import analyze_attachments_static

    attachments: list[dict] = []
    submitted = str(domain or "").strip().lower()
    with Session(sync_engine) as db:
        try:
            inv = db.get(Investigation, UUID(investigation_id))
        except Exception:
            inv = None
        if inv is not None:
            artifact = (
                db.query(Artifact)
                .filter(Artifact.investigation_id == inv.id, Artifact.collector_name == "upload")
                .order_by(Artifact.created_at.desc())
                .first()
            )
            if artifact:
                attachments.append(
                    {
                        "filename": artifact.artifact_name or "uploaded_sample.bin",
                        "sha256": (artifact.sha256_hash or "").lower(),
                    }
                )
    if not attachments and submitted and _HEX_RE.match(submitted):
        if len(submitted) == 64:
            attachments.append({"filename": "submitted_hash.bin", "sha256": submitted})
        elif len(submitted) == 40:
            attachments.append({"filename": "submitted_hash.bin", "sha1": submitted})
        elif len(submitted) == 32:
            attachments.append({"filename": "submitted_hash.bin", "md5": submitted})

    if not attachments:
        return None

    vt = evidence_data.get("vt") or {}
    vt_verdict = "unknown"
    try:
        malicious = int(vt.get("malicious_count") or 0)
        suspicious = int(vt.get("suspicious_count") or 0)
        if malicious > 0:
            vt_verdict = "malicious"
        elif suspicious > 0:
            vt_verdict = "suspicious"
        elif vt.get("found"):
            vt_verdict = "clean"
    except Exception:
        vt_verdict = "unknown"

    vt_by_sha: dict[str, dict] = {}
    for item in attachments:
        sha = str(item.get("sha256") or "").lower()
        if not sha:
            continue
        vt_by_sha[sha] = {
            "vt": {
                "verdict": vt_verdict,
                "malicious_count": int(vt.get("malicious_count") or 0),
                "suspicious_count": int(vt.get("suspicious_count") or 0),
            }
        }
    return analyze_attachments_static(attachments, vt_items_by_sha256=vt_by_sha)


@celery_app.task(
    bind=True,
    name="tasks.run_analysis",
    time_limit=300,       # Hard kill after 5 min (Playwright steps can be slow)
    soft_time_limit=270,  # Soft limit at 4.5 min  -  gives time to persist partial results
)
def run_analysis(
    self,
    collector_results: list[dict],
    domain: str,
    investigation_id: str,
    observable_type: str = "domain",
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
    analysis_started = time.monotonic()
    phase_timings_ms: dict[str, int] = {}
    _publish_progress(
        investigation_id,
        InvestigationState.EVALUATING,
        {},
        "Merging collector evidence...",
        62,
    )

    # For URL investigations, extract the hostname for all domain-based post-processors
    # (subdomain enum, email security, cert timeline, infra pivot, favicon, WHOIS history).
    # HTTP/screenshot/JS analysis still operate on the full URL.
    if observable_type == "url":
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(domain)
        effective_domain = _parsed.hostname or domain
    else:
        effective_domain = domain

    # -- 1. Build evidence object --
    evidence_data = {
        "domain": domain,
        "observable_type": observable_type,
        "investigation_id": investigation_id,
        # Hostname extracted from URL (equals domain for non-URL types)
        "target_domain": effective_domain,
        "timestamps": {
            "started": datetime.now(timezone.utc).isoformat(),
        },
    }
    proxy_summary = selected_proxy_summary(external_context)
    proxy_country = (proxy_summary or {}).get("country")
    if proxy_summary:
        evidence_data["network_profile"] = proxy_summary

    all_artifact_hashes = {}
    artifact_ids: dict[str, str] = {}
    collector_statuses = {}

    def _time_phase(name: str, started_at: float) -> None:
        phase_timings_ms[name] = int((time.monotonic() - started_at) * 1000)

    for result in collector_results:
        name = result["collector"]
        field_name = COLLECTOR_FIELD_MAP.get(name, name)
        collector_statuses[name] = result["status"]
        evidence_data[field_name] = result["evidence"]
        # Track artifact hashes and persist collector raw artifacts.
        for artifact_name, hex_data in result.get("artifacts", {}).items():
            import hashlib
            raw = bytes.fromhex(hex_data)
            all_artifact_hashes[artifact_name] = hashlib.sha256(raw).hexdigest()
            content_type = _guess_content_type(artifact_name)
            art_id = _save_artifact_sync(
                investigation_id=investigation_id,
                collector_name=name,
                artifact_name=artifact_name,
                data=raw,
                content_type=content_type,
            )
            if art_id:
                artifact_ids[artifact_name] = art_id

        # Normalize known artifact id fields to true DB UUID ids.
        if name == "urlscan":
            urlscan_ev = evidence_data.get("urlscan") or {}
            if isinstance(urlscan_ev, dict):
                real_id = artifact_ids.get("urlscan_screenshot_png")
                if real_id:
                    urlscan_ev["screenshot_artifact_id"] = real_id
                elif not artifact_ids.get("urlscan_screenshot_png"):
                    urlscan_ev["screenshot_artifact_id"] = None

    evidence_data["artifact_hashes"] = all_artifact_hashes

    # -- 1b. Subdomain enumeration (post-processing on intel results)  -  domain + url --
    intel_subdomains = evidence_data.get("intel", {}).get("related_subdomains", [])
    if observable_type in ("domain", "url") and intel_subdomains:
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            collector_statuses,
            "Analyzing discovered subdomains...",
            64,
        )
        try:
            from app.collectors.subdomain_collector import enumerate_subdomains
            subdomain_result = enumerate_subdomains(effective_domain, intel_subdomains)
            evidence_data["subdomains"] = subdomain_result
            logger.info(
                f"[{investigation_id}] Subdomain enumeration: "
                f"{len(subdomain_result['resolved'])} resolved, "
                f"{len(subdomain_result['interesting_subdomains'])} interesting"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Subdomain enumeration failed: {e}")

    # -- 1c. Email security analysis (post-processing on DNS results)  -  domain + url --
    dns_data = evidence_data.get("dns", {})
    if observable_type in ("domain", "url") and dns_data.get("meta", {}).get("status") == "completed":
        email_phase_start = time.monotonic()
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            collector_statuses,
            "Analyzing email security controls...",
            66,
        )
        try:
            from app.collectors.email_security import analyze_email_security
            email_result = analyze_email_security(effective_domain, dns_data)
            evidence_data["email_security"] = email_result
            logger.info(
                f"[{investigation_id}] Email security: score={email_result.get('email_security_score')}, "
                f"spoofability={email_result.get('spoofability_score')}, "
                f"DKIM selectors={len(email_result.get('dkim_selectors_found', []))}"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Email security analysis failed: {e}")
        _time_phase("email_security", email_phase_start)

    # -- 1d. Redirect chain analysis (multi-UA cloaking detection)  -  domain + url --
    http_data = evidence_data.get("http", {})
    if observable_type in ("domain", "url") and http_data.get("reachable"):
        redirect_phase_start = time.monotonic()
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            collector_statuses,
            "Analyzing redirects and cloaking...",
            68,
        )
        try:
            from app.collectors.redirect_analysis import analyze_redirects
            redirect_result = analyze_redirects(domain, timeout=15, proxy_country=proxy_country)
            evidence_data["redirect_analysis"] = redirect_result
            logger.info(
                f"[{investigation_id}] Redirect analysis: "
                f"cloaking={redirect_result.get('cloaking_detected')}, "
                f"max_chain={redirect_result.get('max_chain_length')}, "
                f"evasion={len(redirect_result.get('evasion_techniques', []))}"
            )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Redirect analysis failed: {e}")
        _time_phase("redirect_analysis", redirect_phase_start)

    # -- 1e + 1f. Browser post-processing (screenshot + JS) in parallel --
    if observable_type in ("domain", "url") and http_data.get("reachable"):
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            collector_statuses,
            "Running browser analysis (screenshot + JavaScript)...",
            74,
        )
        browser_phase_start = time.monotonic()
        reuse_urlscan_screenshot = _should_reuse_urlscan_screenshot(evidence_data, observable_type)
        if reuse_urlscan_screenshot:
            evidence_data["screenshot"] = _build_reused_screenshot_payload(
                evidence_data,
                investigated_url=investigated_url,
                domain=domain,
            )
            logger.info(
                f"[{investigation_id}] Reusing URLScan screenshot artifact "
                f"{evidence_data['screenshot'].get('artifact_id')} and skipping local capture"
            )

        def _run_screenshot() -> tuple[str, dict]:
            from app.collectors.visual_comparison import capture_screenshot
            screenshot_target = investigated_url or domain
            logger.info(f"[{investigation_id}] Capturing screenshot of {screenshot_target}")
            ss_bytes, ss_final_url = capture_screenshot(
                screenshot_target,
                timeout=25,
                proxy_country=proxy_country,
            )
            ss_art_id = _save_artifact_sync(
                investigation_id, "screenshot",
                "screenshot_domain.png",
                ss_bytes, "image/png",
            )
            if ss_art_id:
                payload = {"artifact_id": ss_art_id, "final_url": ss_final_url, "network_profile": proxy_summary}
            else:
                payload = {
                    "capture_error": "Screenshot captured but failed to save artifact",
                    "final_url": ss_final_url,
                    "network_profile": proxy_summary,
                }
            logger.info(
                f"[{investigation_id}] Screenshot captured: {len(ss_bytes)} bytes, final_url={ss_final_url}"
            )
            return "screenshot", payload

        def _run_js_analysis() -> tuple[str, dict]:
            from app.collectors.js_analysis import analyze_js_behavior
            js_target = investigated_url or domain
            logger.info(f"[{investigation_id}] Starting JS behavior analysis of {js_target}")
            js_result = analyze_js_behavior(
                js_target,
                investigation_id,
                save_artifact_fn=_save_artifact_sync,
                timeout=25,
                proxy_country=proxy_country,
            )
            logger.info(
                f"[{investigation_id}] JS analysis: "
                f"requests={js_result.get('total_requests')}, "
                f"external={js_result.get('external_requests')}, "
                f"POST endpoints={len(js_result.get('post_endpoints', []))}, "
                f"fingerprinting={len(js_result.get('fingerprinting_apis', []))}"
            )
            return "js_analysis", js_result

        max_workers = 1 if reuse_urlscan_screenshot else 2
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map: dict[concurrent.futures.Future, str] = {
                pool.submit(_run_js_analysis): "js_analysis",
            }
            if not reuse_urlscan_screenshot:
                future_map[pool.submit(_run_screenshot)] = "screenshot"
            for future in concurrent.futures.as_completed(future_map):
                name = future_map[future]
                try:
                    key, value = future.result()
                    evidence_data[key] = value
                except SoftTimeLimitExceeded:
                    if name == "screenshot":
                        evidence_data["screenshot"] = {"capture_error": "Task time limit reached during screenshot"}
                        logger.warning(f"[{investigation_id}] Screenshot aborted: task soft time limit reached")
                    else:
                        evidence_data["js_analysis"] = {
                            "total_requests": 0,
                            "external_requests": 0,
                            "request_domains": [],
                            "captured_requests": [],
                            "post_endpoints": [],
                            "tracking_pixels": [],
                            "fingerprinting_apis": [],
                            "suspicious_scripts": [],
                            "websocket_connections": [],
                            "data_exfil_indicators": [],
                            "console_errors": [],
                            "error": "Task time limit reached during JavaScript analysis",
                            "har_artifact_id": None,
                        }
                        logger.warning(f"[{investigation_id}] JS analysis aborted: task soft time limit reached")
                except Exception as e:
                    if name == "screenshot":
                        evidence_data["screenshot"] = {"capture_error": str(e)}
                        logger.warning(f"[{investigation_id}] Screenshot capture failed: {e}")
                    else:
                        evidence_data["js_analysis"] = {
                            "total_requests": 0,
                            "external_requests": 0,
                            "request_domains": [],
                            "captured_requests": [],
                            "post_endpoints": [],
                            "tracking_pixels": [],
                            "fingerprinting_apis": [],
                            "suspicious_scripts": [],
                            "websocket_connections": [],
                            "data_exfil_indicators": [],
                            "console_errors": [],
                            "error": str(e),
                            "har_artifact_id": None,
                        }
                        logger.warning(f"[{investigation_id}] JS behavior analysis failed: {e}")

        _time_phase("browser_postprocessing", browser_phase_start)

    # -- 2. Domain similarity analysis (if client_domain provided)  -  domain only --
    if observable_type == "domain" and client_domain:
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

        # -- 2b. Visual comparison (screenshot-based) --
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
                timeout=25,
                proxy_country=proxy_country,
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
            # Don't re-raise  -  continue to persist partial results
        except Exception as e:
            logger.warning(f"[{investigation_id}] Visual comparison failed: {e}")

    # -- Infrastructure Pivot + Cert Timeline + Favicon  -  domain + url --
    if observable_type in ("domain", "url"):
        infra_phase_start = time.monotonic()
        _publish_progress(
            investigation_id,
            InvestigationState.EVALUATING,
            collector_statuses,
            "Running infrastructure correlation...",
            82,
        )
        try:
            from app.collectors.infrastructure_pivot import collect_infrastructure_pivot
            pivot_result = collect_infrastructure_pivot(evidence_data, effective_domain, investigation_id)
            if pivot_result:
                evidence_data["infrastructure_pivot"] = pivot_result
                logger.info(
                    f"[{investigation_id}] Infrastructure pivot: {pivot_result.get('total_related_domains', 0)} related domains"
                )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Infrastructure pivot failed: {e}")

        try:
            from app.collectors.intel_collector import build_cert_timeline
            cert_timeline = build_cert_timeline(evidence_data, effective_domain)
            if cert_timeline:
                evidence_data["cert_timeline"] = cert_timeline
                logger.info(
                    f"[{investigation_id}] Cert timeline: {cert_timeline.get('total_certs', 0)} certs, "
                    f"burst={cert_timeline.get('cert_burst_detected', False)}"
                )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Cert timeline failed: {e}")

        try:
            from app.collectors.favicon_intel import collect_favicon_intel
            favicon_result = collect_favicon_intel(evidence_data, effective_domain, investigation_id)
            if favicon_result:
                evidence_data["favicon_intel"] = favicon_result
                logger.info(
                    f"[{investigation_id}] Favicon intel: {favicon_result.get('total_hosts_sharing', 0)} hosts sharing hash"
                )
        except Exception as e:
            logger.warning(f"[{investigation_id}] Favicon intel failed: {e}")
        _time_phase("infrastructure_correlation", infra_phase_start)

    # -- 3. URL lexical ML scoring (domain/url) --
    if observable_type in ("domain", "url"):
        lexical_phase_start = time.monotonic()
        try:
            from app.services.url_lexical_ml_service import assess_url_lexical_risk

            lexical_target = _build_lexical_target(
                observable_type=observable_type,
                domain=domain,
                evidence_data=evidence_data,
            )
            if lexical_target:
                evidence_data["url_lexical_ml"] = assess_url_lexical_risk(lexical_target)
        except Exception as e:
            logger.warning(f"[{investigation_id}] URL lexical ML scoring failed: {e}")
            evidence_data["url_lexical_ml"] = {
                "model_source": "built_in",
                "score": 0.0,
                "label": "low",
                "top_features": [],
                "feature_contributions": {},
                "thresholds": {"low_max": 0.30, "medium_max": 0.65},
                "weights": {"lexical_weight": 0.25},
                "error": str(e),
            }
        _time_phase("url_lexical_ml", lexical_phase_start)

    # -- 3b. Redirect destination enrichment (cross-domain redirect intelligence) --
    if observable_type in ("domain", "url"):
        redirect_dest_phase_start = time.monotonic()
        try:
            redirect_dest = _collect_redirect_destination_intel(
                domain=domain,
                investigation_id=investigation_id,
                observable_type=observable_type,
                evidence_data=evidence_data,
            )
            if redirect_dest:
                evidence_data["redirect_destination_intel"] = redirect_dest
        except Exception as e:
            logger.warning(f"[{investigation_id}] Redirect destination enrichment failed: {e}")
        _time_phase("redirect_destination_enrichment", redirect_dest_phase_start)

    # -- 3c. Attachment static analysis for file/hash observables --
    if observable_type in ("file", "hash"):
        attachment_phase_start = time.monotonic()
        try:
            attachment_analysis = _build_attachment_analysis_for_file_hash(
                investigation_id=investigation_id,
                domain=domain,
                evidence_data=evidence_data,
            )
            if attachment_analysis:
                evidence_data["attachment_analysis"] = attachment_analysis
        except Exception as e:
            logger.warning(f"[{investigation_id}] Attachment static analysis failed: {e}")
        _time_phase("attachment_static_analysis", attachment_phase_start)

    # -- 4. Generate signals and detect gaps --
    signal_phase_start = time.monotonic()
    signals = generate_signals(evidence_data)
    gaps = detect_data_gaps(evidence_data)
    _time_phase("signals_and_gaps", signal_phase_start)

    evidence_data["signals"] = [s.model_dump() for s in signals]
    evidence_data["data_gaps"] = [g.model_dump() for g in gaps]

    # Normalize next-gen ML/behavior evidence fields and compute final composite risk.
    try:
        if "url_lexical_ml" in evidence_data and "ml_url_score" not in evidence_data:
            from app.services.ml_url_model import score_url

            lexical_target = _build_lexical_target(
                observable_type=observable_type,
                domain=domain,
                evidence_data=evidence_data,
            )
            if lexical_target:
                evidence_data["ml_url_score"] = score_url(lexical_target)
        if "redirect_analysis" in evidence_data and "url_behavior" not in evidence_data:
            ra = evidence_data.get("redirect_analysis") or {}
            probes = ra.get("probes") or []
            final_url = probes[0].get("final_url") if probes and isinstance(probes[0], dict) else None
            evidence_data["url_behavior"] = {
                "checked": True,
                "redirect_count": int(ra.get("max_chain_length") or 0),
                "ua_cloaking_detected": bool(ra.get("cloaking_detected")),
                "credential_form_present": False,
                "suspicious_post_endpoints": [],
                "multiple_domain_hops": bool(ra.get("intermediate_domains")),
                "unique_domains_in_chain": [str(x.get("domain")) for x in (ra.get("intermediate_domains") or []) if isinstance(x, dict) and x.get("domain")],
                "final_url": final_url,
                "behavior_score": 0.55 if ra.get("cloaking_detected") else (0.25 if int(ra.get("max_chain_length") or 0) >= 3 else 0.05),
                "chains": [],
            }
        from app.services.risk_aggregator import aggregate_risk

        evidence_data["final_risk"] = aggregate_risk(evidence_data)
    except Exception as e:
        logger.warning(f"[{investigation_id}] ML/risk aggregation failed: {e}")

    if external_context:
        evidence_data["external_context"] = external_context

    evidence_data["timestamps"]["collected"] = datetime.now(timezone.utc).isoformat()
    decision_report = build_decision_report(evidence_data, observable_type)

    # -- 4. Generate report  -  fast-path (rule-based) or Claude analyst --
    # Domain and URL investigations use Claude for full AI interpretation.
    # Hash/file/IP use fast-path rule-based classification (no Claude API call).
    if observable_type not in ("domain", "url"):
        report_phase_start = time.monotonic()
        _publish_progress(investigation_id, InvestigationState.EVALUATING, collector_statuses,
                          "Generating automated report...", 90)
        logger.info(f"[{investigation_id}] Using fast-path (rule-based) report for type={observable_type}")
        report_data = _generate_automated_report(evidence_data, observable_type)
        report_data = apply_decision_to_report(report_data, decision_report)
        _time_phase("report_generation", report_phase_start)
    else:
        report_phase_start = time.monotonic()
        _publish_progress(investigation_id, InvestigationState.EVALUATING, collector_statuses,
                          "Evidence collected. Running analyst...", 90)
        actual_model = ""  # updated by _run_analyst_with_compaction; fallback paths leave it blank
        try:
            report_data, analyst_tier, actual_model = _run_analyst_with_compaction(
                evidence_data,
                max_iterations=max_iterations,
                timeout_seconds=settings.analyst_timeout_seconds,
            )
            if _is_parser_fallback_report(report_data):
                logger.warning(
                    f"[{investigation_id}] Analyst output parse fallback detected. "
                    "Using automated report synthesis for structured fields."
                )
                auto_report = _generate_automated_report(evidence_data, observable_type)
                auto_report = apply_decision_to_report(auto_report, decision_report)
                raw_summary = str(report_data.get("executive_summary") or "")[:3000]
                auto_report["primary_reasoning"] = (
                    "Analyst response parse fallback applied. "
                    + str(auto_report.get("primary_reasoning") or "")
                ).strip()
                if raw_summary:
                    auto_report["executive_summary"] = raw_summary
                report_data = auto_report
            report_data = _annotate_compact_analyst_report(report_data, used_tier=analyst_tier)
            report_data = apply_decision_to_report(report_data, decision_report)
        except TimeoutError as e:
            logger.warning(
                f"[{investigation_id}] Analyst timed out after "
                f"{settings.analyst_timeout_seconds}s: {e}. Falling back to automated report."
            )
            report_data = _generate_automated_report(evidence_data, observable_type)
            report_data = apply_decision_to_report(report_data, decision_report)
            timeout_note = (
                f"Analyst timeout after {settings.analyst_timeout_seconds}s. "
                "Fallback automated analysis applied."
            )
            detailed_text = (
                report_data.get("executive_summary")
                or report_data.get("technical_narrative")
                or report_data.get("primary_reasoning", "")
            )
            report_data["primary_reasoning"] = f"{timeout_note} {detailed_text}".strip()
            if report_data.get("executive_summary"):
                report_data["executive_summary"] = f"{timeout_note} {report_data['executive_summary']}".strip()
        except Exception as e:
            if _is_prompt_too_long_error(e):
                logger.warning(
                    f"[{investigation_id}] Analyst prompt exceeded model limits after compact retries: {e}. "
                    "Falling back to automated report."
                )
                report_data = _build_prompt_too_long_fallback_report(
                    apply_decision_to_report(
                        _generate_automated_report(evidence_data, observable_type),
                        decision_report,
                    ),
                    prompt_error=e,
                )
            else:
                logger.error(f"[{investigation_id}] Analyst failed: {e}")
                report_data = apply_decision_to_report({
                    "classification": "inconclusive",
                    "confidence": "low",
                    "investigation_state": "concluded",
                    "primary_reasoning": f"Analyst error: {e}",
                    "legitimate_explanation": "",
                    "malicious_explanation": "",
                    "recommended_action": "investigate",
                    "recommended_steps": ["Review evidence manually  -  analyst encountered an error"],
                    "risk_score": None,
                }, decision_report)
        _inject_lexical_contribution(report_data, evidence_data)
        _apply_phishing_redirect_risk_floor(report_data, evidence_data, observable_type)
        decision_report = apply_decision_to_report(decision_report, report_data)
        report_data = apply_decision_to_report(report_data, decision_report)
        _time_phase("report_generation", report_phase_start)

    report_data = _ensure_report_completeness(report_data, evidence_data, observable_type)

    # Record which AI model produced this report — set after _ensure_report_completeness
    # so it is guaranteed to survive into the persisted report_json.
    # Fast-path types (hash/ip/file) leave ai_model=None → frontend shows "Automated (rule-based)".
    if observable_type in ("domain", "url"):
        report_data["ai_model"] = actual_model
    else:
        report_data["ai_model"] = None
    report_data.setdefault("report_freshness", {
        "status": "fresh",
        "recomputed": False,
        "reason": "initial_analysis",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })

    # Derive recommended_action from classification (rule-based, not AI-generated).
    # This overrides any value the AI may have produced so the action is always consistent.
    _classification = str(report_data.get("classification") or "inconclusive").lower()
    _confidence = str(report_data.get("confidence") or "low").lower()
    if _classification == "malicious":
        report_data["recommended_action"] = "block"
    elif _classification == "suspicious":
        report_data["recommended_action"] = "investigate" if _confidence in ("medium", "high") else "monitor"
    elif _classification == "benign":
        report_data["recommended_action"] = "monitor"
    else:
        report_data["recommended_action"] = "investigate"
    _align_final_risk_with_report(evidence_data, report_data)

    evidence_data["timestamps"]["analyzed"] = datetime.now(timezone.utc).isoformat()
    phase_timings_ms["analysis_total"] = int((time.monotonic() - analysis_started) * 1000)
    evidence_data["pipeline_timings_ms"] = phase_timings_ms
    logger.info(f"[{investigation_id}] Analysis phase timings (ms): {phase_timings_ms}")

    # -- 5. Build final result --
    result = {
        "investigation_id": investigation_id,
        "domain": domain,
        "state": "concluded",
        "evidence": evidence_data,
        "report": report_data,
        "collector_statuses": collector_statuses,
    }

    # -- 6. Persist to database --
    persist_start = time.monotonic()
    _persist_results(investigation_id, evidence_data, report_data, collector_statuses)
    logger.info(f"[{investigation_id}] Persist phase took {int((time.monotonic() - persist_start) * 1000)}ms")

    # -- 7. Publish completion --
    _publish_progress(investigation_id, InvestigationState.CONCLUDED, collector_statuses,
                      "Investigation complete", 100)

    return result


def _generate_automated_report(evidence_data: dict, observable_type: str) -> dict:
    """
    Rule-based report for ip / hash / file investigations.
    No Claude API call  -  classification derived directly from collector scores.
    """
    vt          = evidence_data.get("vt") or {}
    threat_feeds = evidence_data.get("threat_feeds") or {}
    domain      = evidence_data.get("domain", "")

    classification     = "benign"
    confidence         = "medium"
    risk_score: int | None = 10
    key_evidence: list[str] = []
    recommended_action = "monitor"
    recommended_steps: list[str] = []
    findings: list[dict] = []
    data_needed: list[str] = []
    legitimate_explanation = ""
    malicious_explanation = ""
    executive_summary = ""
    technical_narrative = ""
    recommendations_narrative = ""

    # -- Hash / File ----------------------------------------------------------
    if observable_type in ("hash", "file"):
        vt_found     = vt.get("found", False)
        vt_malicious = vt.get("malicious_count", 0)
        vt_suspicious = vt.get("suspicious_count", 0)
        vt_total     = vt.get("total_vendors", 0)
        flagged_by   = vt.get("flagged_malicious_by", []) or []

        if not vt_found:
            classification = "inconclusive"
            confidence     = "low"
            risk_score     = None
            key_evidence   = ["Hash not found in VirusTotal database"]
            recommended_action = "investigate"
        elif vt_malicious >= 5:
            classification = "malicious"
            confidence     = "high"
            risk_score     = min(98, 70 + vt_malicious)
            vendors_str    = ", ".join(flagged_by[:5]) + (f" +{len(flagged_by)-5} more" if len(flagged_by) > 5 else "")
            key_evidence   = [
                f"Detected malicious by {vt_malicious}/{vt_total} antivirus vendors",
                f"Flagged by: {vendors_str}",
            ]
            recommended_action = "block"
            recommended_steps  = [
                "Quarantine and remove the file from all systems",
                "Investigate execution history and lateral movement",
                "Check EDR telemetry for related processes or persistence",
            ]
        elif vt_malicious >= 2 or vt_suspicious >= 3:
            classification = "suspicious"
            confidence     = "medium"
            risk_score     = 65
            key_evidence   = [f"{vt_malicious} malicious, {vt_suspicious} suspicious vendor flags"]
            recommended_action = "escalate"
            recommended_steps  = ["Submit for deeper static/dynamic analysis", "Check for related artifacts"]
        elif vt_malicious == 1:
            classification = "suspicious"
            confidence     = "low"
            risk_score     = 35
            vendor         = flagged_by[0] if flagged_by else "unknown vendor"
            key_evidence   = [f"Single vendor detection ({vendor})  -  may be a false positive"]
            recommended_action = "investigate"
        else:
            classification = "benign"
            confidence     = "medium"
            risk_score     = 5
            key_evidence   = [f"Clean  -  0/{vt_total} detections in VirusTotal"]
            recommended_action = "allow"

    # -- Email ----------------------------------------------------------------
    elif observable_type == "ip":
        vt_malicious  = vt.get("malicious_count", 0) if vt.get("found") else 0
        vt_total      = vt.get("total_vendors", 0)
        abuseipdb     = threat_feeds.get("abuseipdb") or {}
        abuse_score   = abuseipdb.get("abuse_confidence_score", 0)
        abuse_reports = abuseipdb.get("total_reports", 0)
        tf_matches    = threat_feeds.get("threatfox_matches") or []

        if vt_malicious >= 5 or abuse_score >= 80 or tf_matches:
            classification = "malicious"
            confidence     = "high"
            risk_score     = max(85, min(98, abuse_score))
            if vt_malicious:
                key_evidence.append(f"Flagged malicious by {vt_malicious}/{vt_total} VT vendors")
            if abuse_score:
                key_evidence.append(f"AbuseIPDB confidence: {abuse_score}% ({abuse_reports} reports)")
            if tf_matches:
                key_evidence.append(f"ThreatFox IOC matches: {len(tf_matches)}")
            recommended_action = "block"
            recommended_steps  = ["Block at perimeter firewall", "Review connection logs for this IP"]

        elif vt_malicious >= 2 or abuse_score >= 40:
            classification = "suspicious"
            confidence     = "medium"
            risk_score     = max(45, min(70, abuse_score))
            if vt_malicious:
                key_evidence.append(f"Flagged by {vt_malicious} VT vendors")
            if abuse_score:
                key_evidence.append(f"AbuseIPDB score: {abuse_score}%")
            recommended_action = "investigate"

        else:
            classification = "benign"
            confidence     = "medium"
            risk_score     = 10
            if vt.get("found"):
                key_evidence.append(f"VT clean: 0/{vt_total} detections")
            if abuse_score == 0 and abuse_reports == 0:
                key_evidence.append("No AbuseIPDB reports")
            recommended_action = "monitor"

    # -- Domain / URL ---------------------------------------------------------
    elif observable_type in ("domain", "url"):
        vt_found = vt.get("found", False)
        vt_malicious = vt.get("malicious_count", 0) if vt_found else 0
        vt_suspicious = vt.get("suspicious_count", 0) if vt_found else 0
        vt_total = vt.get("total_vendors", 0)

        intel = evidence_data.get("intel") or {}
        intel_hits = [
            hit for hit in (intel.get("blocklist_hits") or [])
            if str(hit.get("source") or "").strip().lower() != "uribl"
        ]

        tf_matches = threat_feeds.get("threatfox_matches") or []
        openphish_listed = bool(threat_feeds.get("openphish_listed"))
        phishtank = threat_feeds.get("phishtank") or {}
        phishtank_positive = bool(phishtank.get("in_database"))
        phishtank_verified = bool(phishtank.get("verified"))

        http_early = evidence_data.get("http") or {}
        http_phishing = list(http_early.get("phishing_indicators") or [])
        http_has_login = bool(http_early.get("has_login_form"))
        domain_suspicion_context = _has_domain_suspicion_context(evidence_data)
        high_confidence_http_signals = [
            s for s in http_phishing
            if _is_high_confidence_http_phishing_signal(s)
        ]
        contextual_http_signals = [
            s for s in http_phishing
            if _is_contextual_http_phishing_signal(s)
        ]
        http_strong_signals = [
            s for s in http_phishing
            if _is_high_confidence_http_phishing_signal(s)
            or (domain_suspicion_context and _is_contextual_http_phishing_signal(s))
        ]
        http_scored_signals = [
            s for s in http_phishing
            if _is_high_confidence_http_phishing_signal(s)
            or (domain_suspicion_context and not _is_contextual_http_phishing_signal(s))
        ]
        http_phishing_score = len(http_strong_signals) * 2 + len(http_scored_signals)
        weak_signal_score, weak_signal_evidence = _domain_weak_signal_score(
            evidence_data,
            contextual_http=bool(contextual_http_signals),
        )

        # AnyRun TI/sandbox verdict — extract best verdict across all items
        hybrid_evidence = evidence_data.get("hybrid_analysis") or {}
        anyrun_verdict = ""
        anyrun_threat_names: list[str] = []
        _hybrid_items = hybrid_evidence.get("items") if isinstance(hybrid_evidence, dict) else None
        if isinstance(_hybrid_items, list):
            for _item in _hybrid_items:
                if not isinstance(_item, dict):
                    continue
                _v = str(_item.get("verdict") or "").strip().lower()
                _names = list(_item.get("threat_names") or [])
                if _v == "malicious":
                    anyrun_verdict = "malicious"
                    anyrun_threat_names = anyrun_threat_names or _names
                elif _v in {"suspicious"} and anyrun_verdict != "malicious":
                    anyrun_verdict = "suspicious"
                    anyrun_threat_names = anyrun_threat_names or _names
        anyrun_malicious = anyrun_verdict == "malicious"
        anyrun_suspicious = anyrun_verdict == "suspicious"

        if vt_malicious >= 5 or phishtank_verified or tf_matches or openphish_listed or anyrun_malicious:
            classification = "malicious"
            confidence = "high"
            risk_score = 90
            recommended_action = "block"
        elif high_confidence_http_signals and (http_has_login or len(http_phishing) >= 2):
            # Static analysis detected credential harvesting with no external feed confirmation —
            # classify as malicious phishing even when sandbox says clean.
            classification = "malicious"
            confidence = "medium"
            risk_score = 82
            recommended_action = "block"
        elif vt_malicious >= 2 or vt_suspicious >= 5 or len(intel_hits) >= 2 or anyrun_suspicious:
            classification = "suspicious"
            confidence = "medium"
            risk_score = 60
            recommended_action = "investigate"
        elif http_phishing_score >= 3 or (http_strong_signals and http_has_login):
            classification = "suspicious"
            confidence = "medium"
            risk_score = 65
            recommended_action = "investigate"
        elif phishtank_positive:
            classification = "inconclusive"
            confidence = "low"
            risk_score = 30
            recommended_action = "investigate"
        elif http_phishing_score >= 1:
            classification = "suspicious"
            confidence = "low"
            risk_score = 40
            recommended_action = "investigate"
        elif weak_signal_score >= 4:
            classification = "suspicious"
            confidence = "medium"
            risk_score = 50
            recommended_action = "investigate"
        elif weak_signal_score >= 3:
            classification = "suspicious"
            confidence = "low"
            risk_score = 40
            recommended_action = "monitor"
        else:
            classification = "benign"
            confidence = "medium"
            risk_score = 15
            recommended_action = "monitor"

        if anyrun_verdict:
            names_str = (", ".join(anyrun_threat_names[:4]) + " ") if anyrun_threat_names else ""
            key_evidence.append(f"AnyRun TI verdict: {anyrun_verdict.upper()} — {names_str}community threat intelligence")
        if vt_found:
            key_evidence.append(f"VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious of {vt_total}")
        if intel_hits:
            key_evidence.append(f"Intel blocklist hits: {len(intel_hits)}")
        if tf_matches:
            key_evidence.append(f"ThreatFox matches: {len(tf_matches)}")
        if openphish_listed:
            key_evidence.append("OpenPhish listed")
        if phishtank_positive:
            key_evidence.append(
                "PhishTank match"
                + (" (verified)" if phishtank_verified else " (unverified)")
            )
        for sig in http_strong_signals:
            key_evidence.append(f"Static HTTP: {sig}")
        if contextual_http_signals and not domain_suspicion_context:
            key_evidence.append(
                "Static HTTP input/brand observations were treated as contextual because no independent suspicious-domain signal was present"
            )
        key_evidence.extend(weak_signal_evidence)

        whois = evidence_data.get("whois") or {}
        http = evidence_data.get("http") or {}
        email_sec = evidence_data.get("email_security") or {}
        js = evidence_data.get("js_analysis") or {}
        pipeline = evidence_data.get("pipeline_timings_ms") or {}

        domain_age = whois.get("domain_age_days")
        registrar = whois.get("registrar")
        final_url = http.get("final_url")
        email_spoofability = email_sec.get("spoofability_score")
        js_total = js.get("total_requests", 0)
        js_external = js.get("external_requests", 0)

        if anyrun_verdict:
            _names_desc = (f" Threat categories: {', '.join(anyrun_threat_names[:6])}." if anyrun_threat_names else "")
            findings.append({
                "id": "anyrun_verdict",
                "title": f"AnyRun threat intelligence: {anyrun_verdict.upper()}",
                "description": (
                    f"AnyRun community threat intelligence classified this indicator as {anyrun_verdict}.{_names_desc}"
                    " This verdict is based on prior sandbox submissions and community reporting."
                ),
                "severity": "critical" if anyrun_malicious else "high",
                "evidence_refs": ["hybrid_analysis.items"],
            })

        if phishtank_positive:
            findings.append({
                "id": "fallback_phishtank_hit",
                "title": "PhishTank listing observed",
                "description": "Domain/URL was found in PhishTank feed"
                               + (" with verified status." if phishtank_verified else " but not verified."),
                "severity": "high" if phishtank_verified else "medium",
                "evidence_refs": ["threat_feeds.phishtank"],
            })
            if not phishtank_verified:
                data_needed.append("Confirm whether the PhishTank listing is a true positive or stale/unverified entry.")

        if vt_malicious > 0 or vt_suspicious > 0:
            findings.append({
                "id": "fallback_vt_signal",
                "title": "VirusTotal detection signal",
                "description": f"VT reports {vt_malicious} malicious and {vt_suspicious} suspicious detections.",
                "severity": "high" if vt_malicious >= 3 else "medium",
                "evidence_refs": ["vt.malicious_count", "vt.suspicious_count"],
            })

        if http_phishing:
            severity = "high" if high_confidence_http_signals else ("medium" if http_strong_signals else "low")
            desc_parts = [f"Static HTTP analysis identified {len(http_phishing)} content observation(s):"]
            desc_parts += [f"  • {s}" for s in http_phishing[:6]]
            if http_has_login:
                desc_parts.append("  • Login/account input field present on page")
            if contextual_http_signals and not domain_suspicion_context:
                desc_parts.append(
                    "  • Input fields and third-party brand references are common on legitimate sites and were not used to raise risk without independent suspicious-domain context"
                )
            findings.append({
                "id": "static_http_phishing",
                "title": "Static HTTP content observations detected",
                "description": " ".join(desc_parts),
                "severity": severity,
                "evidence_refs": ["http.phishing_indicators", "http.has_login_form"],
            })

        if weak_signal_score >= 3:
            findings.append({
                "id": "weak_signal_cluster",
                "title": "Suspicious weak-signal cluster",
                "description": "Multiple medium-confidence signals combine into suspicious context: " + "; ".join(weak_signal_evidence[:6]),
                "severity": "medium" if weak_signal_score >= 4 else "low",
                "evidence_refs": ["url_lexical_ml", "signals", "infrastructure_pivot", "email_security"],
            })

        if email_spoofability in {"high", "medium"}:
            findings.append({
                "id": "fallback_email_spoofability",
                "title": "Email spoofability exposure",
                "description": f"Email security posture indicates spoofability score: {email_spoofability}.",
                "severity": "medium",
                "evidence_refs": ["email_security.spoofability_score"],
            })

        redirect_count = len(http.get("redirect_chain") or [])
        if redirect_count >= 3:
            findings.append({
                "id": "fallback_redirect_chain",
                "title": "Long redirect chain observed",
                "description": f"HTTP probing observed {redirect_count} redirect hops before final destination.",
                "severity": "medium",
                "evidence_refs": ["http.redirect_chain"],
            })

        if (domain_age or 0) > 0 and (domain_age or 0) <= 30:
            findings.append({
                "id": "fallback_young_domain",
                "title": "Recently registered domain",
                "description": f"WHOIS indicates the domain is {domain_age} days old.",
                "severity": "medium",
                "evidence_refs": ["whois.domain_age_days"],
            })

        if js_total >= 50 and js_external >= 10:
            findings.append({
                "id": "fallback_high_js_external",
                "title": "Elevated external JavaScript activity",
                "description": (
                    f"Browser telemetry captured {js_total} requests, including {js_external} to external domains."
                ),
                "severity": "low",
                "evidence_refs": ["js_analysis.total_requests", "js_analysis.external_requests"],
            })

        if not findings:
            findings.append({
                "id": "fallback_no_high_risk_findings",
                "title": "No high-risk technical findings detected",
                "description": (
                    "Automated checks across reputation, DNS/WHOIS age, HTTP behavior, "
                    "email controls, and JavaScript telemetry did not produce high-confidence malicious indicators."
                ),
                "severity": "info",
                "evidence_refs": [
                    "vt",
                    "threat_feeds",
                    "whois.domain_age_days",
                    "http.redirect_chain",
                    "email_security.spoofability_score",
                    "js_analysis.total_requests",
                ],
            })

        if classification == "benign":
            legitimate_explanation = (
                "Registration, hosting, and observed web behavior are consistent with normal operations. "
                "No strong malicious indicators were confirmed across the primary telemetry sources."
            )
            malicious_explanation = (
                "Limited weak indicators may exist in open-source feeds, but evidence does not support "
                "a high-confidence malicious conclusion at this time."
            )
            recommended_steps = [
                "Keep the observable in passive monitoring for 7-14 days.",
                "Track certificate and DNS changes for sudden infrastructure shifts.",
                "Alert only if verified malicious feed matches appear.",
            ]
        elif classification == "inconclusive":
            legitimate_explanation = (
                "Some telemetry appears consistent with legitimate usage, but confidence is reduced due to "
                "conflicting or unverified threat-feed signals."
            )
            malicious_explanation = (
                "Unverified phishing/reputation indicators suggest potential risk, but current evidence is insufficient "
                "for a definitive malicious classification."
            )
            recommended_steps = [
                "Validate external feed matches (especially PhishTank/OpenPhish) with manual review.",
                "Correlate with internal telemetry (proxy, DNS, EDR) for real user impact.",
                "Re-run investigation if infrastructure/content changes are observed.",
            ]
        else:
            legitimate_explanation = (
                "Some baseline signals may resemble legitimate behavior, but they are outweighed by risk indicators."
            )
            malicious_explanation = (
                "Multiple threat and behavior signals indicate suspicious or malicious characteristics requiring action."
            )
            recommended_steps = [
                "Open an incident ticket and escalate for SOC validation.",
                "Block or heavily monitor the observable at perimeter controls.",
                "Hunt for related indicators in recent logs and endpoint telemetry.",
            ]

        exec_bits = [
            f"Observable: {domain} ({observable_type})",
            f"Classification: {classification.upper()} ({confidence} confidence), risk {risk_score}/100.",
        ]
        if registrar:
            exec_bits.append(f"Registrar: {registrar}.")
        if domain_age is not None:
            exec_bits.append(f"Domain age: {domain_age} days.")
        if final_url:
            exec_bits.append(f"Final URL observed: {final_url}.")
        if key_evidence:
            exec_bits.append("Key evidence: " + "; ".join(key_evidence[:4]))
        executive_summary = " ".join(exec_bits)

        _anyrun_narrative = ""
        if anyrun_verdict:
            _names_str = (", ".join(anyrun_threat_names[:4]) if anyrun_threat_names else "")
            _anyrun_narrative = (
                f" AnyRun TI verdict: {anyrun_verdict.upper()}"
                + (f" ({_names_str})" if _names_str else "") + "."
            )
        technical_narrative = (
            f"Network and web telemetry show reachable={bool(http.get('reachable'))}, "
            f"redirects={len(http.get('redirect_chain') or [])}, and JS activity "
            f"{js_total} requests ({js_external} external). "
            f"Email posture is spoofability={email_spoofability or 'unknown'}. "
            f"Threat feeds: PhishTank={phishtank_positive} "
            f"(verified={phishtank_verified}), OpenPhish={openphish_listed}, "
            f"ThreatFox matches={len(tf_matches)}.{_anyrun_narrative} "
            f"Pipeline timings (ms): report_generation={pipeline.get('report_generation')}, "
            f"browser_postprocessing={pipeline.get('browser_postprocessing')}."
        )
        recommendations_narrative = " ".join(
            [f"{idx + 1}. {step}" for idx, step in enumerate(recommended_steps)]
        )

    # -- Build summary text ---------------------------------------------------
    evidence_str = "; ".join(key_evidence) if key_evidence else "No significant threat indicators found."
    risk_str     = f"Risk score: {risk_score}/100." if risk_score is not None else "Risk score undetermined."
    summary      = (
        f"Automated analysis for {observable_type.upper()}  -  {domain}. "
        f"Classification: {classification.upper()} ({confidence} confidence). "
        f"{risk_str} Key evidence: {evidence_str}"
    )
    if not executive_summary:
        executive_summary = summary
    if not technical_narrative:
        technical_narrative = summary
    if not legitimate_explanation:
        legitimate_explanation = (
            "" if classification == "malicious"
            else f"No significant threat indicators found for this {observable_type}."
        )
    if not malicious_explanation:
        malicious_explanation = evidence_str if classification != "benign" else ""
    if not recommendations_narrative:
        recommendations_narrative = (
            f"Recommended action: {recommended_action}. "
            + (" ".join(recommended_steps) if recommended_steps else "No additional steps required.")
        )

    report = {
        "classification": classification,
        "confidence": confidence,
        "investigation_state": "concluded",
        "primary_reasoning": summary,
        "legitimate_explanation": legitimate_explanation,
        "malicious_explanation": malicious_explanation,
        "key_evidence": key_evidence,
        "contradicting_evidence": [],
        "data_needed": data_needed,
        "findings": findings,
        "iocs": _build_iocs_from_evidence(evidence_data, observable_type),
        "recommended_action": recommended_action,
        "recommended_steps": recommended_steps,
        "risk_score": risk_score,
        "risk_rationale": evidence_str,
        "executive_summary": executive_summary,
        "technical_narrative": technical_narrative,
        "recommendations_narrative": recommendations_narrative,
    }
    return apply_decision_to_report(report, build_decision_report(evidence_data, observable_type))


def _build_iocs_from_evidence(evidence_data: dict, observable_type: str) -> list[dict]:
    """
    Build IOC list directly from collected technical evidence.
    """
    iocs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add_ioc(ioc_type: str, value: str, context: str, confidence: str = "medium") -> bool:
        if len(iocs) >= MAX_IOCS_PER_REPORT:
            return False
        normalized = _normalize_ioc_for_storage({
            "type": ioc_type,
            "value": value,
            "context": context,
            "confidence": confidence,
        })
        if normalized is None:
            return False
        key = (normalized["type"], normalized["value"].lower())
        if key in seen:
            return False
        seen.add(key)
        iocs.append(normalized)
        return True

    observable = (evidence_data.get("domain") or "").strip()
    if observable_type == "domain":
        add_ioc("domain", observable, "Investigated domain", "high")
        http = evidence_data.get("http") or {}
        final_url = str(http.get("final_url") or "").strip()
        if final_url:
            add_ioc("url", final_url, "HTTP final URL", "medium")
    elif observable_type == "url":
        add_ioc("url", observable, "Investigated URL", "high")
        try:
            from urllib.parse import urlparse as _urlparse
            _hostname = (_urlparse(observable).hostname or "").strip()
            if _hostname:
                add_ioc("domain", _hostname, "Hostname extracted from investigated URL", "high")
        except Exception:
            pass
    elif observable_type == "ip":
        add_ioc("ip", observable, "Investigated IP", "high")
    elif observable_type in ("hash", "file"):
        add_ioc("hash", observable, "Investigated sample/hash", "high")

    http = evidence_data.get("http") or {}
    final_url = (http.get("final_url") or "").strip()
    if final_url:
        add_ioc("url", final_url, "Final URL observed during HTTP probing", "medium")
    for hop in (http.get("redirect_chain") or [])[:5]:
        hop_url = (hop.get("url") if isinstance(hop, dict) else None) or ""
        if hop_url:
            add_ioc("url", str(hop_url), "HTTP redirect chain", "low")

    dns = evidence_data.get("dns") or {}
    for ipv4 in (dns.get("a") or [])[:10]:
        add_ioc("ip", str(ipv4), "Resolved A record", "medium")
    for ipv6 in (dns.get("aaaa") or [])[:10]:
        add_ioc("ip", str(ipv6), "Resolved AAAA record", "low")

    hosting = evidence_data.get("hosting") or {}
    if hosting.get("ip"):
        add_ioc("ip", str(hosting.get("ip")), "Hosting IP", "medium")

    urlscan = evidence_data.get("urlscan") or {}
    if urlscan.get("page_url"):
        add_ioc("url", str(urlscan.get("page_url")), "URLScan observed page URL", "medium")
    if urlscan.get("page_ip"):
        add_ioc("ip", str(urlscan.get("page_ip")), "URLScan observed page IP", "medium")

    # ThreatFox IOC matches from threat_feeds collector.
    threat_feeds = evidence_data.get("threat_feeds") or {}
    for match in (threat_feeds.get("threatfox_matches") or []):
        ioc_type = str(match.get("ioc_type") or "").lower()
        ioc_value = str(match.get("ioc_value") or "").strip()
        if ioc_type in {"ip", "domain", "url", "hash", "email"}:
            add_ioc(ioc_type, ioc_value, "ThreatFox match", "high")
    # IP threat intelligence pivots.
    abuse = threat_feeds.get("abuseipdb") or {}
    if abuse.get("ip"):
        add_ioc("ip", abuse["ip"], "AbuseIPDB lookup target", "medium")

    # AnyRun sandbox IOC report — domains/IPs/URLs observed during live detonation.
    hybrid = evidence_data.get("hybrid_analysis") or {}
    anyrun_extracted_added = 0
    anyrun_raw_added = 0
    for _item in (hybrid.get("items") or [])[:3]:
        if not isinstance(_item, dict):
            continue
        _sandbox_intel = _item.get("sandbox_intelligence") or {}
        for _ioc in (_sandbox_intel.get("extracted_iocs") or [])[:100]:
            if anyrun_extracted_added >= MAX_ANYRUN_EXTRACTED_IOCS:
                break
            if not isinstance(_ioc, dict):
                continue
            _ioc_type = str(_ioc.get("type") or "").strip().lower()
            _ioc_val = str(_ioc.get("value") or "").strip()
            if _ioc_type in {"domain", "ip", "url", "hash", "email"}:
                if add_ioc(
                    _ioc_type,
                    _ioc_val,
                    str(_ioc.get("context") or "AnyRun sandbox extracted IOC"),
                    str(_ioc.get("confidence") or "medium"),
                ):
                    anyrun_extracted_added += 1
        _raw = _item.get("raw_summary") or {}
        for _ioc in (_raw.get("iocs") or [])[:50]:
            if anyrun_raw_added >= MAX_ANYRUN_RAW_IOCS:
                break
            if not isinstance(_ioc, dict):
                continue
            _ioc_val = str(_ioc.get("ioc") or _ioc.get("value") or "").strip()
            _ioc_cat = str(_ioc.get("category") or "").strip().lower()
            _ioc_type = str(_ioc.get("type") or "").strip().lower()
            if not _ioc_val:
                continue
            # Map AnyRun IOC categories to standard types
            if _ioc_cat in {"domain", "domains"} or _ioc_type in {"domain", "hostname"}:
                if add_ioc("domain", _ioc_val, "AnyRun sandbox — contacted domain", "medium"):
                    anyrun_raw_added += 1
            elif _ioc_cat in {"ip", "network"} or _ioc_type in {"ip", "ipv4", "ipv6"}:
                if add_ioc("ip", _ioc_val, "AnyRun sandbox — contacted IP", "medium"):
                    anyrun_raw_added += 1
            elif _ioc_cat in {"url", "http"} or _ioc_type == "url":
                if add_ioc("url", _ioc_val, "AnyRun sandbox — HTTP request", "medium"):
                    anyrun_raw_added += 1

    return iocs


def _ensure_report_completeness(report_data: dict, evidence_data: dict, observable_type: str) -> dict:
    """
    Ensure report always has baseline analyst content even if AI output is sparse.
    """
    if not isinstance(report_data, dict):
        report_data = {}

    normalized = dict(report_data)
    fallback = _generate_automated_report(evidence_data, observable_type)

    def _blank(value: object) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return not value.strip()
        if isinstance(value, (list, dict, tuple, set)):
            return len(value) == 0
        return False

    # Always guarantee required keys exist.
    for key, value in fallback.items():
        normalized.setdefault(key, value)

    if _blank(normalized.get("primary_reasoning")):
        narrative_primary = (
            normalized.get("executive_summary")
            or normalized.get("technical_narrative")
            or normalized.get("recommendations_narrative")
        )
        if not _blank(narrative_primary):
            normalized["primary_reasoning"] = str(narrative_primary).strip()

    # Backfill commonly missing sections that power UI/PDF tabs.
    for key in (
        "findings",
        "iocs",
        "key_evidence",
        "recommended_steps",
        "executive_summary",
        "technical_narrative",
        "recommendations_narrative",
    ):
        if _blank(normalized.get(key)):
            normalized[key] = fallback.get(key)

    # Keep primary reasoning short and SOC-usable even when model output is verbose.
    reasoning_text = str(normalized.get("primary_reasoning") or "")
    if _should_simplify_primary_reasoning(reasoning_text, observable_type):
        normalized["primary_reasoning"] = str(fallback.get("primary_reasoning") or reasoning_text).strip()

    return normalized


def _should_simplify_primary_reasoning(text: str, observable_type: str | None = None) -> bool:
    if not text:
        return False
    compact = " ".join(text.split()).lower()
    if observable_type in {"domain", "url", "email"}:
        noisy_markers = (
            "attacker-necessity",
            "satisfying the",
            "hypothesis comparison",
            "(1)",
            "(2)",
            "(3)",
        )
        return any(marker in compact for marker in noisy_markers)
    if len(compact) > 420:
        return True
    noisy_markers = (
        "attacker-necessity",
        "satisfying the",
        "hypothesis comparison",
        "(1)",
        "(2)",
        "(3)",
    )
    return any(marker in compact for marker in noisy_markers)


def _apply_phishing_redirect_risk_floor(report_data: dict, evidence_data: dict, observable_type: str) -> None:
    """
    Raise risk when a newly created domain redirects cross-domain to an established destination,
    a common phishing lure pattern.
    """
    if observable_type not in {"domain", "url"} or not isinstance(report_data, dict):
        return

    whois = evidence_data.get("whois") or {}
    http = evidence_data.get("http") or {}
    investigated = str(evidence_data.get("domain") or "").strip().lower()
    final_url = str(http.get("final_url") or "").strip()
    domain_age_days = whois.get("domain_age_days")

    if not investigated or not final_url:
        return
    if not isinstance(domain_age_days, int) or domain_age_days < 0:
        return

    try:
        final_host = (urlparse(final_url).hostname or "").strip().lower()
    except Exception:
        final_host = ""
    if not final_host:
        return

    investigated_host = investigated
    if "://" in investigated:
        try:
            investigated_host = (urlparse(investigated).hostname or investigated).strip().lower()
        except Exception:
            investigated_host = investigated

    investigated_root = extract_registered_domain(investigated_host) or investigated_host
    final_root = extract_registered_domain(final_host) or final_host
    if investigated_root == final_root:
        return

    if domain_age_days > 120:
        return

    # Suspicious redirect pattern confirmed: young domain + cross-domain redirect.
    current_score = report_data.get("risk_score")
    try:
        numeric_score = int(current_score) if current_score is not None else 0
    except Exception:
        numeric_score = 0
    report_data["risk_score"] = max(65, numeric_score)

    classification = str(report_data.get("classification") or "").lower()
    if classification in {"benign", "inconclusive", ""}:
        report_data["classification"] = "suspicious"
    confidence = str(report_data.get("confidence") or "").lower()
    if confidence in {"low", ""}:
        report_data["confidence"] = "medium"
    action = str(report_data.get("recommended_action") or "").lower()
    if action in {"monitor", "", "allow"}:
        report_data["recommended_action"] = "investigate"

    findings = report_data.get("findings")
    if not isinstance(findings, list):
        findings = []
    if not any(isinstance(f, dict) and str(f.get("id")) == "young_cross_domain_redirect" for f in findings):
        findings.append(
            {
                "id": "young_cross_domain_redirect",
                "title": "Young domain redirects to different root domain",
                "description": (
                    f"WHOIS age is {domain_age_days} days and HTTP final URL resolves to "
                    f"{final_root} (different from investigated root {investigated_root}). "
                    "This redirect-lure pattern is consistent with phishing pretext infrastructure."
                ),
                "severity": "high" if domain_age_days <= 45 else "medium",
                "evidence_refs": ["whois.domain_age_days", "http.final_url"],
            }
        )
    report_data["findings"] = findings

    key_evidence = report_data.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = []
    redirect_line = (
        f"Young domain ({domain_age_days} days) redirects to different root: "
        f"{investigated_root} -> {final_root}"
    )
    if redirect_line not in key_evidence:
        key_evidence.append(redirect_line)
    report_data["key_evidence"] = key_evidence


def _is_parser_fallback_report(report_data: dict) -> bool:
    if not isinstance(report_data, dict):
        return False
    reason = str(report_data.get("primary_reasoning") or "").strip().lower()
    findings = report_data.get("findings") or []
    iocs = report_data.get("iocs") or []
    classification = str(report_data.get("classification") or "").strip().lower()
    return (
        "could not be parsed into structured format" in reason
        and not findings
        and not iocs
        and classification in {"", "inconclusive"}
    )


def _inject_lexical_contribution(report_data: dict, evidence_data: dict) -> None:
    """
    Ensure lexical ML appears in Findings and contributes 20-30% to final risk score.
    """
    if not isinstance(report_data, dict):
        return
    lexical = evidence_data.get("url_lexical_ml") or {}
    if not isinstance(lexical, dict) or not lexical:
        return

    lexical_score = float(lexical.get("score") or 0.0)
    lexical_raw = float(lexical.get("raw_score") or lexical_score)
    lexical_label = str(lexical.get("label") or "unknown").lower()
    top = [str(x) for x in (lexical.get("top_features") or []) if str(x).strip()]
    model_source = str(lexical.get("model_source") or "unknown")
    calibrated = bool(lexical.get("calibration_applied"))
    lexical_weight = 0.25

    rep_score = report_data.get("risk_score")
    rep_norm = 0.5 if rep_score is None else max(0.0, min(1.0, float(rep_score) / 100.0))
    blended = (1.0 - lexical_weight) * rep_norm + lexical_weight * lexical_score
    blended_score = int(round(blended * 100))

    floor_score, floor_reasons = _trusted_external_risk_floor(evidence_data)
    if floor_score and blended_score < floor_score:
        blended_score = floor_score
        cls = str(report_data.get("classification") or "").lower()
        if floor_score >= 85:
            report_data["classification"] = "malicious"
            report_data["confidence"] = "high"
            report_data["recommended_action"] = "block"
        elif cls in {"", "benign", "inconclusive"}:
            report_data["classification"] = "suspicious"
            if str(report_data.get("confidence") or "").lower() in {"", "low"}:
                report_data["confidence"] = "medium"
            if str(report_data.get("recommended_action") or "").lower() in {"", "allow", "monitor"}:
                report_data["recommended_action"] = "investigate"

    existing = report_data.get("findings")
    findings = existing if isinstance(existing, list) else []
    if not any(isinstance(f, dict) and str(f.get("id")) == "lexical_ml_contribution" for f in findings):
        sev = "high" if lexical_label == "high" else ("medium" if lexical_label == "medium" else "low")
        findings.append(
            {
                "id": "lexical_ml_contribution",
                "title": "URL lexical ML risk contribution",
                "description": (
                    f"Lexical model ({model_source}) scored this target as {lexical_label.upper()} "
                    f"(raw={lexical_raw:.4f}, calibrated={lexical_score:.4f}, weight={lexical_weight:.2f}). "
                    f"Top features: {', '.join(top[:5]) if top else 'not available'}."
                ),
                "severity": sev,
                "evidence_refs": ["url_lexical_ml.score", "url_lexical_ml.top_features"],
            }
        )
        report_data["findings"] = findings

    key = report_data.get("key_evidence")
    key_evidence = key if isinstance(key, list) else []
    lexical_line = (
        f"Lexical ML ({model_source}) {lexical_label} risk "
        f"(raw={lexical_raw:.4f}, calibrated={lexical_score:.4f}"
        + (", calibration=on" if calibrated else ", calibration=off")
        + ")"
    )
    if lexical_line not in key_evidence:
        key_evidence.append(lexical_line)
    if floor_reasons:
        floor_line = (
            f"Trusted external intelligence floor applied at {blended_score}/100 due to: "
            + "; ".join(floor_reasons)
        )
        if floor_line not in key_evidence:
            key_evidence.append(floor_line)
        report_data["key_evidence"] = key_evidence

    # Apply blended score only when a numeric score exists or can be inferred.
    report_data["risk_score"] = blended_score
    rationale = str(report_data.get("risk_rationale") or "").strip()
    blend_note = (
        f"Final risk uses blended scoring: reputation_weight=0.75, lexical_weight=0.25, "
        f"reputation_component={rep_norm:.4f}, lexical_component={lexical_score:.4f}, final={blended:.4f}."
    )
    if floor_reasons:
        blend_note += f" External intelligence floor enforced at {blended_score}/100."
    report_data["risk_rationale"] = (rationale + " " + blend_note).strip()


def _trusted_external_risk_floor(evidence_data: dict) -> tuple[int, list[str]]:
    """
    Determine minimum risk score floor from trusted external sources
    (VirusTotal, URLScan, Hybrid Analysis) to avoid over-dilution by lexical ML.
    """
    strong_hits = 0
    medium_hits = 0
    reasons: list[str] = []

    vt = evidence_data.get("vt") or {}
    vt_malicious = int(vt.get("malicious_count") or 0)
    vt_suspicious = int(vt.get("suspicious_count") or 0)
    if vt_malicious >= 10:
        strong_hits += 1
        reasons.append(f"VirusTotal high malicious detections ({vt_malicious})")
    elif vt_malicious >= 5 or vt_suspicious >= 10:
        medium_hits += 1
        reasons.append(f"VirusTotal elevated detections (m={vt_malicious}, s={vt_suspicious})")

    urlscan = evidence_data.get("urlscan") or {}
    urlscan_verdict = str(urlscan.get("verdict") or "").strip().lower()
    try:
        urlscan_score = float(urlscan.get("score") or 0.0)
    except Exception:
        urlscan_score = 0.0
    if urlscan_verdict == "malicious" and urlscan_score >= 70:
        strong_hits += 1
        reasons.append(f"URLScan malicious verdict ({urlscan_score:.0f}/100)")
    elif urlscan_verdict in {"malicious", "suspicious"} or urlscan_score >= 40:
        medium_hits += 1
        reasons.append(f"URLScan risk signal ({urlscan_verdict or 'score-only'} {urlscan_score:.0f}/100)")

    hybrid = evidence_data.get("hybrid_analysis") or {}
    hybrid_verdict = str(hybrid.get("verdict") or "").strip().lower()
    try:
        hybrid_score = float(hybrid.get("score") or 0.0)
    except Exception:
        hybrid_score = 0.0
    items = hybrid.get("items") if isinstance(hybrid, dict) else None
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            v = str(item.get("verdict") or "").strip().lower()
            try:
                s = float(item.get("score") or 0.0)
            except Exception:
                s = 0.0
            if not hybrid_verdict and v:
                hybrid_verdict = v
            if s > hybrid_score:
                hybrid_score = s

    if hybrid_verdict == "malicious" or hybrid_score >= 70:
        strong_hits += 1
        reasons.append(f"Hybrid Analysis malicious/high score ({hybrid_score:.0f}/100)")
    elif hybrid_verdict in {"suspicious"} or hybrid_score >= 40:
        medium_hits += 1
        reasons.append(f"Hybrid Analysis suspicious signal ({hybrid_score:.0f}/100)")

    if strong_hits >= 2:
        return 90, reasons
    if strong_hits >= 1:
        return 80, reasons
    if medium_hits >= 2:
        return 70, reasons
    return 0, []


def _is_contextual_http_phishing_signal(signal: object) -> bool:
    text = str(signal or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "email-only input",
            "credential or account input fields",
            "third-party brand reference",
            "brand impersonation",
        )
    )


def _is_high_confidence_http_phishing_signal(signal: object) -> bool:
    text = str(signal or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "form posts to external domain",
            "telegram bot api",
            "hardcoded external url",
            "credential exfiltration",
            "clickfix fake captcha",
            "paste/run a command",
        )
    )


def _domain_weak_signal_score(evidence_data: dict, *, contextual_http: bool = False) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    lexical = evidence_data.get("url_lexical_ml") or {}
    if not isinstance(lexical, dict) or not lexical:
        lexical = (evidence_data.get("ml_url_score") or {}).get("raw") or evidence_data.get("ml_url_score") or {}
    if isinstance(lexical, dict):
        label = str(lexical.get("label") or lexical.get("risk_level") or "").lower()
        try:
            lexical_score = float(lexical.get("score") or lexical.get("phishing_probability") or 0.0)
        except Exception:
            lexical_score = 0.0
        top_features = [str(x).lower() for x in (lexical.get("top_features") or [])]
        if label == "high" or lexical_score >= 0.65:
            score += 2
            reasons.append(f"Lexical model high risk ({lexical_score:.2f})")
        elif label == "medium" or lexical_score >= 0.45:
            score += 1
            reasons.append(f"Lexical model medium risk ({lexical_score:.2f})")
        if "has_sensitive_keyword" in top_features:
            score += 1
            reasons.append("Hostname contains a sensitive keyword such as secure/login/account")

    email = evidence_data.get("email_security") or {}
    if isinstance(email, dict) and str(email.get("spoofability_score") or "").lower() == "high":
        score += 1
        reasons.append("High email spoofability")

    infra = evidence_data.get("infrastructure_pivot") or {}
    if isinstance(infra, dict):
        if infra.get("shared_hosting_detected"):
            score += 1
            reasons.append("Shared hosting or crowded infrastructure observed")
        if infra.get("registrant_pivots"):
            score += 1
            reasons.append("Registrant/registrar pivot links to other investigated domains")

    signals = evidence_data.get("signals") or []
    if isinstance(signals, list):
        signal_ids = {
            str(sig.get("id") or "")
            for sig in signals
            if isinstance(sig, dict)
        }
        if "sig_high_spoofability" in signal_ids and "High email spoofability" not in reasons:
            score += 1
            reasons.append("High email spoofability")
        if {"sig_shared_hosting", "sig_registrant_pivot"} & signal_ids and not any("infrastructure" in r for r in reasons):
            score += 1
            reasons.append("Infrastructure pivot signal observed")

    if contextual_http:
        score += 1
        reasons.append("Static HTTP brand/input observation present")

    return score, reasons


def _has_domain_suspicion_context(evidence_data: dict) -> bool:
    vt = evidence_data.get("vt") or {}
    if int(vt.get("malicious_count") or 0) > 0 or int(vt.get("suspicious_count") or 0) >= 3:
        return True

    threat_feeds = evidence_data.get("threat_feeds") or {}
    if threat_feeds.get("openphish_listed") or (threat_feeds.get("threatfox_matches") or []):
        return True
    phishtank = threat_feeds.get("phishtank") or {}
    if phishtank.get("verified"):
        return True

    intel = evidence_data.get("intel") or {}
    blocklist_hits = [
        hit for hit in (intel.get("blocklist_hits") or [])
        if str((hit or {}).get("source") or "").strip().lower() != "uribl"
    ]
    if blocklist_hits:
        return True

    hybrid = evidence_data.get("hybrid_analysis") or {}
    if str(hybrid.get("verdict") or "").strip().lower() in {"malicious", "suspicious"}:
        return True
    items = hybrid.get("items")
    if isinstance(items, list) and any(
        isinstance(item, dict)
        and str(item.get("verdict") or "").strip().lower() in {"malicious", "suspicious"}
        for item in items
    ):
        return True

    similarity = evidence_data.get("domain_similarity") or {}
    if float(similarity.get("overall_similarity_score") or 0) >= 50:
        return True

    visual = evidence_data.get("visual_comparison") or {}
    if visual.get("is_visual_clone"):
        return True

    whois = evidence_data.get("whois") or {}
    age_days = whois.get("domain_age_days")
    if isinstance(age_days, int) and 0 <= age_days <= 30:
        return True

    redirect = evidence_data.get("redirect_analysis") or {}
    if redirect.get("cloaking_detected"):
        return True

    return False


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _run_analyst_sync(
    evidence_data: dict,
    max_iterations: int,
    timeout_seconds: int,
) -> tuple[dict, str]:
    """
    Synchronous wrapper for the async LLM analyst call.
    Celery workers are sync, so we run the async code in a new event loop.
    Returns (report_dict, actual_model_id).
    """
    import asyncio
    from app.models.schemas import CollectedEvidence
    from app.analyst.orchestrator import run_analyst

    evidence_obj = CollectedEvidence(**evidence_data)

    loop = asyncio.new_event_loop()
    try:
        report, actual_model = loop.run_until_complete(
            asyncio.wait_for(
                run_analyst(evidence_obj, iteration=0, max_iterations=max_iterations),
                timeout=timeout_seconds,
            )
        )
        report_dict = report.model_dump(mode="json")

        # Enrich findings with MITRE ATT&CK metadata
        try:
            from app.analyst.attack_mapping import enrich_findings_with_attack
            if report_dict.get("findings"):
                report_dict["findings"] = enrich_findings_with_attack(report_dict["findings"])
        except Exception:
            pass  # ATT&CK enrichment is non-critical

        return report_dict, actual_model
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
            if not inv:
                logger.error(
                    f"[{investigation_id}] Investigation not found in DB  -  skipping persist. "
                    "This task may be a stale re-queue for a deleted/reset investigation."
                )
                return
            if str(inv.state or "").lower() == "cancelled":
                logger.info("[%s] Skip persist because investigation is cancelled.", investigation_id)
                return

            inv.state = "concluded"
            inv.concluded_at = datetime.now(timezone.utc)
            inv.classification = report_data.get("classification")
            inv.confidence = report_data.get("confidence")
            inv.risk_score = report_data.get("risk_score")
            inv.recommended_action = report_data.get("recommended_action")

            # Save or update evidence (one row per investigation_id).
            ev = session.execute(
                select(Evidence).where(Evidence.investigation_id == inv_id)
            ).scalar_one_or_none()
            if ev is None:
                ev = Evidence(
                    investigation_id=inv_id,
                    evidence_json=evidence_data,
                    signals=evidence_data.get("signals", []),
                    data_gaps=evidence_data.get("data_gaps", []),
                    external_context=evidence_data.get("external_context"),
                )
                session.add(ev)
            else:
                ev.evidence_json = evidence_data
                ev.signals = evidence_data.get("signals", [])
                ev.data_gaps = evidence_data.get("data_gaps", [])
                ev.external_context = evidence_data.get("external_context")

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

            # Save or update collector results (one row per collector per investigation).
            existing_collector_results = {
                row.collector_name: row
                for row in session.execute(
                    select(CollectorResult).where(CollectorResult.investigation_id == inv_id)
                ).scalars()
            }

            for name, status in collector_statuses.items():
                field_name = COLLECTOR_FIELD_MAP.get(name, name)
                col_evidence = evidence_data.get(field_name, {})
                cr = existing_collector_results.get(name)
                if cr is None:
                    cr = CollectorResult(
                        investigation_id=inv_id,
                        collector_name=name,
                        status=status,
                        evidence_json=col_evidence,
                        duration_ms=col_evidence.get("meta", {}).get("duration_ms"),
                    )
                    session.add(cr)
                else:
                    cr.status = status
                    cr.evidence_json = col_evidence
                    cr.duration_ms = col_evidence.get("meta", {}).get("duration_ms")

            # Extract IOCs from report and persist to iocs table.
            # Keep this defensive: a single oversized/noisy IOC should not leave
            # an otherwise completed investigation stuck in evaluating.
            persisted_iocs: set[tuple[str, str]] = set()
            for ioc in (report_data.get("iocs", []) or [])[:MAX_IOCS_PER_REPORT]:
                normalized_ioc = _normalize_ioc_for_storage(ioc)
                if normalized_ioc is None:
                    continue
                ioc_key = (normalized_ioc["type"], normalized_ioc["value"].lower())
                if ioc_key in persisted_iocs:
                    continue
                persisted_iocs.add(ioc_key)
                session.add(IOCRecord(
                    investigation_id=inv_id,
                    type=normalized_ioc["type"],
                    value=normalized_ioc["value"],
                    context=normalized_ioc["context"],
                    confidence=normalized_ioc["confidence"],
                ))

            # Save WHOIS history snapshot
            # Use target_domain (hostname extracted from URL for URL type) so WHOIS
            # history is keyed on the domain, not the full URL.
            domain = evidence_data.get("target_domain") or (inv.domain if inv else None)
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

            # -- Client Alert Check --------------------------------------
            if inv:
                try:
                    _check_client_alerts_sync(session, inv, report_data)
                except Exception as e:
                    logger.warning(f"[{investigation_id}] Client alert check failed: {e}")

            # Update batch progress if this investigation belongs to a batch
            if inv and inv.batch_id:
                _update_batch_progress(session, inv.batch_id)

    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to persist results: {e}")


def _align_final_risk_with_report(evidence_data: dict, report_data: dict) -> None:
    """
    Keep evidence.final_risk aligned with the persisted report verdict.

    The component aggregator remains useful as a model view, but the report score
    is the decision score analysts see in lists, exports, and summary tabs.
    """
    if not isinstance(evidence_data, dict) or not isinstance(report_data, dict):
        return
    final_risk = evidence_data.get("final_risk")
    if not isinstance(final_risk, dict):
        return
    report_score = report_data.get("risk_score")
    try:
        risk_score = int(report_score)
    except Exception:
        return

    if "composite_risk_score" not in final_risk:
        final_risk["composite_risk_score"] = final_risk.get("risk_score")
    if "composite_risk_level" not in final_risk:
        final_risk["composite_risk_level"] = final_risk.get("risk_level")

    final_risk["risk_score"] = max(0, min(100, risk_score))
    final_risk["risk_level"] = (
        "high" if final_risk["risk_score"] >= 70
        else "medium" if final_risk["risk_score"] >= 35
        else "low"
    )
    final_risk["source"] = "report_decision"
    rationale = final_risk.get("rationale")
    if isinstance(rationale, list):
        note = "Final risk aligned to persisted report decision score"
        if note not in rationale:
            rationale.append(note)


def recompute_report_for_existing_investigation(
    investigation_id: str,
    *,
    reason: str = "evidence_updated",
) -> dict | None:
    """
    Rebuild the deterministic report after evidence changes post-conclusion.

    This is intentionally non-LLM: collector re-runs and deferred sandbox results
    need a fast, repeatable verdict refresh without spending another analyst call.
    """
    try:
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session
        from app.db.session import sync_engine
        from app.models.database import Evidence, Investigation, Report
        import uuid

        inv_id = uuid.UUID(investigation_id)
        with Session(sync_engine) as session:
            inv = session.get(Investigation, inv_id)
            if inv is None:
                logger.warning("[%s] Recompute skipped: investigation not found", investigation_id)
                return None

            evidence_row = session.execute(
                select(Evidence).where(Evidence.investigation_id == inv_id)
            ).scalar_one_or_none()
            if evidence_row is None:
                logger.warning("[%s] Recompute skipped: evidence not found", investigation_id)
                return None

            evidence_data = (
                json.loads(evidence_row.evidence_json)
                if isinstance(evidence_row.evidence_json, str)
                else dict(evidence_row.evidence_json or {})
            )
            observable_type = str(inv.observable_type or evidence_data.get("observable_type") or "domain")
            domain = str(inv.domain or evidence_data.get("domain") or "")
            evidence_data.setdefault("domain", domain)
            evidence_data.setdefault("observable_type", observable_type)
            evidence_data.setdefault("investigation_id", investigation_id)

            signals = generate_signals(evidence_data)
            gaps = detect_data_gaps(evidence_data)
            evidence_data["signals"] = [s.model_dump() for s in signals]
            evidence_data["data_gaps"] = [g.model_dump() for g in gaps]
            evidence_data.setdefault("timestamps", {})
            evidence_data["timestamps"]["reanalyzed"] = datetime.now(timezone.utc).isoformat()

            try:
                from app.services.risk_aggregator import aggregate_risk

                evidence_data["final_risk"] = aggregate_risk(evidence_data)
            except Exception as exc:
                logger.warning("[%s] Recompute risk aggregation failed: %s", investigation_id, exc)

            decision_report = build_decision_report(evidence_data, observable_type)
            report_data = apply_decision_to_report(
                _generate_automated_report(evidence_data, observable_type),
                decision_report,
            )
            _inject_lexical_contribution(report_data, evidence_data)
            _apply_phishing_redirect_risk_floor(report_data, evidence_data, observable_type)
            decision_report = apply_decision_to_report(decision_report, report_data)
            report_data = apply_decision_to_report(report_data, decision_report)
            report_data = _ensure_report_completeness(report_data, evidence_data, observable_type)
            report_data["ai_model"] = None
            report_data["report_freshness"] = {
                "status": "fresh",
                "recomputed": True,
                "reason": reason,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            report_data["primary_reasoning"] = (
                f"Report recomputed after {reason}. "
                + str(report_data.get("primary_reasoning") or "")
            ).strip()
            _align_final_risk_with_report(evidence_data, report_data)

            latest_iteration = session.execute(
                select(func.max(Report.iteration)).where(Report.investigation_id == inv_id)
            ).scalar()
            next_iteration = int(latest_iteration or 0) + 1

            inv.classification = report_data.get("classification")
            inv.confidence = report_data.get("confidence")
            inv.risk_score = report_data.get("risk_score")
            inv.recommended_action = report_data.get("recommended_action")
            inv.updated_at = datetime.now(timezone.utc)
            if str(inv.state or "").lower() not in {"cancelled", "failed"}:
                inv.state = "concluded"

            evidence_row.evidence_json = evidence_data
            evidence_row.signals = evidence_data.get("signals", [])
            evidence_row.data_gaps = evidence_data.get("data_gaps", [])
            evidence_row.external_context = evidence_data.get("external_context")

            session.add(Report(
                investigation_id=inv_id,
                iteration=next_iteration,
                report_json=report_data,
                executive_summary=report_data.get("executive_summary"),
                technical_narrative=report_data.get("technical_narrative"),
                recommendations=report_data.get("recommendations_narrative"),
            ))
            session.commit()

            logger.info(
                "[%s] Report recomputed after evidence update: class=%s risk=%s iteration=%s",
                investigation_id,
                report_data.get("classification"),
                report_data.get("risk_score"),
                next_iteration,
            )
            return report_data
    except Exception as exc:
        logger.error("[%s] Report recompute failed: %s", investigation_id, exc, exc_info=True)
        return None


def _check_client_alerts_sync(session, inv, report_data: dict) -> None:
    """Sync version of client alert check  -  runs inside the Celery task DB session."""
    from app.models.database import Client, ClientAlert

    classification = (report_data.get("classification") or "").lower()
    if classification in ("", "benign"):
        return

    SEVERITY_MAP = {
        "malicious": "critical",
        "suspicious": "high",
        "inconclusive": "medium",
    }
    severity = SEVERITY_MAP.get(classification, "medium")
    inv_domain = inv.domain.lower().removeprefix("www.")

    clients = session.execute(
        __import__("sqlalchemy", fromlist=["select"]).select(Client).where(Client.status == "active")
    ).scalars().all()

    now = datetime.now(timezone.utc)
    new_alerts: list[ClientAlert] = []

    for client in clients:
        client_root = client.domain.lower().removeprefix("www.")
        aliases = [a.lower().removeprefix("www.") for a in (client.aliases or [])]

        # 1. Alias match
        if inv_domain in aliases:
            new_alerts.append(ClientAlert(
                client_id=client.id,
                investigation_id=inv.id,
                alert_type="phishing_detected",
                severity=severity,
                title=f"Monitored alias {inv.domain} classified as {classification}",
                details_json={"investigated_domain": inv.domain, "classification": classification},
            ))

        # 2. Typosquatting: investigation ran with this client as client_domain
        elif getattr(inv, "client_domain", None) and \
                (inv.client_domain or "").lower().removeprefix("www.") == client_root:
            new_alerts.append(ClientAlert(
                client_id=client.id,
                investigation_id=inv.id,
                alert_type="typosquatting",
                severity=severity,
                title=f"Potential typosquatting of {client.domain}: {inv.domain}",
                details_json={
                    "investigated_domain": inv.domain,
                    "client_domain": client.domain,
                    "classification": classification,
                },
            ))

        # 3. Brand keyword match
        else:
            matched_kw = next(
                (kw for kw in (client.brand_keywords or []) if kw.lower() in inv_domain),
                None,
            )
            if matched_kw:
                new_alerts.append(ClientAlert(
                    client_id=client.id,
                    investigation_id=inv.id,
                    alert_type="brand_impersonation",
                    severity=severity,
                    title=f"Brand keyword '{matched_kw}' in {classification} domain: {inv.domain}",
                    details_json={
                        "investigated_domain": inv.domain,
                        "classification": classification,
                        "matched_keyword": matched_kw,
                        "client_name": client.name,
                    },
                ))

    for alert in new_alerts:
        session.add(alert)

    # Update client counters
    from collections import Counter
    counts = Counter(str(a.client_id) for a in new_alerts)
    for client in clients:
        n = counts.get(str(client.id), 0)
        if n:
            client.alert_count = (client.alert_count or 0) + n
            client.last_alert_at = now

    if new_alerts:
        session.commit()
        logger.info("Created %d client alert(s) for investigation %s", len(new_alerts), inv.id)


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
                if str(inv.state or "").lower() == "cancelled":
                    return
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
            # For S3, we'd need async  -  for now store locally as fallback
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


def _guess_content_type(artifact_name: str) -> str:
    name = str(artifact_name or "").lower()
    if name.endswith(".png") or name.endswith("_png"):
        return "image/png"
    if name.endswith(".jpg") or name.endswith(".jpeg") or name.endswith("_jpg") or name.endswith("_jpeg"):
        return "image/jpeg"
    if name.endswith(".har") or name.endswith(".json") or name.endswith("_json"):
        return "application/json"
    if name.endswith(".html") or name.endswith("_html"):
        return "text/html"
    if name.endswith(".txt") or name.endswith(".log") or name.endswith("_txt") or name.endswith("_log"):
        return "text/plain"
    return "application/octet-stream"


def _build_analyst_input_evidence(evidence_data: dict, tier: str = "standard") -> dict:
    """
    Build a compact evidence payload for LLM analysis while preserving the full
    evidence object for persistence and UI rendering.
    """
    compact = copy.deepcopy(evidence_data or {})
    compact["_analyst_compaction_tier"] = tier
    compact["analyst_digest"] = _build_analyst_evidence_digest(evidence_data, tier=tier)
    _summarize_heavy_analyst_sections(compact, tier=tier)

    if tier == "standard":
        trim_limits = {
            ("intel", "related_subdomains"): 100,
            ("intel", "related_urls"): 80,
            ("intel", "historical_ip_addresses"): 50,
            ("intel", "certificates"): 50,
            ("js_analysis", "captured_requests"): 80,
            ("js_analysis", "request_domains"): 50,
            ("js_analysis", "tracking_pixels"): 40,
            ("js_analysis", "suspicious_scripts"): 40,
            ("js_analysis", "data_exfil_indicators"): 40,
            ("js_analysis", "console_errors"): 30,
            ("subdomains", "resolved"): 100,
            ("subdomains", "unresolved"): 80,
            ("subdomains", "interesting_subdomains"): 60,
            ("threat_feeds", "threatfox_matches"): 50,
            ("threat_feeds", "recent_reports"): 50,
            ("cert_timeline", "entries"): 100,
            ("favicon_intel", "hosts"): 75,
            ("infrastructure_pivot", "related_ips"): 50,
            ("signals",): 80,
            ("data_gaps",): 40,
            ("artifact_hashes",): 50,
        }
        text_limit = 4000
    elif tier == "compact":
        trim_limits = {
            ("intel", "related_subdomains"): 20,
            ("intel", "related_urls"): 12,
            ("intel", "historical_ip_addresses"): 10,
            ("intel", "certificates"): 10,
            ("js_analysis", "captured_requests"): 10,
            ("js_analysis", "request_domains"): 10,
            ("js_analysis", "tracking_pixels"): 8,
            ("js_analysis", "suspicious_scripts"): 8,
            ("js_analysis", "data_exfil_indicators"): 8,
            ("js_analysis", "console_errors"): 5,
            ("subdomains", "resolved"): 20,
            ("subdomains", "unresolved"): 20,
            ("subdomains", "interesting_subdomains"): 12,
            ("threat_feeds", "threatfox_matches"): 10,
            ("threat_feeds", "recent_reports"): 10,
            ("cert_timeline", "entries"): 15,
            ("favicon_intel", "hosts"): 12,
            ("infrastructure_pivot", "related_ips"): 10,
            ("signals",): 20,
            ("data_gaps",): 10,
            ("artifact_hashes",): 20,
        }
        text_limit = 1000
    else:
        trim_limits = {
            ("intel", "related_subdomains"): 10,
            ("intel", "related_urls"): 5,
            ("intel", "historical_ip_addresses"): 5,
            ("intel", "certificates"): 5,
            ("js_analysis", "captured_requests"): 4,
            ("js_analysis", "request_domains"): 5,
            ("js_analysis", "tracking_pixels"): 3,
            ("js_analysis", "suspicious_scripts"): 3,
            ("js_analysis", "data_exfil_indicators"): 3,
            ("js_analysis", "console_errors"): 3,
            ("subdomains", "resolved"): 10,
            ("subdomains", "unresolved"): 10,
            ("subdomains", "interesting_subdomains"): 6,
            ("threat_feeds", "threatfox_matches"): 5,
            ("threat_feeds", "recent_reports"): 5,
            ("cert_timeline", "entries"): 8,
            ("favicon_intel", "hosts"): 6,
            ("infrastructure_pivot", "related_ips"): 5,
            ("signals",): 8,
            ("data_gaps",): 6,
            ("artifact_hashes",): 10,
        }
        text_limit = 600
        _drop_paths(
            compact,
            [
                ["screenshot"],
                ["artifact_hashes"],
            ],
        )

    for path, limit in trim_limits.items():
        _trim_list(compact, list(path), limit)

    _trim_nested_text(compact, max_chars=text_limit)
    return compact


def _build_analyst_evidence_digest(evidence_data: dict, *, tier: str) -> dict:
    associated_with, basis = _infer_observable_association(evidence_data)
    signals = evidence_data.get("signals") or []
    gaps = evidence_data.get("data_gaps") or []
    digest = {
        "observable_summary": {
            "observable": str(evidence_data.get("domain") or ""),
            "observable_type": str(evidence_data.get("observable_type") or "domain"),
            "tier": tier,
        },
        "associated_with": associated_with,
        "association_basis": basis,
        "collector_summaries": {
            "whois": _digest_whois(evidence_data.get("whois") or {}),
            "http": _digest_http(evidence_data.get("http") or {}),
            "urlscan": _digest_urlscan(evidence_data.get("urlscan") or {}),
            "vt": _digest_vt(evidence_data.get("vt") or {}),
            "threat_feeds": _digest_threat_feeds(evidence_data.get("threat_feeds") or {}),
            "brave_osint": _digest_brave_osint(evidence_data.get("brave_osint") or {}),
            "js_analysis": _digest_js_analysis(evidence_data.get("js_analysis") or {}),
            "hybrid_analysis": _digest_hybrid_analysis(evidence_data.get("hybrid_analysis") or {}),
            "domain_similarity": _digest_domain_similarity(evidence_data.get("domain_similarity") or {}),
            "visual_comparison": _digest_visual_comparison(evidence_data.get("visual_comparison") or {}),
            "redirect_destination_intel": _digest_redirect_destination(evidence_data.get("redirect_destination_intel") or {}),
        },
        "top_signals": [
            {
                "id": str(item.get("id") or ""),
                "severity": str(item.get("severity") or "info"),
                "description": str(item.get("description") or ""),
            }
            for item in signals[: (15 if tier == "standard" else 8 if tier == "compact" else 5)]
            if isinstance(item, dict)
        ],
        "top_data_gaps": [
            {
                "id": str(item.get("id") or ""),
                "impact": str(item.get("impact") or ""),
                "description": str(item.get("description") or ""),
            }
            for item in gaps[: (10 if tier == "standard" else 5 if tier == "compact" else 3)]
            if isinstance(item, dict)
        ],
    }
    return digest


def _infer_observable_association(evidence_data: dict) -> tuple[str, list[str]]:
    http = evidence_data.get("http") or {}
    urlscan = evidence_data.get("urlscan") or {}
    whois = evidence_data.get("whois") or {}
    brave = evidence_data.get("brave_osint") or {}
    redirect_dest = evidence_data.get("redirect_destination_intel") or {}

    basis: list[str] = []
    candidates: list[str] = []

    for brand in (http.get("brand_indicators") or [])[:3]:
        text = str(brand or "").strip()
        if text:
            candidates.append(text)
            basis.append(f"HTTP brand indicator: {text}")

    for label, raw in (
        ("HTTP title", http.get("title")),
        ("URLScan title", urlscan.get("page_title")),
    ):
        title = _normalize_title_candidate(raw)
        if title:
            candidates.append(title)
            basis.append(f"{label}: {title}")

    registrant_org = str(whois.get("registrant_org") or "").strip()
    if registrant_org and not _looks_like_privacy_service(registrant_org):
        candidates.append(registrant_org)
        basis.append(f"WHOIS registrant org: {registrant_org}")

    top_hits = brave.get("top_hits") or []
    if isinstance(top_hits, list):
        for hit in top_hits[:3]:
            if not isinstance(hit, dict):
                continue
            hit_title = _normalize_title_candidate(hit.get("title"))
            if hit_title:
                candidates.append(hit_title)
                basis.append(f"Brave OSINT hit: {hit_title}")
            for keyword in (hit.get("matched_keywords") or [])[:2]:
                text = str(keyword or "").strip()
                if text:
                    candidates.append(text)
                    basis.append(f"Brave OSINT keyword: {text}")

    destination_root = str(redirect_dest.get("destination_root") or "").strip()
    if destination_root:
        basis.append(f"Redirect destination root: {destination_root}")

    if not candidates:
        return "", basis[:6]

    normalized = {}
    for candidate in candidates:
        key = re.sub(r"[^a-z0-9]+", " ", candidate.lower()).strip()
        if not key:
            continue
        normalized[key] = normalized.get(key, {"label": candidate, "count": 0})
        normalized[key]["count"] += 1

    best = max(normalized.values(), key=lambda item: item["count"])
    label = str(best["label"]).strip()
    phishing_hints = " ".join(
        str(x)
        for x in (
            http.get("title"),
            urlscan.get("page_title"),
            " ".join(http.get("phishing_indicators") or []),
            brave.get("summary"),
        )
        if x
    ).lower()
    if any(token in phishing_hints for token in ("login", "verify", "verification", "account", "phish", "credential")):
        association = f"Appears associated with a {label} themed login or verification flow."
    else:
        association = f"Appears associated with {label}."
    return association, basis[:6]


def _normalize_title_candidate(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    primary = re.split(r"\s[\-\|\:\u2013]\s", text, maxsplit=1)[0].strip()
    primary = re.sub(r"\s+", " ", primary)
    words = primary.split()
    if len(words) > 8:
        primary = " ".join(words[:8]).strip()
    return primary


def _looks_like_privacy_service(value: str) -> bool:
    compact = value.lower()
    markers = ("proxy", "privacy", "redacted", "whoisguard", "contact privacy", "domains by proxy")
    return any(marker in compact for marker in markers)


def _digest_whois(whois: dict) -> dict:
    return {
        "registrar": whois.get("registrar"),
        "domain_age_days": whois.get("domain_age_days"),
        "privacy_protected": whois.get("privacy_protected"),
        "registrant_org": whois.get("registrant_org"),
        "registrant_country": whois.get("registrant_country"),
    }


def _digest_http(http: dict) -> dict:
    return {
        "reachable": http.get("reachable"),
        "final_url": http.get("final_url"),
        "final_status_code": http.get("final_status_code"),
        "title": http.get("title"),
        "has_login_form": http.get("has_login_form"),
        "brand_indicators": (http.get("brand_indicators") or [])[:5],
        "phishing_indicators": (http.get("phishing_indicators") or [])[:5],
        "technologies_detected": (http.get("technologies_detected") or [])[:5],
    }


def _digest_urlscan(urlscan: dict) -> dict:
    return {
        "verdict": urlscan.get("verdict"),
        "score": urlscan.get("score"),
        "page_url": urlscan.get("page_url"),
        "page_title": urlscan.get("page_title"),
        "page_ip": urlscan.get("page_ip"),
        "tags": (urlscan.get("tags") or [])[:5],
        "notes": (urlscan.get("notes") or [])[:3],
    }


def _digest_vt(vt: dict) -> dict:
    return {
        "malicious_count": vt.get("malicious_count"),
        "suspicious_count": vt.get("suspicious_count"),
        "total_vendors": vt.get("total_vendors"),
        "flagged_malicious_by": (vt.get("flagged_malicious_by") or [])[:8],
        "flagged_suspicious_by": (vt.get("flagged_suspicious_by") or [])[:5],
        "tags": (vt.get("tags") or [])[:8],
        "categories": dict(list((vt.get("categories") or {}).items())[:6]),
    }


def _digest_threat_feeds(threat_feeds: dict) -> dict:
    phishtank = threat_feeds.get("phishtank") or {}
    abuse = threat_feeds.get("abuseipdb") or {}
    otx = threat_feeds.get("otx") or {}
    return {
        "openphish_listed": threat_feeds.get("openphish_listed"),
        "phishtank": {
            "in_database": phishtank.get("in_database"),
            "verified": phishtank.get("verified"),
            "target_brand": phishtank.get("target_brand"),
        },
        "abuseipdb": {
            "abuse_confidence_score": abuse.get("abuse_confidence_score"),
            "total_reports": abuse.get("total_reports"),
        },
        "threatfox_matches": [
            {
                "ioc_value": item.get("ioc_value"),
                "threat_type": item.get("threat_type"),
                "malware": item.get("malware"),
            }
            for item in (threat_feeds.get("threatfox_matches") or [])[:5]
            if isinstance(item, dict)
        ],
        "otx": {
            "found": otx.get("found"),
            "pulse_count": otx.get("pulse_count"),
            "malware_families": (otx.get("malware_families") or [])[:5],
            "adversaries": (otx.get("adversaries") or [])[:5],
            "pulses": [
                {
                    "name": item.get("name"),
                    "author_name": item.get("author_name"),
                    "tags": (item.get("tags") or [])[:5],
                }
                for item in (otx.get("pulses") or [])[:5]
                if isinstance(item, dict)
            ],
        },
    }


def _digest_brave_osint(brave: dict) -> dict:
    return {
        "score": brave.get("score"),
        "risk_level": brave.get("risk_level"),
        "summary": brave.get("summary"),
        "top_hits": [
            {
                "title": hit.get("title"),
                "url": hit.get("url"),
                "description": hit.get("description"),
                "source": hit.get("source"),
                "matched_keywords": (hit.get("matched_keywords") or [])[:3],
            }
            for hit in (brave.get("top_hits") or [])[:3]
            if isinstance(hit, dict)
        ],
    }


def _digest_js_analysis(js: dict) -> dict:
    return {
        "total_requests": js.get("total_requests"),
        "external_requests": js.get("external_requests"),
        "request_domains": (js.get("request_domains") or [])[:8],
        "credential_post_endpoints": [
            item.get("url")
            for item in (js.get("post_endpoints") or [])[:10]
            if isinstance(item, dict) and item.get("is_credential_form")
        ][:5],
        "suspicious_scripts": [
            {
                "domain": item.get("domain"),
                "reason": item.get("reason"),
            }
            for item in (js.get("suspicious_scripts") or [])[:5]
            if isinstance(item, dict)
        ],
    }


def _digest_hybrid_analysis(hybrid: dict) -> dict:
    return {
        "items": [
            {
                "indicator_type": item.get("indicator_type"),
                "verdict": item.get("verdict"),
                "analysis_id": item.get("analysis_id"),
                "threat_score": item.get("threat_score"),
                "sandbox_intelligence": _digest_anyrun_sandbox_intelligence(item.get("sandbox_intelligence") or {}),
                "contacted_domains": ((item.get("dynamic_io_summary") or {}).get("contacted_domains") or [])[:5],
                "contacted_ips": ((item.get("dynamic_io_summary") or {}).get("contacted_ips") or [])[:5],
            }
            for item in (hybrid.get("items") or [])[:3]
            if isinstance(item, dict)
        ]
    }


def _digest_anyrun_sandbox_intelligence(intel: dict) -> dict:
    if not isinstance(intel, dict):
        return {}
    process_tree = intel.get("process_tree_summary") or {}
    return {
        "summary": intel.get("summary") or {},
        "process_tree_summary": {
            "process_count": process_tree.get("process_count"),
            "edge_count": process_tree.get("edge_count"),
            "root_processes": (process_tree.get("root_processes") or [])[:3],
            "high_risk_processes": (process_tree.get("high_risk_processes") or [])[:5],
            "narrative": process_tree.get("narrative"),
        },
        "contacted_hosts": (intel.get("contacted_hosts") or [])[:8],
        "contacted_ips": (intel.get("contacted_ips") or [])[:8],
        "dropped_files": (intel.get("dropped_files") or [])[:8],
        "suspicious_commands": (intel.get("suspicious_commands") or [])[:8],
        "extracted_iocs": (intel.get("extracted_iocs") or [])[:12],
    }


def _digest_domain_similarity(similarity: dict) -> dict:
    return {
        "client_domain": similarity.get("client_domain"),
        "overall_similarity_score": similarity.get("overall_similarity_score"),
        "is_potential_typosquat": similarity.get("is_potential_typosquat"),
        "summary": similarity.get("summary"),
    }


def _digest_visual_comparison(visual: dict) -> dict:
    return {
        "client_domain": visual.get("client_domain"),
        "overall_visual_similarity": visual.get("overall_visual_similarity"),
        "is_visual_clone": visual.get("is_visual_clone"),
        "summary": visual.get("summary"),
    }


def _digest_redirect_destination(redirect_dest: dict) -> dict:
    return {
        "destination_root": redirect_dest.get("destination_root"),
        "final_url": redirect_dest.get("final_url"),
        "destination_host": redirect_dest.get("destination_host"),
        "whois_registrant_org": ((redirect_dest.get("whois") or {}).get("registrant_org") if isinstance(redirect_dest.get("whois"), dict) else None),
    }


def _summarize_heavy_analyst_sections(compact: dict, *, tier: str) -> None:
    vt = compact.get("vt")
    if isinstance(vt, dict):
        vt["vendor_results"] = (vt.get("vendor_results") or [])[: (25 if tier == "standard" else 6 if tier == "compact" else 5)]
        vt["tags"] = (vt.get("tags") or [])[: (20 if tier == "standard" else 6 if tier == "compact" else 5)]
        vt_dns_records = vt.get("vt_dns_records")
        if isinstance(vt_dns_records, list):
            vt["vt_dns_records"] = vt_dns_records[:10 if tier == "standard" else 3]

    intel = compact.get("intel")
    if isinstance(intel, dict):
        intel["cert_entries_raw"] = []
        intel["related_subdomains"] = (intel.get("related_subdomains") or [])[: (75 if tier == "standard" else 10 if tier == "compact" else 5)]
        intel["related_certs"] = (intel.get("related_certs") or [])[: (20 if tier == "standard" else 5)]

    brave = compact.get("brave_osint")
    if isinstance(brave, dict):
        brave["top_hits"] = (brave.get("top_hits") or [])[: (10 if tier == "standard" else 4 if tier == "compact" else 3)]
        brave["observed_results"] = (brave.get("observed_results") or [])[: (10 if tier == "standard" else 0)]
        brave["all_results"] = (brave.get("all_results") or [])[: (10 if tier == "standard" else 0)]
        brave["queries"] = (brave.get("queries") or [])[: (8 if tier == "standard" else 3)]

    js = compact.get("js_analysis")
    if isinstance(js, dict):
        js["captured_requests"] = (js.get("captured_requests") or [])[: (80 if tier == "standard" else 10 if tier == "compact" else 4)]
        js["request_domains"] = (js.get("request_domains") or [])[: (40 if tier == "standard" else 6 if tier == "compact" else 4)]
        post_endpoints = []
        for item in (js.get("post_endpoints") or [])[: (25 if tier == "standard" else 10)]:
            if isinstance(item, dict) and (item.get("is_credential_form") or tier != "digest"):
                post_endpoints.append(item)
        js["post_endpoints"] = post_endpoints[: (20 if tier == "standard" else 5 if tier == "compact" else 3)]

    hybrid = compact.get("hybrid_analysis")
    if isinstance(hybrid, dict):
        summarized_items = []
        for item in (hybrid.get("items") or [])[: (6 if tier == "standard" else 3)]:
            if not isinstance(item, dict):
                continue
            dynamic = item.get("dynamic_io_summary") or {}
            raw = item.get("raw_summary") or {}
            summarized_items.append(
                {
                    "checked": item.get("checked"),
                    "indicator_type": item.get("indicator_type"),
                    "verdict": item.get("verdict"),
                    "analysis_id": item.get("analysis_id"),
                    "threat_score": item.get("threat_score"),
                    "error": item.get("error"),
                    "cache_hit": item.get("cache_hit"),
                    "dynamic_io_summary": {
                        "contacted_domains": (dynamic.get("contacted_domains") or [])[: (20 if tier == "standard" else 5)],
                        "contacted_ips": (dynamic.get("contacted_ips") or [])[: (20 if tier == "standard" else 5)],
                        "processes": (dynamic.get("processes") or [])[: (15 if tier == "standard" else 5)],
                    },
                    "sandbox_intelligence": _digest_anyrun_sandbox_intelligence(item.get("sandbox_intelligence") or {}),
                    "raw_summary": dict(list(raw.items())[:5]) if isinstance(raw, dict) else {},
                }
            )
        hybrid["items"] = summarized_items

    http = compact.get("http")
    if isinstance(http, dict):
        http["response_headers"] = dict(list((http.get("response_headers") or {}).items())[: (16 if tier == "standard" else 8)])
        http["external_resources"] = (http.get("external_resources") or [])[: (30 if tier == "standard" else 8)]


def _run_analyst_with_compaction(
    evidence_data: dict,
    *,
    max_iterations: int,
    timeout_seconds: int,
) -> tuple[dict, str, str]:
    """
    Returns (report_dict, compaction_tier, actual_model_id).
    """
    last_error: Exception | None = None
    tiers = ("standard", "compact", "digest")
    for tier in tiers:
        analyst_input = _build_analyst_input_evidence(evidence_data, tier=tier)
        try:
            report_dict, actual_model = _run_analyst_sync(
                analyst_input,
                max_iterations,
                timeout_seconds=timeout_seconds,
            )
            return report_dict, tier, actual_model
        except Exception as exc:
            if not _is_prompt_too_long_error(exc) or tier == tiers[-1]:
                raise
            last_error = exc
            logger.warning("Analyst prompt exceeded model limits at tier=%s; retrying with smaller payload.", tier)
    if last_error:
        raise last_error
    raise RuntimeError("Analyst compaction retry exhausted without result")


def _is_prompt_too_long_error(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return "invalid_request_error" in text and "prompt is too long" in text


def _annotate_compact_analyst_report(report_data: dict, *, used_tier: str) -> dict:
    if used_tier == "standard":
        return report_data

    annotated = copy.deepcopy(report_data or {})
    note = f"Analyst used compact evidence ({used_tier} tier) due to prompt size limits."
    primary = str(annotated.get("primary_reasoning") or "").strip()
    executive = str(annotated.get("executive_summary") or "").strip()
    annotated["primary_reasoning"] = f"{note} {primary}".strip()
    if executive:
        annotated["executive_summary"] = f"{note} {executive}".strip()
    return annotated


def _build_prompt_too_long_fallback_report(automated_report: dict, *, prompt_error: Exception) -> dict:
    fallback = copy.deepcopy(automated_report or {})
    note = "Analyst prompt exceeded model limits after compact retries. Fallback automated analysis applied."
    detail = (
        fallback.get("executive_summary")
        or fallback.get("technical_narrative")
        or fallback.get("primary_reasoning", "")
    )
    fallback["primary_reasoning"] = f"{note} {detail}".strip()
    if fallback.get("executive_summary"):
        fallback["executive_summary"] = f"{note} {fallback['executive_summary']}".strip()
    steps = fallback.get("recommended_steps")
    if not isinstance(steps, list):
        steps = []
    if "Review evidence manually if the full analyst narrative is required." not in steps:
        steps.append("Review evidence manually if the full analyst narrative is required.")
    fallback["recommended_steps"] = steps
    fallback["analyst_error"] = str(prompt_error)
    return fallback


def _trim_list(payload: dict, path: list[str], limit: int) -> None:
    node = payload
    for key in path[:-1]:
        if not isinstance(node, dict):
            return
        node = node.get(key)
        if node is None:
            return
    if not isinstance(node, dict):
        return
    leaf = path[-1]
    value = node.get(leaf)
    if isinstance(value, list) and len(value) > limit:
        node[leaf] = value[:limit]
    elif isinstance(value, dict) and len(value) > limit:
        node[leaf] = dict(list(value.items())[:limit])


def _drop_paths(payload: dict, paths: list[list[str]]) -> None:
    for path in paths:
        node = payload
        for key in path[:-1]:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
            if node is None:
                break
        if isinstance(node, dict):
            node.pop(path[-1], None)


def _trim_nested_text(value, *, max_chars: int):
    if isinstance(value, dict):
        for k, v in list(value.items()):
            value[k] = _trim_nested_text(v, max_chars=max_chars)
        return value
    if isinstance(value, list):
        return [_trim_nested_text(v, max_chars=max_chars) for v in value]
    if isinstance(value, str) and len(value) > max_chars:
        return value[:max_chars] + "...[truncated]"
    return value


def _should_reuse_urlscan_screenshot(evidence_data: dict, observable_type: str) -> bool:
    if observable_type not in ("domain", "url"):
        return False
    urlscan = evidence_data.get("urlscan") or {}
    return bool(urlscan.get("screenshot_artifact_id"))


def _build_reused_screenshot_payload(
    evidence_data: dict,
    *,
    investigated_url: str | None,
    domain: str,
) -> dict:
    urlscan = evidence_data.get("urlscan") or {}
    return {
        "artifact_id": urlscan.get("screenshot_artifact_id"),
        "final_url": urlscan.get("page_url") or investigated_url or domain,
    }


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
