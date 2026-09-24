"""
Admin and operational health endpoints.
"""

from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter

from app.models.schemas import APIHealthResponse
from app.services.api_health_service import get_api_health_snapshot

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/api-health", response_model=APIHealthResponse)
async def get_api_health() -> APIHealthResponse:
    # On a cold cache this probes three providers with blocking HTTP calls, up
    # to 10s each. Inline on the event loop that is 30 seconds during which the
    # API answers nothing at all — which is what made this page return
    # "Internal Server Error" on first load and succeed on a refresh.
    return await asyncio.to_thread(get_api_health_snapshot)


@router.get("/opensearch-health")
async def get_opensearch_health() -> dict:
    """Does the log cluster answer with the configuration we actually ship?

    This exists because a probe run with `OPENSEARCH_VERIFY_TLS=false` proves
    the query works and proves nothing about the deployed setting. This one
    reads the live settings — CA bundle included — and either connects or says
    exactly why not, so "the CA is installed correctly" is a thing that can be
    checked rather than assumed.

    Safe to call at any time: it is a GET against `/` on the cluster.
    """
    from starlette.concurrency import run_in_threadpool

    from app.config import get_settings
    from app.services import opensearch_client as osc

    settings = get_settings()

    def _probe() -> dict:
        bundle = str(getattr(settings, "opensearch_ca_bundle", "") or "")
        base = {
            "verify_tls": bool(settings.opensearch_verify_tls),
            "ca_bundle": bundle or None,
            "ca_bundle_present": bool(bundle) and os.path.exists(bundle),
            "nodes_configured": sum(
                1 for i in (1, 2, 3) if getattr(settings, f"opensearch_node{i}", "")
            ),
            "index_pattern": settings.opensearch_index_pattern,
        }
        if not settings.opensearch_verify_tls:
            base["warning"] = (
                "Certificate verification is disabled. The cluster's admin password is "
                "being sent over a connection nobody has checked."
            )
        try:
            with osc.OpenSearchClient(settings=settings) as client:
                base.update({"reachable": True, **client.ping()})
        except Exception as exc:  # noqa: BLE001
            base.update({"reachable": False, "error": osc.redact(exc)[:300]})
        return base

    return await run_in_threadpool(_probe)
