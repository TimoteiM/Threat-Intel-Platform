"""
Top-level API router — aggregates all endpoint modules.
"""

from fastapi import APIRouter

from app.api.investigations import router as investigations_router
from app.api.sse import router as sse_router
from app.api.enrichment import router as enrichment_router
from app.api.export import router as export_router
from app.api.artifacts import router as artifacts_router
from app.api.reference_images import router as reference_images_router
from app.api.pivots import router as pivots_router
from app.api.batches import router as batches_router
from app.api.attack import router as attack_router
from app.api.dashboard import router as dashboard_router
from app.api.iocs import router as iocs_router
from app.api.watchlist import router as watchlist_router
from app.api.whois_history import router as whois_history_router
from app.api.geo import router as geo_router

api_router = APIRouter()

api_router.include_router(investigations_router)
api_router.include_router(sse_router)
api_router.include_router(enrichment_router)
api_router.include_router(export_router)
api_router.include_router(artifacts_router)
api_router.include_router(reference_images_router)
api_router.include_router(pivots_router)
api_router.include_router(batches_router)
api_router.include_router(attack_router)
api_router.include_router(dashboard_router)
api_router.include_router(iocs_router)
api_router.include_router(watchlist_router)
api_router.include_router(whois_history_router)
api_router.include_router(geo_router)
