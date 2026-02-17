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

api_router = APIRouter()

api_router.include_router(investigations_router)
api_router.include_router(sse_router)
api_router.include_router(enrichment_router)
api_router.include_router(export_router)
api_router.include_router(artifacts_router)
api_router.include_router(reference_images_router)
