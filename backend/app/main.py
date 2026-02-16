"""
FastAPI application factory.

Configures CORS, lifespan events, and mounts the API router.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_settings

settings = get_settings()

# ── Logging ──
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Threat Investigation Platform starting")
    logger.info(f"Environment: {settings.app_env}")
    logger.info(f"Analyst model: {settings.anthropic_model}")
    yield
    logger.info("Shutting down")


# ── App ──
app = FastAPI(
    title="Domain Threat Investigation Platform",
    version="1.0.0",
    description="Automated domain threat investigation with evidence-based analysis",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ──
app.include_router(api_router)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }
