"""
FastAPI application factory.

Configures CORS, security middleware, lifespan events, and mounts the API router.
"""

from __future__ import annotations

import logging
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.config import get_settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.db.session import async_engine

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
    from sqlalchemy import text
    from app.models.database import Base  # noqa: F401 — import registers all models

    async with async_engine.begin() as conn:
        # Create any tables that don't exist yet (idempotent)
        await conn.run_sync(Base.metadata.create_all)

        # Add columns that may be missing from tables created before these fields existed.
        # ALTER TABLE ... ADD COLUMN IF NOT EXISTS is idempotent — safe to run every boot.
        col_migrations = [
            "ALTER TABLE clients ADD COLUMN IF NOT EXISTS default_collectors JSONB NOT NULL DEFAULT '[]'::jsonb",
            "ALTER TABLE investigations ADD COLUMN IF NOT EXISTS observable_type VARCHAR(20) NOT NULL DEFAULT 'domain'",
            "ALTER TABLE investigations ALTER COLUMN domain TYPE VARCHAR(512)",
        ]
        for stmt in col_migrations:
            await conn.execute(text(stmt))

    logger.info("Database schema verified / migrated")

    logger.info("Threat Investigation Platform starting")
    logger.info(f"Environment: {settings.app_env}")
    logger.info(f"Analyst model: {settings.openai_model}")
    claude_fallback_enabled = bool(settings.anthropic_api_key and settings.anthropic_model)
    if claude_fallback_enabled:
        logger.info(f"Claude fallback: enabled (model={settings.anthropic_model})")
    else:
        logger.info("Claude fallback: disabled (set ANTHROPIC_API_KEY and ANTHROPIC_MODEL)")
    yield
    logger.info("Shutting down")


# ── App ──
app = FastAPI(
    title="Domain Threat Investigation Platform",
    version="1.0.0",
    description="Automated domain threat investigation with evidence-based analysis",
    lifespan=lifespan,
    # Disable auto-generated docs in production to avoid leaking schema
    docs_url="/api/docs" if settings.is_development else None,
    redoc_url=None,
)


# ── Security Headers Middleware ──
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defensive HTTP security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if not settings.is_development:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization", "X-Request-ID"],
)


# ── Global Exception Handler ──
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all for unhandled exceptions.
    In development: returns exception type + message for easier debugging.
    In production: returns a generic 500 with no internal details.
    """
    print(
        f"\n[EXCEPTION] {request.method} {request.url.path} → "
        f"{type(exc).__name__}: {exc}",
        flush=True,
    )
    traceback.print_exc()
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}: "
        f"{type(exc).__name__}: {exc}",
        exc_info=True,
    )
    if settings.is_development:
        return JSONResponse(
            status_code=500,
            content={"detail": f"{type(exc).__name__}: {exc}"},
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again later."},
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
