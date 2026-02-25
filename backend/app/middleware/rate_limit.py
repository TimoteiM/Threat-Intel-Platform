"""
In-memory sliding-window rate limiter middleware.

Tracks request counts per (IP, endpoint) pair using a sliding time window.
No external dependencies — uses a simple list-of-timestamps approach.

Limits (POST only — read operations are uncapped):
  POST /api/investigations  → 10 per minute
  POST /api/tools/ip-lookup → 20 per minute
  POST /api/batches         → 3 per minute
  POST /api/watchlist       → 15 per minute
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# (limit, window_seconds)
_LIMITS: dict[str, tuple[int, int]] = {
    "POST:/api/investigations":  (10, 60),
    "POST:/api/tools/ip-lookup": (20, 60),
    "POST:/api/batches":         (3,  60),
    "POST:/api/watchlist":       (15, 60),
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter keyed on (client IP, method+path).

    Memory note: timestamps older than the window are pruned on every request
    for that bucket, so the dict stays bounded to (active IPs × endpoints).
    """

    def __init__(self, app):
        super().__init__(app)
        # bucket_key → list of request timestamps
        self._buckets: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        route_key = f"{request.method}:{request.url.path}"

        if route_key in _LIMITS:
            limit, window = _LIMITS[route_key]
            # Prefer X-Forwarded-For for proxy setups, fall back to direct client
            ip = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or (request.client.host if request.client else "unknown")
            )
            bucket_key = f"{ip}:{route_key}"
            now = time.monotonic()

            # Prune timestamps outside the sliding window
            self._buckets[bucket_key] = [
                t for t in self._buckets[bucket_key] if now - t < window
            ]

            if len(self._buckets[bucket_key]) >= limit:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": f"Rate limit exceeded. Maximum {limit} requests per {window}s."
                    },
                    headers={"Retry-After": str(window)},
                )

            self._buckets[bucket_key].append(now)

        return await call_next(request)
