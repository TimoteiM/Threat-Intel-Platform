"""
Simple token bucket rate limiter for external API calls.

Prevents hammering ip-api.com, crt.sh, etc.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class RateLimiter:
    """
    Per-source token bucket rate limiter.

    Usage:
        limiter = RateLimiter()
        await limiter.acquire("ip-api", max_per_second=2)
        # ... make the API call ...
    """

    def __init__(self):
        self._timestamps: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def acquire(self, source: str, max_per_second: float = 2.0):
        """Wait until a request slot is available for the given source."""
        interval = 1.0 / max_per_second

        async with self._lock:
            now = time.monotonic()
            timestamps = self._timestamps[source]

            # Remove old timestamps
            cutoff = now - 1.0
            self._timestamps[source] = [t for t in timestamps if t > cutoff]
            timestamps = self._timestamps[source]

            if len(timestamps) >= max_per_second:
                # Need to wait
                oldest = timestamps[0]
                wait_time = (oldest + 1.0) - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)

            self._timestamps[source].append(time.monotonic())


# Global instance
rate_limiter = RateLimiter()
