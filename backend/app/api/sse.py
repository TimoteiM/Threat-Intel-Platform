"""
Server-Sent Events endpoint for real-time investigation progress.

GET /api/investigations/{id}/status

The client opens an SSE connection and receives updates as:
- Collectors complete
- State transitions occur
- Analysis finishes
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.config import get_settings
from app.db.session import AsyncSessionLocal
from app.models.database import Investigation

logger = logging.getLogger(__name__)
router = APIRouter(tags=["sse"])
settings = get_settings()


@router.get("/api/investigations/{investigation_id}/status")
async def investigation_status_stream(investigation_id: str):
    """
    SSE stream of investigation progress events.

    Events are published to Redis pub/sub by the Celery tasks.
    This endpoint subscribes and forwards them to the client.
    """

    async def event_generator() -> AsyncGenerator[str, None]:
        redis_client = aioredis.from_url(settings.redis_url)
        pubsub = redis_client.pubsub()
        channel = f"investigation:{investigation_id}"

        await pubsub.subscribe(channel)
        logger.debug(f"SSE: subscribed to {channel}")

        # Send a best-effort initial snapshot so UI can render immediately.
        try:
            inv_uuid = uuid.UUID(investigation_id)
            async with AsyncSessionLocal() as session:
                inv = (
                    await session.execute(
                        select(Investigation).where(Investigation.id == inv_uuid)
                    )
                ).scalar_one_or_none()
                if inv:
                    state = (inv.state or "created").lower()
                    percent = {
                        "created": 2,
                        "gathering": 25,
                        "evaluating": 75,
                        "concluded": 100,
                        "failed": 100,
                    }.get(state, 0)
                    initial = json.dumps({
                        "type": "state_change",
                        "investigation_id": investigation_id,
                        "state": state,
                        "percent_complete": percent,
                        "message": f"Investigation state: {state}",
                        "done": state in ("concluded", "failed"),
                    })
                    yield f"data: {initial}\n\n"
        except Exception as e:
            logger.debug(f"SSE initial snapshot failed for {investigation_id}: {e}")

        try:
            idle_count = 0
            max_idle = 300  # 5 minutes timeout

            while idle_count < max_idle:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )

                if message and message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")

                    yield f"data: {data}\n\n"
                    idle_count = 0

                    # Check if investigation is done
                    try:
                        parsed = json.loads(data)
                        state = parsed.get("state", "")
                        if state in ("concluded", "failed"):
                            yield f"data: {json.dumps({'done': True})}\n\n"
                            break
                    except json.JSONDecodeError:
                        pass
                else:
                    idle_count += 1
                    # Send keepalive every 15 seconds
                    if idle_count % 15 == 0:
                        yield ": keepalive\n\n"

        finally:
            await pubsub.unsubscribe(channel)
            await redis_client.aclose()
            logger.debug(f"SSE: unsubscribed from {channel}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )
