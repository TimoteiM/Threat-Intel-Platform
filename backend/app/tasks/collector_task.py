"""
Collector Task — runs a single collector module inside a Celery worker.

Called in parallel by the investigation task via a chord.
Returns serialized evidence + metadata for aggregation.
"""

from __future__ import annotations

import logging

from app.tasks.celery_app import celery_app
from app.collectors.registry import get_collector
from app.models.enums import CollectorStatus

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="tasks.run_collector",
    max_retries=1,
    default_retry_delay=5,
)
def run_collector(
    self,
    domain: str,
    collector_name: str,
    investigation_id: str,
    timeout: int = 30,
) -> dict:
    """
    Execute a single collector and return serialized results.

    Returns:
        {
            "collector": "dns",
            "status": "completed",
            "evidence": { ... },      # Pydantic model as dict
            "meta": { ... },           # CollectorMeta as dict
            "artifacts": { "dns_raw_records": "<base64>" },
        }
    """
    logger.info(f"[{investigation_id}] Running collector: {collector_name} for {domain}")

    collector_cls = get_collector(collector_name)
    if not collector_cls:
        return {
            "collector": collector_name,
            "status": CollectorStatus.FAILED.value,
            "evidence": {},
            "meta": {"collector": collector_name, "status": "failed",
                     "error": f"Unknown collector: {collector_name}"},
            "artifacts": {},
        }

    collector = collector_cls(
        domain=domain,
        investigation_id=investigation_id,
        timeout=timeout,
    )

    evidence, meta, raw_artifacts = collector.run()

    # Serialize artifacts as hex-encoded strings for JSON transport
    # (actual binary storage happens in the analysis task)
    serialized_artifacts = {
        name: data.hex() for name, data in raw_artifacts.items()
    }

    # Publish progress via Redis pub/sub
    _publish_collector_progress(investigation_id, collector_name, meta.status.value)

    return {
        "collector": collector_name,
        "status": meta.status.value,
        "evidence": evidence.model_dump(mode="json"),
        "meta": meta.model_dump(mode="json"),
        "artifacts": serialized_artifacts,
    }


def _publish_collector_progress(
    investigation_id: str,
    collector_name: str,
    status: str,
) -> None:
    """Push a progress event to Redis pub/sub for SSE streaming."""
    import json
    import redis

    try:
        from app.config import get_settings
        settings = get_settings()
        r = redis.Redis.from_url(settings.redis_url)
        r.publish(
            f"investigation:{investigation_id}",
            json.dumps({
                "type": "collector_complete",
                "investigation_id": investigation_id,
                "collector": collector_name,
                "status": status,
            }),
        )
    except Exception as e:
        logger.warning(f"Failed to publish progress: {e}")
