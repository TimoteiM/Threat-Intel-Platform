"""
Celery application configuration.

This is the single Celery instance used by all tasks.
Worker startup: celery -A app.tasks.celery_app worker --loglevel=info
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "threat_intel",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Reliability
    task_track_started=True,
    task_time_limit=120,           # Hard kill after 2 min
    task_soft_time_limit=90,       # Raise SoftTimeLimitExceeded after 90s
    task_acks_late=True,           # Ack after completion (not on receive)

    # Performance
    worker_prefetch_multiplier=1,  # One task at a time per worker process
    worker_concurrency=4,          # 4 parallel worker processes

    # Task routing (optional — all tasks go to default queue for now)
    task_default_queue="investigations",

    # Celery Beat — periodic task schedule
    beat_schedule={
        "watchlist-scheduled-checks": {
            "task": "tasks.watchlist_check",
            "schedule": crontab(minute=0),  # Every hour, on the hour
        },
    },
    timezone="UTC",
)

# Auto-discover tasks in these modules
celery_app.autodiscover_tasks([
    "app.tasks.collector_task",
    "app.tasks.investigation_task",
    "app.tasks.analysis_task",
    "app.tasks.batch_task",
    "app.tasks.watchlist_task",
])
