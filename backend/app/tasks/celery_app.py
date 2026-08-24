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
    # With acks_late a task killed mid-flight stays unacknowledged and Redis
    # redelivers it once this expires. It must stay ABOVE the longest task's
    # time limit (alert runs allow 1800s) or a still-running task gets handed to
    # a second worker and the investigation runs twice. Stated here because the
    # value was previously an inherited default nobody had chosen, and lowering
    # it is the obvious-looking way to make recovery faster — it is not.
    # Fast recovery is tasks.recover_stuck_alert_runs, which verifies liveness.
    broker_transport_options={"visibility_timeout": 3600},
    task_reject_on_worker_lost=True,

    # Performance
    # Use threads pool — prefork (billiard) fails on Windows with WinError 5/6
    # (shared-memory semaphores don't work reliably on Windows).
    # Threads are fine here: all tasks are I/O-bound (HTTP, DNS, DB).
    worker_pool="threads",
    worker_prefetch_multiplier=1,  # One task at a time per worker thread
    worker_concurrency=8,          # 8 concurrent I/O threads

    # Task routing (optional — all tasks go to default queue for now)
    task_default_queue="investigations",

    # Celery Beat — periodic task schedule
    beat_schedule={
        "watchlist-scheduled-checks": {
            "task": "tasks.watchlist_check",
            "schedule": crontab(minute=0),  # Every hour, on the hour
        },
        # A URL VirusTotal has never seen gets submitted for scanning, and the
        # result lands after the investigation has already concluded. Without
        # this the pending id was recorded and never chased.
        "virustotal-collect-pending": {
            "task": "tasks.vt_collect_pending",
            "schedule": crontab(minute="*/15"),
        },
        # A worker that dies mid-task leaves its run in `processing`. Redis will
        # redeliver the message eventually, but not before the visibility
        # timeout, which has to stay above the task's own 30-minute limit. This
        # closes that gap to minutes instead of up to an hour.
        "recover-stuck-alert-runs": {
            "task": "tasks.recover_stuck_alert_runs",
            "schedule": crontab(minute="*/3"),
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
    "app.tasks.email_investigation_task",
    "app.tasks.watchlist_task",
    "app.tasks.alert_recovery_task",
    "app.tasks.alert_body_task",
    "app.tasks.alert_callback_task",
    "app.tasks.vt_pending_task",
])
