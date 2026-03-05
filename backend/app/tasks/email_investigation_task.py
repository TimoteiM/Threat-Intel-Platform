from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import EmailInvestigationRun
from app.services.email_investigation_processing_service import (
    prepare_history_payload,
    process_email_investigation,
)
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _update_run(run_uuid: uuid.UUID, **fields) -> bool:
    with Session(sync_engine) as db:
        run = db.get(EmailInvestigationRun, run_uuid)
        if not run:
            return False
        for key, value in fields.items():
            setattr(run, key, value)
        db.commit()
        return True


@celery_app.task(bind=True, name="tasks.run_email_investigation", time_limit=900, soft_time_limit=840)
def run_email_investigation(
    self,
    run_id: str,
    file_path: str,
    *,
    context: str = "",
    max_urls: int = 20,
    max_attachment_hashes: int = 5,
    include_url_screenshots: bool = False,
    run_ai: bool = True,
    ml_phishing_score: str | None = None,
) -> str:
    try:
        parsed_id = uuid.UUID(run_id)
    except ValueError:
        logger.error("Invalid email investigation run_id: %s", run_id)
        return run_id

    with Session(sync_engine) as db:
        run = db.get(EmailInvestigationRun, parsed_id)
        if not run:
            logger.error("Email investigation run not found: %s", run_id)
            return run_id
        run_filename = run.filename

    _update_run(parsed_id, status="processing", error=None)

    try:
        with open(file_path, "rb") as fh:
            payload = fh.read()

        response_payload = asyncio.run(
            process_email_investigation(
                payload=payload,
                filename=run_filename,
                context=context,
                max_urls=max_urls,
                max_attachment_hashes=max_attachment_hashes,
                include_url_screenshots=include_url_screenshots,
                run_ai=run_ai,
                ml_phishing_score=ml_phishing_score,
            )
        )

        _update_run(
            parsed_id,
            email_subject=str(response_payload.get("email_subject") or "")[:512] or None,
            sender_email=response_payload.get("sender_email"),
            sender_domain=response_payload.get("sender_domain"),
            sender_ip=response_payload.get("sender_ip"),
            resolution_source=str(response_payload.get("resolution_source") or "unknown"),
            result_json=prepare_history_payload(response_payload),
            status="completed",
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        _update_run(
            parsed_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            completed_at=datetime.now(timezone.utc),
        )
        logger.exception("Email investigation run failed: %s", run_id)
    finally:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            logger.warning("Could not remove temporary email payload: %s", file_path)

    return run_id
