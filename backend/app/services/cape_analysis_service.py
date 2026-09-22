"""The sandbox-analysis workflow, independent of who triggered it.

This module owns the *record*: creating it idempotently, moving it between
states with an audit trail, and deciding what a sample is eligible for. The
CAPE wire format lives in cape_client, the report mapping in cape_normalizer,
and the long-running polling in tasks/cape_task. Keeping them apart means the
API can create an analysis without importing anything that talks to CAPE.

Idempotency
-----------
A detonation occupies one of six VMs for minutes, so "submit" must be safe to
press twice. `get_or_create` writes a row whose `idempotency_key` is unique on
(tenant, sample, provider, policy, run_seq) and treats the unique-violation as
success — the row the other caller just created is the answer. That is the
same mechanism whether the duplicate comes from a double-clicked button, a
retried HTTP request, or two workers racing.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.database import SandboxAnalysis

logger = logging.getLogger(__name__)

PROVIDER_CAPE = "cape"

# Bump when a change to what we send CAPE (route, timeout, enforce_timeout)
# means an old analysis is no longer equivalent to a new one. It is part of the
# idempotency key, so bumping it lets everything be analysed again once.
ANALYSIS_POLICY_VERSION = "v1"

STATUS_QUEUED = "queued"
STATUS_SUBMITTING = "submitting"
STATUS_SUBMITTED = "submitted"
STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_PROCESSING = "processing"
STATUS_REPORTED = "reported"
STATUS_FAILED = "failed"
STATUS_TIMED_OUT = "timed_out"
STATUS_CANCELLED = "cancelled"

ALL_STATUSES = (
    STATUS_QUEUED, STATUS_SUBMITTING, STATUS_SUBMITTED, STATUS_PENDING,
    STATUS_RUNNING, STATUS_PROCESSING, STATUS_REPORTED, STATUS_FAILED,
    STATUS_TIMED_OUT, STATUS_CANCELLED,
)
TERMINAL_STATUSES = frozenset({STATUS_REPORTED, STATUS_FAILED, STATUS_TIMED_OUT, STATUS_CANCELLED})
ACTIVE_STATUSES = frozenset(set(ALL_STATUSES) - TERMINAL_STATUSES)
# States a retry may legitimately start from. A reported analysis is not
# retried — re-running it deliberately is a new run_seq, not a retry.
RETRYABLE_STATUSES = frozenset({STATUS_FAILED, STATUS_TIMED_OUT, STATUS_CANCELLED})

# How CAPE's own task states map onto ours.
CAPE_STATE_MAP = {
    "pending": STATUS_PENDING,
    "running": STATUS_RUNNING,
    "completed": STATUS_PROCESSING,
    "processing": STATUS_PROCESSING,
    "reported": STATUS_REPORTED,
    "failed_analysis": STATUS_FAILED,
    "failed_processing": STATUS_FAILED,
    "failure": STATUS_FAILED,
}

# Dynamic execution needs a handler in the guest image. This deployment has no
# PDF reader installed, so a PDF is accepted — CAPE still yields static and
# network signal — but the analyst is told the document was never opened,
# because an empty PDF report otherwise reads as "nothing happened".
_LIMITED_EXTENSIONS = {
    ".pdf": (
        "PDF dynamic execution is unavailable: no compatible PDF reader is installed in the "
        "guest image, so the document will not be opened. Static and network findings are "
        "still collected; the absence of behaviour is not evidence that the file is safe."
    ),
}


def make_idempotency_key(
    *, client: str | None, sha256: str | None = None, target_url: str | None = None,
    target_kind: str = "file", provider: str = PROVIDER_CAPE,
    policy_version: str = ANALYSIS_POLICY_VERSION, run_seq: int = 1,
) -> str:
    """Identity of one analysis.

    A file is identified by its digest, a URL by the URL itself — normalised to
    lowercase host and no trailing slash so `Example.com/` and `example.com`
    are one analysis rather than two detonations of the same page.
    """
    tenant = (client or "_global").strip().lower() or "_global"
    if str(target_kind) == "url":
        identity = f"url:{normalise_url(target_url)}"
    else:
        identity = str(sha256 or "").strip().lower()
    return f"{tenant}|{identity}|{provider}|{policy_version}|{int(run_seq)}"


def normalise_url(value: str | None) -> str:
    from urllib.parse import urlparse, urlunparse

    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    path = parsed.path.rstrip("/") or ""
    return urlunparse((parsed.scheme.lower(), f"{host}{port}", path, "", parsed.query, ""))


def sample_limitations(*, sample_name: str | None, sample_type: str | None = None) -> list[str]:
    """What this guest image cannot do with this sample. Shown, never hidden."""
    name = str(sample_name or "").strip().lower()
    declared = str(sample_type or "").strip().lower()
    notes: list[str] = []
    for extension, note in _LIMITED_EXTENSIONS.items():
        if name.endswith(extension) or extension.lstrip(".") in declared:
            notes.append(note)
    return notes


def get_or_create(
    db: Session,
    *,
    sha256: str | None = None,
    target_kind: str = "file",
    target_url: str | None = None,
    client: str | None = None,
    sample_name: str | None = None,
    sample_size: int | None = None,
    sample_type: str | None = None,
    investigation_id: uuid.UUID | None = None,
    alert_run_id: uuid.UUID | None = None,
    artifact_id: uuid.UUID | None = None,
    requested_by: str | None = None,
    run_seq: int = 1,
    provider: str = PROVIDER_CAPE,
) -> tuple[SandboxAnalysis, bool]:
    """The analysis for this sample, creating it only if it is not there.

    Returns (row, created). `created` false means somebody already asked —
    possibly a millisecond ago in another worker — and this caller should
    simply watch that analysis rather than starting a second one.
    """
    kind = "url" if str(target_kind) == "url" else "file"
    digest = str(sha256 or "").strip().lower() or None
    url = normalise_url(target_url) if kind == "url" else None

    if kind == "file" and (digest is None or len(digest) != 64):
        raise ValueError("A SHA-256 digest is required to create a file sandbox analysis")
    if kind == "url" and not url:
        raise ValueError("A URL is required to create a URL sandbox analysis")

    key = make_idempotency_key(
        client=client, sha256=digest, target_url=url, target_kind=kind,
        provider=provider, run_seq=run_seq,
    )

    existing = db.execute(
        select(SandboxAnalysis).where(SandboxAnalysis.idempotency_key == key)
    ).scalars().first()
    if existing is not None:
        return existing, False

    settings = get_settings()
    row = SandboxAnalysis(
        provider=provider,
        status=STATUS_QUEUED,
        target_kind=kind,
        target_url=url,
        sha256=digest,
        sample_name=(sample_name or None),
        sample_size=sample_size,
        sample_type=(sample_type or None),
        client=(client or None),
        investigation_id=investigation_id,
        alert_run_id=alert_run_id,
        artifact_id=artifact_id,
        idempotency_key=key,
        policy_version=ANALYSIS_POLICY_VERSION,
        run_seq=int(run_seq),
        requested_by=(requested_by or None)[:64] if requested_by else None,
        normalized_json={},
        raw_summary={},
        state_history=[],
        deadline_at=datetime.now(timezone.utc)
        + timedelta(seconds=int(settings.cape_max_poll_duration_seconds)),
    )
    _append_history(row, STATUS_QUEUED, actor=requested_by, note="analysis requested")
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        # Another caller won the race on the unique key. Theirs is the answer;
        # this is the ordinary outcome of two workers, not an error.
        db.rollback()
        existing = db.execute(
            select(SandboxAnalysis).where(SandboxAnalysis.idempotency_key == key)
        ).scalars().first()
        if existing is None:
            raise
        logger.info("Sandbox analysis %s already existed for key %s", existing.id, key)
        return existing, False

    db.refresh(row)
    return row, True


def claim_for_work(db: Session, analysis_id: uuid.UUID | str) -> SandboxAnalysis | None:
    """Lock the row so only one worker drives this analysis.

    FOR UPDATE rather than an advisory lock: the row is the thing being
    contended for, the transaction is short, and the lock dies with the worker
    if it is killed mid-analysis.
    """
    try:
        parsed = uuid.UUID(str(analysis_id))
    except ValueError:
        return None
    return db.execute(
        select(SandboxAnalysis).where(SandboxAnalysis.id == parsed).with_for_update()
    ).scalars().first()


def transition(
    db: Session,
    row: SandboxAnalysis,
    new_status: str,
    *,
    actor: str | None = None,
    note: str | None = None,
    error: str | None = None,
    commit: bool = True,
) -> SandboxAnalysis:
    """Move to a state and record that it happened.

    Every change goes through here so `state_history` is complete. A workflow
    that sets `row.status` directly is a workflow whose audit trail lies.
    """
    if new_status not in ALL_STATUSES:
        raise ValueError(f"Unknown sandbox analysis status: {new_status!r}")

    previous = row.status
    row.status = new_status
    if error is not None:
        # Redacted at the boundary; see cape_client.redact.
        row.error = str(error)[:2000]
    if new_status == STATUS_SUBMITTED and row.submitted_at is None:
        row.submitted_at = datetime.now(timezone.utc)
    if new_status in TERMINAL_STATUSES:
        row.completed_at = datetime.now(timezone.utc)

    _append_history(row, new_status, actor=actor, note=note, previous=previous)
    if commit:
        db.commit()
    logger.info(
        "Sandbox analysis %s: %s -> %s%s", row.id, previous, new_status,
        f" ({note})" if note else "",
    )
    return row


def _append_history(
    row: SandboxAnalysis, status: str, *, actor: str | None = None,
    note: str | None = None, previous: str | None = None,
) -> None:
    entry = {
        "status": status,
        "from": previous,
        "at": datetime.now(timezone.utc).isoformat(),
        "actor": actor or "system",
    }
    if note:
        entry["note"] = str(note)[:300]
    # Reassigned rather than appended: SQLAlchemy does not see in-place
    # mutation of a JSONB list, so an append alone would never be persisted.
    row.state_history = list(row.state_history or []) + [entry]


def is_expired(row: SandboxAnalysis, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    deadline = row.deadline_at
    if deadline is None:
        return False
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline < now


def resumable(db: Session, *, limit: int = 50) -> list[SandboxAnalysis]:
    """Analyses a restarted worker should pick back up.

    The workflow survives a restart because its state is in Postgres, not in
    the worker: anything not terminal is still owed an answer.
    """
    return list(
        db.execute(
            select(SandboxAnalysis)
            .where(SandboxAnalysis.status.in_(tuple(ACTIVE_STATUSES)))
            .order_by(SandboxAnalysis.created_at.asc())
            .limit(limit)
        ).scalars().all()
    )


def to_public_dict(row: SandboxAnalysis) -> dict[str, Any]:
    """What an API may return.

    Nothing provider-secret appears here: no token, no base URL, no headers.
    `raw_summary` is a bounded reference to the CAPE task, not the report.
    """
    return {
        "id": str(row.id),
        "provider": row.provider,
        "status": row.status,
        "target_kind": getattr(row, "target_kind", "file") or "file",
        "target_url": getattr(row, "target_url", None),
        "verdict": row.verdict,
        "malscore": row.malscore,
        "sha256": row.sha256,
        "sha1": row.sha1,
        "md5": row.md5,
        "sample_name": row.sample_name,
        "sample_size": row.sample_size,
        "sample_type": row.sample_type,
        "client": row.client,
        "investigation_id": str(row.investigation_id) if row.investigation_id else None,
        "alert_run_id": str(row.alert_run_id) if row.alert_run_id else None,
        "artifact_id": str(row.artifact_id) if row.artifact_id else None,
        "provider_task_id": row.provider_task_id,
        "reused_existing": bool(row.reused_existing),
        "policy_version": row.policy_version,
        "run_seq": row.run_seq,
        "poll_attempts": row.poll_attempts,
        "error": row.error,
        "requested_by": row.requested_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "submitted_at": row.submitted_at.isoformat() if row.submitted_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "limitations": sample_limitations(sample_name=row.sample_name, sample_type=row.sample_type),
        "state_history": list(row.state_history or [])[-25:],
        "raw_summary": dict(row.raw_summary or {}),
    }
