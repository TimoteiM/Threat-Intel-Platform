"""Collect an investigation's steps, then write them once.

**Fail-open in the pipeline, fail-loud in the record.** A recording bug must
never take an investigation down — the pipeline is the product and this is a
narration of it. But a recorder that drops three of eight steps and then
renders as a complete five-step chain is the defect this record exists to
close, one level up. So every way a step can fail to record produces an entry
in `incomplete_steps`, the record carries `incomplete = True`, and the page
says so above the chain.

**Validated per step, not at the end.** Each step's fields are round-tripped
through JSON the moment they are offered. A step that cannot be serialised
becomes one `incomplete_steps` entry; it does not poison the insert and lose
the other seven. Deferring validation to `persist` would make one bad field
cost the whole chain, which is the failure mode that produces a silent short
chain rather than a visible gap.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator

logger = logging.getLogger(__name__)

#: Per-step response excerpt cap. These rows hold customer data, so the
#: excerpt is bounded and the truncation is recorded rather than silent — a
#: truncated response read as the whole response is the floor-as-fact shape.
EXCERPT_LIMIT_BYTES = 4096


def _jsonable(value: Any) -> Any:
    """`value` if it survives a JSON round-trip, else raise."""
    return json.loads(json.dumps(value, default=str))


class InvestigationRecorder:
    """Accumulates steps in memory. Nothing touches the database until
    `persist`, so a long pipeline holds one transaction's worth of work rather
    than a connection for its duration."""

    def __init__(self, *, origin_surface: str, origin_id: str,
                 tenant_id: str | None = None,
                 actor_kind: str = "automated_ingest",
                 actor_user_id: Any = None,
                 actor_recorded: str | None = None) -> None:
        self.origin_surface = origin_surface
        self.origin_id = str(origin_id)
        self.tenant_id = tenant_id
        self.actor_kind = actor_kind
        self.actor_user_id = actor_user_id
        self.actor_recorded = actor_recorded
        # The email pipeline runs the indicator checks and the sandbox in two
        # threads under one `asyncio.gather`, and both record. `list.append`
        # is atomic under the GIL but `self._ordinal += 1` is not, so two
        # concurrent steps could take the same ordinal — two steps claiming to
        # be the third, in a chain whose whole point is order.
        self._lock = threading.Lock()
        self.steps: list[dict[str, Any]] = []
        self.incomplete_steps: list[dict[str, Any]] = []
        self.model_calls = 0
        self.observables_stopped = 0
        self.steps_escalated = 0
        self._ordinal = 0

    # -- recording ---------------------------------------------------------

    def step(
        self,
        kind: str,
        question: str,
        *,
        source: str | None = None,
        target: str | None = None,
        query: Any = None,
        response: Any = None,
        verdict: str | None = None,
        observables_found: Any = None,
        observables_selected: Any = None,
        warrant: Any = None,
        absence_kind: str | None = None,
        absence_reason: str | None = None,
        duration_ms: int | None = None,
        cost: Any = None,
        fields: Any = None,
    ) -> None:
        """Record one step. Never raises."""
        with self._lock:
            self._ordinal += 1
            ordinal = self._ordinal
        try:
            excerpt, truncated, size = self._excerpt(response)
            entry = {
                "ordinal": ordinal,
                "kind": str(kind),
                "question": str(question),
                "source": source,
                "target": (str(target)[:512] if target else None),
                "query": _jsonable(query or {}),
                "response_excerpt": excerpt,
                "response_truncated": truncated,
                "response_bytes": size,
                "verdict": verdict,
                "observables_found": _jsonable(observables_found or []),
                "observables_selected": _jsonable(observables_selected or []),
                "warrant": _jsonable(warrant or {}),
                "absence_kind": absence_kind,
                "absence_reason": absence_reason,
                "duration_ms": duration_ms,
                "cost": _jsonable(cost or {}),
                # The template's inputs. Kept separate from the evidence
                # fields so a template can never read a raw response.
                "fields": _jsonable(fields or {}),
            }
            with self._lock:
                self.steps.append(entry)
                if cost and any((cost or {}).values()):
                    self.steps_escalated += 1
                if (cost or {}).get("model_calls"):
                    self.model_calls += int(cost["model_calls"])
        except Exception as exc:  # noqa: BLE001
            self.fail(ordinal, kind, f"{type(exc).__name__}: {exc}")

    def fail(self, ordinal: int, kind: str, reason: str) -> None:
        """Note that a step could not be recorded. This is the loud half."""
        logger.warning("investigation step %s (%s) not recorded: %s",
                       ordinal, kind, reason)
        with self._lock:
            self.incomplete_steps.append({
                "ordinal": ordinal, "kind": str(kind), "reason": str(reason)[:500],
            })

    @contextmanager
    def timed(self, kind: str, question: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Time a stage and record it, whatever happens inside.

        A stage that raises still records a step — with `check_failed` — so a
        failure appears in the chain rather than shortening it.
        """
        started = time.perf_counter()
        carrier: dict[str, Any] = {}
        try:
            yield carrier
        except Exception as exc:  # noqa: BLE001
            self.step(
                kind, question,
                absence_kind="check_failed",
                absence_reason=(
                    f"This step did not complete ({type(exc).__name__}), so "
                    f"its question is unanswered rather than answered in the "
                    f"negative."
                ),
                duration_ms=int((time.perf_counter() - started) * 1000),
                fields={"question_text": question,
                        "reason": f"it did not complete ({type(exc).__name__})."},
                **kwargs,
            )
            raise
        merged = {**kwargs, **carrier}
        merged["duration_ms"] = int((time.perf_counter() - started) * 1000)
        self.step(kind, question, **merged)

    def _excerpt(self, response: Any) -> tuple[str | None, bool, int | None]:
        if response is None:
            return None, False, None
        text = response if isinstance(response, str) else json.dumps(
            response, default=str, sort_keys=True)
        from app.services.log_secret_sanitizer import sanitize_text
        try:
            # Returns a SanitizedLog, not a str. Taking the object as a string
            # would store `SanitizedLog(text=...)` — the secret inside a repr,
            # which is worse than not sanitising because it looks sanitised.
            sanitised = sanitize_text(text)
            text = sanitised.text
            redactions = sanitised.total
        except Exception:  # noqa: BLE001
            # Belt as well as braces: an unsanitised excerpt is not stored.
            return None, True, None
        if redactions:
            logger.info("investigation step excerpt: %d value(s) redacted",
                        redactions)
        size = len(text.encode("utf-8"))
        if size <= EXCERPT_LIMIT_BYTES:
            return text, False, size
        return text[:EXCERPT_LIMIT_BYTES], True, size

    # -- persistence -------------------------------------------------------

    def ordered_steps(self) -> list[dict[str, Any]]:
        """Steps by ordinal. Recorded from two threads, so insertion order is
        arrival order and not the chain's order."""
        with self._lock:
            return sorted(self.steps, key=lambda s: s["ordinal"])

    def as_record(self, *, verdict: str | None = None,
                  summary: str | None = None,
                  summary_unverified_entities: Any = None,
                  summary_unverified_numerals: Any = None) -> dict[str, Any]:
        return {
            "origin_surface": self.origin_surface,
            "origin_id": self.origin_id,
            "tenant_id": self.tenant_id,
            "actor_kind": self.actor_kind,
            "actor_user_id": self.actor_user_id,
            "actor_recorded": self.actor_recorded,
            "verdict": verdict,
            "summary": summary,
            "summary_unverified_entities": list(summary_unverified_entities or []),
            "summary_unverified_numerals": list(summary_unverified_numerals or []),
            "incomplete": bool(self.incomplete_steps),
            "incomplete_steps": list(self.incomplete_steps),
            "steps_run": len(self.steps),
            "steps_escalated": self.steps_escalated,
            "observables_stopped": self.observables_stopped,
            "model_calls": self.model_calls,
        }


class NullRecorder(InvestigationRecorder):
    """Records nothing, same interface.

    So the pipeline has no `if recorder:` branches — a conditional around
    every recording call is eight places for the recorder to be forgotten,
    and the forgetting would be invisible.
    """

    def __init__(self) -> None:
        super().__init__(origin_surface="none", origin_id="none")

    def step(self, *a: Any, **k: Any) -> None:  # noqa: D102
        return None

    def fail(self, *a: Any, **k: Any) -> None:  # noqa: D102
        return None


def persist_sync(recorder: InvestigationRecorder, db: Any, *,
                 verdict: str | None = None, summary: str | None = None,
                 summary_unverified_entities: Any = None,
                 summary_unverified_numerals: Any = None) -> Any:
    """Write the record and its steps in one transaction. Never raises.

    Returns the record's id, or `None` if nothing could be written — in which
    case the caller's investigation is unaffected, which is the fail-open half
    of the contract. The loud half is `incomplete_steps`, already on the
    record by the time this runs.

    Idempotent on `(origin_surface, origin_id)`: a re-derived chain replaces
    the previous one rather than accumulating a second copy of the same
    investigation, because two chains for one run is a question nobody can
    answer from the page.
    """
    from sqlalchemy import delete, select

    from app.models.database import InvestigationRecord, InvestigationStep

    try:
        existing = db.execute(
            select(InvestigationRecord.id).where(
                InvestigationRecord.origin_surface == recorder.origin_surface,
                InvestigationRecord.origin_id == recorder.origin_id,
            )
        ).scalars().all()
        if existing:
            db.execute(delete(InvestigationRecord).where(
                InvestigationRecord.id.in_(existing)))

        fields = recorder.as_record(
            verdict=verdict, summary=summary,
            summary_unverified_entities=summary_unverified_entities,
            summary_unverified_numerals=summary_unverified_numerals,
        )
        record = InvestigationRecord(**fields)
        db.add(record)
        db.flush()
        for entry in recorder.ordered_steps():
            payload = {k: v for k, v in entry.items() if k != "fields"}
            # `fields` are the template's inputs. Stored inside `query` rather
            # than as a column of their own, so there is exactly one place a
            # renderer reads from and it is never the raw response.
            payload["query"] = {"template_fields": entry.get("fields") or {},
                                **(payload.get("query") or {})}
            db.add(InvestigationStep(record_id=record.id, **payload))
        db.commit()
        return record.id
    except Exception as exc:  # noqa: BLE001
        logger.error("investigation record not persisted (%s): %s",
                     recorder.origin_id, type(exc).__name__)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
