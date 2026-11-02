"""CAPE evidence for an observable: what CAPE knows, and a detonation if it does not.

The collector first *looks up* what CAPE — or this platform's own record of
CAPE — already knows. If nothing is known and the caller has said a detonation
is warranted, it starts one and waits a bounded number of seconds for it.

It does not wait for the detonation to finish, because on this instance it will
not: measured over the URL analyses in the record, a fresh one takes 271-321
seconds, of which 180 is the enforced in-VM analysis timeout. What the wait
does catch is an analysis CAPE had already run, or one adopted from an earlier
submission, which returns in about a second. Everything else is deferred: the
workflow in tasks/cape_task.py owns it from there, and when the report lands it
is written into this investigation's evidence and the analyst is re-run over it
(_annotate_investigation). Nobody has to press anything.

Submitting from here rather than from an analyst's button is the difference
between a report arriving five minutes into an investigation and arriving five
minutes after somebody notices it is missing.

Two different questions, depending on the observable:

* **hash / file** — ask CAPE directly whether it has analysed this sample
  (`tasks/search/sha256`). This is the case an alert carrying a hash hits.
* **domain / ip / url** — asks CAPE which of *its* analyses contacted the
  host, through POST /tasks/extendedsearch/. The GET /tasks/search/ route
  accepts only file hashes — /tasks/search/domain/ returns 404 on this
  instance — which is why the first version of this collector answered domains
  from our own records alone. It still falls back to those, because an
  analysis this platform ran and CAPE has since pruned is still evidence.
"""

from __future__ import annotations

import json
import logging
import time
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.collectors.base import BaseCollector
from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import SandboxAnalysis
from app.models.schemas import CapeEvidence, CapeNormalizedReport, CollectorMeta
from app.services import cape_analysis_service as svc
from app.services import cape_client as cape

logger = logging.getLogger(__name__)

_MAX_MATCHES = 5


class CapeCollector(BaseCollector):
    name = "cape"
    supported_types = frozenset({"hash", "file", "domain", "ip", "url"})

    def _collect(self) -> CapeEvidence:
        evidence = CapeEvidence()
        settings = get_settings()

        if not settings.cape_configured:
            evidence.reason = "CAPE sandbox integration is not configured."
            return evidence

        try:
            if self.observable_type in {"hash", "file"}:
                return self._by_hash(settings)
            return self._by_indicator()
        except cape.CapeError as exc:
            # A sandbox that cannot be reached is a gap in the evidence, not a
            # failed investigation. Say so and let the rest of the run stand.
            evidence.reason = cape.redact(str(exc))[:300]
            logger.info("CAPE collector could not answer for %s: %s", self.domain, evidence.reason)
            return evidence

    # -- hash / file ---------------------------------------------------------

    def _by_hash(self, settings) -> CapeEvidence:
        evidence = CapeEvidence()
        digest = str(self.domain or "").strip().lower()

        if self.file_artifact_id and len(digest) != 64:
            digest = self._artifact_digest() or digest
        if len(digest) != 64:
            evidence.reason = "Not a SHA-256; CAPE is searched by SHA-256 only."
            return evidence

        # Ours first: if this platform already detonated the sample we have the
        # normalized report on hand and need not ask CAPE at all.
        stored = self._stored_for_hash(digest)
        if stored is not None:
            evidence.available = True
            evidence.report = stored
            return evidence

        with cape.CapeClient(settings=settings) as client:
            tasks = client.search_by_sha256(digest)
            reported = [t for t in tasks if t.status == "reported"]
            if not reported:
                evidence.reason = (
                    "CAPE has no completed analysis for this hash. "
                    "Submit the file to detonate it."
                    if not tasks else
                    f"CAPE has {len(tasks)} analysis/analyses for this hash, none completed yet."
                )
                return evidence

            task_id = max(t.task_id for t in reported)
            report = client.fetch_report(task_id, formats=settings.cape_report_format_list)

        from app.services.cape_normalizer import normalize_report

        evidence.available = True
        evidence.report = normalize_report(
            report.payload, task_id=task_id, report_format=report.fmt, report_size_bytes=report.size_bytes
        )
        self._store_artifact(f"cape_task_{task_id}.json", json.dumps(report.payload)[:2_000_000].encode())
        return evidence

    def _artifact_digest(self) -> str | None:
        from app.models.database import Artifact

        with Session(sync_engine) as db:
            artifact = db.get(Artifact, self.file_artifact_id)
            return str(artifact.sha256_hash).lower() if artifact and artifact.sha256_hash else None

    def _stored_for_hash(self, digest: str) -> CapeNormalizedReport | None:
        with Session(sync_engine) as db:
            row = db.execute(
                select(SandboxAnalysis)
                .where(
                    SandboxAnalysis.sha256 == digest,
                    SandboxAnalysis.provider == svc.PROVIDER_CAPE,
                    SandboxAnalysis.status == svc.STATUS_REPORTED,
                )
                .order_by(SandboxAnalysis.created_at.desc())
                .limit(1)
            ).scalars().first()
            if row is None or not row.normalized_json:
                return None
            return _as_report(row.normalized_json)

    # -- domain / ip / url ---------------------------------------------------

    def _by_indicator(self) -> CapeEvidence:
        """Which analyses — CAPE's or ours — touched this host."""
        evidence = CapeEvidence()
        needle = self._indicator_value()
        if not needle:
            evidence.reason = "No usable indicator value."
            return evidence

        # 1. CAPE itself. Its store covers every analysis the instance has run,
        #    including ones this platform never asked for.
        remote = self._ask_cape(needle)
        if remote is not None:
            evidence.available = True
            evidence.report = remote
            return evidence

        # 2. Ours, as a fallback: an analysis we ran and CAPE has since pruned
        #    is still evidence.
        matches: list[SandboxAnalysis] = []
        with Session(sync_engine) as db:
            for field in ("domains", "dns_queries", "tls_sni", "hosts"):
                rows = db.execute(
                    select(SandboxAnalysis)
                    .where(
                        SandboxAnalysis.status == svc.STATUS_REPORTED,
                        text(
                            f"normalized_json->'network'->'{field}' @> CAST(:needle AS jsonb)"
                        ).bindparams(needle=json.dumps([needle])),
                    )
                    .order_by(SandboxAnalysis.created_at.desc())
                    .limit(_MAX_MATCHES)
                ).scalars().all()
                matches.extend(rows)
                if matches:
                    break

        if not matches:
            # 3. Nothing known. Detonate it, if this caller asked for that.
            detonated = self._detonate_and_wait()
            if detonated is not None:
                return detonated
            evidence.reason = (
                f"No CAPE analysis has contacted {needle}. Searched CAPE's own "
                "analyses and this platform's stored detonations."
            )
            return evidence

        best = matches[0]
        evidence.available = True
        evidence.report = _as_report(best.normalized_json)
        if evidence.report is not None:
            evidence.report.limitations = list(evidence.report.limitations) + [
                f"Matched because CAPE task {best.provider_task_id} contacted {needle} "
                f"while detonating {best.sample_name or best.sha256[:16]}."
            ]
        return evidence

    def _detonate_and_wait(self) -> CapeEvidence | None:
        """Start a detonation for this target and wait a bounded time for it.

        Returns None when no detonation was warranted, so the caller keeps its
        own wording for "nothing known".

        The wait watches our own row rather than polling CAPE, because the
        workflow task owns the conversation with CAPE and its throttle handling.
        Two pollers on a service that rate-limits at one request per five
        seconds would mostly succeed in throttling each other.
        """
        settings = get_settings()
        if not settings.cape_auto_detonate_urls:
            return None
        # An IP is not something CAPE can fetch and detonate; the lookup above is
        # the whole of what this collector can say about one.
        if self.observable_type not in {"domain", "url"}:
            return None

        context = self.external_context if isinstance(self.external_context, dict) else {}
        # The caller decides. The same gate that decides whether AnyRun is worth
        # its cost decides this, and it is evaluated once, in the investigation
        # task, with the fast collectors' evidence in hand. A collector that
        # decided for itself would detonate every URL in every pasted alert.
        if not context.get("cape_detonate"):
            return None

        target = svc.normalise_url(self.domain)
        if not target:
            return None

        evidence = CapeEvidence()
        try:
            analysis_id, task_id, status = self._start(target, context)
        except Exception as exc:  # noqa: BLE001 — a failed submission is a gap, not a crash
            # The detail goes to the log, not to the panel. What surfaced here
            # first was a psycopg2 foreign-key error, which tells an analyst
            # nothing and looks like the sandbox misbehaving.
            logger.warning(
                "[%s] CAPE auto-detonation of %s could not start: %s",
                self.investigation_id, target, cape.redact(str(exc))[:400],
            )
            evidence.reason = (
                "Could not start a CAPE detonation for this target; the sandbox was not asked. "
                "The reason is in the worker log."
            )
            return evidence

        deadline = time.monotonic() + max(0, int(settings.cape_inline_wait_seconds))
        interval = max(5, int(settings.cape_inline_poll_seconds))
        while True:
            report, status, task_id = self._read_analysis(analysis_id)
            if report is not None:
                evidence.available = True
                evidence.report = report
                return evidence
            if status in svc.TERMINAL_STATUSES:
                evidence.reason = (
                    f"CAPE detonation of {target} finished as {status} without a report."
                )
                return evidence
            if time.monotonic() >= deadline:
                break
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))

        # Deferred, not failed. Nothing is lost by stopping here: the workflow
        # keeps polling, and when the report lands it is written into this
        # investigation and the analyst runs again over it.
        evidence.pending = True
        evidence.pending_analysis_id = str(analysis_id)
        evidence.pending_task_id = str(task_id) if task_id else None
        evidence.pending_since = datetime.now(timezone.utc).isoformat()
        evidence.reason = (
            f"Detonating {target} in CAPE"
            + (f" as task {task_id}" if task_id else "")
            + f" — still {status} after {settings.cape_inline_wait_seconds}s. A URL detonation on "
              "this instance takes about five minutes; the report is merged into this "
              "investigation and the verdict recomputed as soon as it lands. No action needed."
        )
        logger.info(
            "[%s] CAPE detonation of %s deferred after %ss (analysis %s, task %s)",
            self.investigation_id, target, settings.cape_inline_wait_seconds, analysis_id, task_id,
        )
        return evidence

    def _start(self, target: str, context: dict[str, Any]) -> tuple[Any, str | None, str]:
        """Create (or adopt) the analysis row and make sure something is driving it."""
        from app.tasks.cape_task import run_cape_analysis

        investigation_uuid = _as_uuid(self.investigation_id)
        with Session(sync_engine) as db:
            row, created = svc.get_or_create(
                db,
                target_kind="url",
                target_url=target,
                client=str(context.get("client_domain") or "") or None,
                sample_name=self.domain,
                investigation_id=investigation_uuid,
                requested_by="auto-detonation",
            )
            analysis_id, task_id, status = row.id, row.provider_task_id, row.status
            db.commit()

        if created:
            run_cape_analysis.delay(str(analysis_id))
            logger.info("[%s] CAPE auto-detonation queued for %s (analysis %s)",
                        self.investigation_id, target, analysis_id)
        else:
            # Somebody already asked — an earlier investigation of the same URL,
            # or another worker a millisecond ago. Watch theirs. If it is sitting
            # in a non-terminal state with nothing driving it, the beat job
            # `cape-resume-in-flight` picks it up within five minutes.
            logger.info("[%s] CAPE auto-detonation adopted existing analysis %s (%s)",
                        self.investigation_id, analysis_id, status)
        return analysis_id, task_id, status

    def _read_analysis(self, analysis_id: Any) -> tuple[CapeNormalizedReport | None, str, str | None]:
        with Session(sync_engine) as db:
            row = db.get(SandboxAnalysis, analysis_id)
            if row is None:
                return None, svc.STATUS_FAILED, None
            status = str(row.status or "")
            task_id = str(row.provider_task_id) if row.provider_task_id else None
            if status == svc.STATUS_REPORTED and row.normalized_json:
                return _as_report(row.normalized_json), status, task_id
            return None, status, task_id

    def _ask_cape(self, needle: str) -> CapeNormalizedReport | None:
        """CAPE's own analyses that contacted this indicator.

        The search response is report-shaped already — info, target, network
        and malscore — so the match is normalized straight from it rather than
        pulling the full report, which runs to tens of megabytes for one task.
        """
        from app.services.cape_normalizer import normalize_report

        options = ["ip"] if self.observable_type == "ip" else ["domain"]
        if self.observable_type == "url":
            options = ["url", "domain"]

        settings = get_settings()
        try:
            with cape.CapeClient(settings=settings) as client:
                for option in options:
                    argument = self.domain if option == "url" else needle
                    hits = client.search_reports(option, argument)
                    if not hits:
                        continue
                    best = max(hits, key=lambda h: _as_int((h.get("info") or {}).get("id")))
                    report = normalize_report(best, task_id=(best.get("info") or {}).get("id"))
                    report.limitations = list(report.limitations) + [
                        f"Matched because CAPE task {report.task_id} contacted {argument} "
                        f"while analysing {report.file_name or 'another sample'}."
                    ]
                    return report
        except cape.CapeError as exc:
            # A search failure is a gap, not a verdict. Fall through to ours.
            logger.info("CAPE indicator search failed for %s: %s", needle, cape.redact(str(exc))[:200])
        return None

    def _indicator_value(self) -> str | None:
        value = str(self.domain or "").strip().lower()
        if not value:
            return None
        if self.observable_type == "url":
            from urllib.parse import urlparse

            parsed = urlparse(value if "://" in value else f"http://{value}")
            return (parsed.hostname or "").lower() or None
        return value

    def _empty_evidence(self, meta: CollectorMeta) -> CapeEvidence:
        return CapeEvidence(meta=meta, available=False, reason="CAPE collector did not complete.")


def _as_uuid(value: Any) -> Any:
    try:
        return _uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _as_report(payload: Any) -> CapeNormalizedReport | None:
    if not isinstance(payload, dict) or not payload:
        return None
    try:
        return CapeNormalizedReport.model_validate(payload)
    except Exception:
        logger.warning("Stored CAPE report did not validate against the current schema")
        return None
