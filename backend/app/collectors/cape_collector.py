"""CAPE evidence for an observable, without ever detonating inline.

A collector runs inside an investigation and has to finish in seconds. A CAPE
detonation takes minutes, so this collector never submits: it *looks up* what
CAPE — or this platform's own record of CAPE — already knows. Submission is the
asynchronous workflow in tasks/cape_task.py, started deliberately by an analyst
or by the alert pipeline.

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
