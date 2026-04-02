"""
Hybrid Analysis collector.

Supports URL/hash/file/domain observables and returns cached sandbox verdicts.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.collectors.base import BaseCollector
from app.db.session import sync_engine
from app.models.database import Artifact
from app.models.schemas import CollectorMeta, HybridAnalysisEvidence, HybridAnalysisItem
from app.services.hybrid_analysis_service import lookup_hybrid_analysis


class HybridAnalysisCollector(BaseCollector):
    name = "hybrid_analysis"
    supported_types = frozenset({"domain", "url", "hash", "file"})

    def _collect(self) -> HybridAnalysisEvidence:
        evidence = HybridAnalysisEvidence()
        indicator_type = "url"
        indicator = self.domain
        file_bytes: bytes | None = None
        file_name: str | None = None
        submit_on_not_found = False

        if self.observable_type in {"hash", "file"}:
            indicator_type = "hash"
            # For uploaded file submissions (hash mode), fallback to quick-scan file
            # when hash lookup is not yet present in Hybrid.
            file_name, file_bytes = self._load_uploaded_file()
            submit_on_not_found = bool(file_bytes)
        elif self.observable_type == "domain":
            indicator_type = "url"
            indicator = f"https://{self.domain}"
            submit_on_not_found = True
        elif self.observable_type == "url":
            submit_on_not_found = True

        result = lookup_hybrid_analysis(
            indicator=indicator,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            submit_on_not_found=submit_on_not_found,
            sandbox_first=bool(self.observable_type in {"domain", "url"}),
        )
        item = HybridAnalysisItem(
            checked=bool(result.get("checked")),
            indicator_type=str(result.get("indicator_type") or indicator_type),
            verdict=str(result.get("verdict") or "unknown"),
            analysis_id=result.get("analysis_id"),
            threat_score=result.get("threat_score"),
            error=result.get("error"),
            cache_hit=result.get("cache_hit"),
            dynamic_io_summary=result.get("dynamic_io_summary") or {},
            raw_summary=result.get("raw_summary") or {},
        )
        evidence.items = [item]
        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> HybridAnalysisEvidence:
        return HybridAnalysisEvidence(meta=meta)

    def _load_uploaded_file(self) -> tuple[str | None, bytes | None]:
        if not self.file_artifact_id:
            return None, None
        try:
            with Session(sync_engine) as db:
                art = db.get(Artifact, self.file_artifact_id)
                if not art:
                    return None, None
                path = Path(str(art.storage_path or "")).expanduser()
                if not path.is_absolute():
                    path = Path("/app") / path
                if not path.exists() or not path.is_file():
                    return art.artifact_name, None
                return art.artifact_name, path.read_bytes()
        except Exception:
            return None, None
