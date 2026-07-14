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
from app.services.anyrun_intelligence import build_anyrun_sandbox_intelligence
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

        network_profile = self.external_context.get("network_profile") if isinstance(self.external_context, dict) else {}
        proxy_country = str((network_profile or {}).get("proxy_country") or "").strip() or None
        use_residential_proxy = bool((network_profile or {}).get("use_residential_proxy") or proxy_country)
        result = lookup_hybrid_analysis(
            indicator=indicator,
            indicator_type=indicator_type,
            file_bytes=file_bytes,
            file_name=file_name,
            submit_on_not_found=submit_on_not_found,
            # TI lookup must run first so existing MALICIOUS community reports are
            # trusted over a fresh sandbox that may return CLEAN (e.g. phishing pages
            # that require user interaction). sandbox_first would bypass TI entirely.
            sandbox_first=False,
            use_residential_proxy=use_residential_proxy,
            proxy_country=proxy_country,
        )
        def _make_item(r: dict, *, is_primary: bool = True) -> HybridAnalysisItem:
            raw = r.get("raw_summary") or {}
            # Tags live in raw_summary.tags (AnyRun community tags like "phishing", "credential-harvesting")
            _tags = list(raw.get("tags") or [])
            sandbox_intelligence = build_anyrun_sandbox_intelligence(r)
            return HybridAnalysisItem(
                checked=bool(r.get("checked")),
                indicator_type=str(r.get("indicator_type") or indicator_type),
                verdict=str(r.get("verdict") or "unknown"),
                provider_verdict=r.get("provider_verdict"),
                verdict_context=r.get("verdict_context") or raw.get("verdict_context") or {},
                analysis_id=r.get("analysis_id"),
                analysis_link=r.get("analysis_link"),
                threat_score=r.get("threat_score"),
                threat_names=list(r.get("threat_names") or []),
                tags=_tags,
                error=r.get("error"),
                cache_hit=r.get("cache_hit"),
                dynamic_io_summary=r.get("dynamic_io_summary") or {},
                raw_summary=raw,
                sandbox_intelligence=sandbox_intelligence,
                # domain_intelligence only on the primary row to avoid duplication
                domain_intelligence=r.get("domain_intelligence") or None if is_primary else None,
            )

        items = [_make_item(result, is_primary=True)]
        for extra in list(result.get("additional_items") or []):
            items.append(_make_item(extra, is_primary=False))

        evidence.items = items
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
