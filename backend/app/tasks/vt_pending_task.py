"""
Collect VirusTotal scans that were still running when the investigation finished.

When VirusTotal has never seen a URL, the collector submits it and polls for a
result — twice, five seconds apart. A fresh scan usually takes longer than that,
so the investigation concludes with `found: false` and a note reading "re-run the
VT collector shortly to collect the result". Nothing ever did. The pending
analysis id was recorded and then forgotten, and the case kept a VirusTotal
section saying nothing was known while VirusTotal was, by then, answering.

One real example: the platform submitted a `.ondigitalocean.app` URL at 15:37:01,
VirusTotal stamped the analysis a second later, and the investigation still
concluded with no reputation data at all.

This task closes that loop. It finds investigations whose VT evidence carries a
pending analysis id, asks VirusTotal whether the scan finished, and folds the
result into the stored evidence.

It deliberately does not re-run the decision engine. A late VirusTotal result can
change what the verdict *should* be, and silently rewriting a conclusion an
analyst may already have acted on is worse than showing them the new evidence
next to the old verdict. The evidence records that the reputation arrived late,
so the disagreement is visible rather than hidden.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, attributes

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import Evidence, Investigation
from app.services.provider_usage_metrics import record_provider_request
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Older than this and the scan is not coming — VirusTotal expires analyses, and
# chasing week-old ids just burns quota.
MAX_AGE_HOURS = 48

# Quota guard: this runs unattended, so it takes a bounded bite each pass.
MAX_PER_RUN = 25


@celery_app.task(
    bind=True,
    name="tasks.vt_collect_pending",
    time_limit=600,
    soft_time_limit=540,
)
def collect_pending_vt_analyses(self) -> str:
    settings = get_settings()
    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        return "VirusTotal not configured"

    cutoff = datetime.now(timezone.utc) - timedelta(hours=MAX_AGE_HOURS)
    collected = still_pending = expired = 0

    with Session(sync_engine) as session:
        rows = session.execute(
            select(Evidence, Investigation)
            .join(Investigation, Investigation.id == Evidence.investigation_id)
            .where(
                Evidence.evidence_json["vt"]["pending_analysis_id"].astext.isnot(None),
                Evidence.created_at >= cutoff,
            )
            .order_by(Evidence.created_at.desc())
            .limit(MAX_PER_RUN)
        ).all()

        for evidence, investigation in rows:
            payload = dict(evidence.evidence_json or {})
            vt = dict(payload.get("vt") or {})
            analysis_id = str(vt.get("pending_analysis_id") or "").strip()
            if not analysis_id:
                continue

            result = _fetch_analysis(api_key, analysis_id, settings)
            if result is None:
                still_pending += 1
                continue
            if result == "expired":
                vt.pop("pending_analysis_id", None)
                vt.setdefault("notes", []).append(
                    "VirusTotal no longer has this analysis; the scan result was never collected."
                )
                expired += 1
            else:
                vt = _merge_result(vt, result)
                collected += 1

            payload["vt"] = vt
            evidence.evidence_json = payload
            # evidence_json is JSONB and mutated in place above; without this the
            # ORM does not notice and the update is silently dropped.
            attributes.flag_modified(evidence, "evidence_json")
            logger.info(
                "[%s] Collected late VirusTotal result for %s",
                investigation.id,
                investigation.domain,
            )

        session.commit()

    return (
        f"vt pending: {collected} collected, {still_pending} still running, {expired} expired"
    )


def _fetch_analysis(api_key: str, analysis_id: str, settings: Any) -> dict | str | None:
    """The finished analysis, `"expired"` if VT lost it, or None while it runs."""
    try:
        record_provider_request("virustotal")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": api_key},
            timeout=int(getattr(settings, "collector_timeout", 20) or 20),
        )
    except Exception as exc:
        logger.warning("VirusTotal analysis poll failed for %s: %s", analysis_id, exc)
        return None

    if response.status_code == 404:
        return "expired"
    if response.status_code != 200:
        return None

    data = response.json()
    attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
    if attrs.get("status") != "completed":
        return None
    return data


def _merge_result(vt: dict, analysis: dict) -> dict:
    """
    Fold a finished analysis into the stored VT evidence.

    Parsed here rather than through the collector's own parser because that one
    needs a live collector instance; the shape taken is the same subset the
    report and decision engine read.
    """
    attrs = (analysis.get("data", {}) or {}).get("attributes", {}) or {}
    stats = attrs.get("stats") or {}
    results = attrs.get("results") or {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)

    flagged = [
        vendor
        for vendor, outcome in results.items()
        if str((outcome or {}).get("category") or "") in {"malicious", "suspicious"}
    ]

    merged = dict(vt)
    merged.pop("pending_analysis_id", None)
    merged.update(
        {
            "found": True,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_vendors": malicious + suspicious + harmless + undetected,
            "flagged_malicious_by": sorted(flagged),
            "scope": "url",
            # Marked explicitly so the report can say the reputation arrived
            # after the verdict, rather than implying the engine had it.
            "collected_after_conclusion": True,
        }
    )
    notes = [note for note in (merged.get("notes") or []) if "still scanning" not in note]
    notes.append(
        f"VirusTotal finished this scan after the investigation concluded: "
        f"{malicious} malicious, {suspicious} suspicious of "
        f"{malicious + suspicious + harmless + undetected} vendors. "
        "The verdict on this page was reached without it."
    )
    merged["notes"] = notes
    return merged
