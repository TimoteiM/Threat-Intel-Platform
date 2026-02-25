"""
IP Lookup Tool — standalone IP reputation check with persistent history.

POST   /api/tools/ip-lookup              → Run lookup + save to history
GET    /api/tools/ip-lookup/history      → List past lookups (most recent first)
GET    /api/tools/ip-lookup/history/{id} → Get a specific saved lookup
DELETE /api/tools/ip-lookup/history/{id} → Delete a saved lookup
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from datetime import datetime, timezone

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, delete

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import IPLookup

router = APIRouter(tags=["tools"])
logger = logging.getLogger(__name__)

ABUSEIPDB_CATEGORIES: dict[int, str] = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class IPLookupRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v.strip()


# ─── Lookup ───

@router.post("/api/tools/ip-lookup")
async def ip_lookup(request: IPLookupRequest, session: DBSession):
    """
    Run an IP reputation check (AbuseIPDB verbose + ThreatFox).
    Result is saved to history and returned immediately.
    """
    settings = get_settings()
    ip = request.ip
    result: dict = {
        "ip": ip,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "abuseipdb": None,
        "threatfox": [],
        "errors": [],
    }

    # ── AbuseIPDB (verbose) ──
    if not settings.abuseipdb_api_key:
        result["errors"].append("AbuseIPDB API key not configured")
    else:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            if data:
                reports = data.get("reports", [])
                all_cats: list[int] = []
                for report in reports:
                    all_cats.extend(report.get("categories", []))
                unique_cats = list(set(all_cats))

                recent_reports = [
                    {
                        "reported_at": r.get("reportedAt"),
                        "comment": (r.get("comment") or "").strip()[:300],
                        "categories": r.get("categories", []),
                        "category_labels": [
                            ABUSEIPDB_CATEGORIES.get(c, f"Cat {c}")
                            for c in r.get("categories", [])
                        ],
                        "reporter_country": r.get("reporterCountryCode"),
                    }
                    for r in sorted(
                        reports,
                        key=lambda r: r.get("reportedAt", ""),
                        reverse=True,
                    )[:15]
                ]

                result["abuseipdb"] = {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "isp": data.get("isp"),
                    "usage_type": data.get("usageType"),
                    "country_code": data.get("countryCode"),
                    "country_name": data.get("countryName"),
                    "domain": data.get("domain"),
                    "hostnames": data.get("hostnames", [])[:10],
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "categories": unique_cats,
                    "category_labels": [
                        ABUSEIPDB_CATEGORIES.get(c, f"Category {c}")
                        for c in unique_cats
                    ],
                    "recent_reports": recent_reports,
                }
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
            result["errors"].append(f"AbuseIPDB: {type(e).__name__}")

    # ── ThreatFox ──
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            headers={"API-KEY": ""},
            timeout=15,
        )
        resp.raise_for_status()
        tf_data = resp.json()
        if tf_data.get("query_status") == "ok":
            for ioc in tf_data.get("data", []) or []:
                result["threatfox"].append({
                    "ioc_value": ioc.get("ioc", ip),
                    "ioc_type": ioc.get("ioc_type", "ip:port"),
                    "threat_type": ioc.get("threat_type", "unknown"),
                    "malware": ioc.get("malware_printable") or ioc.get("malware"),
                    "confidence_level": ioc.get("confidence_level"),
                    "first_seen": ioc.get("first_seen"),
                    "last_seen": ioc.get("last_seen"),
                    "tags": ioc.get("tags") or [],
                })
    except Exception as e:
        logger.debug(f"ThreatFox lookup failed for {ip}: {e}")
        result["errors"].append(f"ThreatFox: {type(e).__name__}")

    # ── Persist to history ──
    ab = result.get("abuseipdb")
    record = IPLookup(
        id=uuid.uuid4(),
        ip=ip,
        abuse_score=ab.get("abuse_confidence_score") if ab else None,
        isp=ab.get("isp") if ab else None,
        country_code=ab.get("country_code") if ab else None,
        threatfox_count=len(result["threatfox"]),
        result_json=result,
        queried_at=datetime.now(timezone.utc),
    )
    session.add(record)
    await session.flush()

    result["id"] = str(record.id)
    return result


# ─── History ───

@router.get("/api/tools/ip-lookup/history")
async def list_ip_lookup_history(session: DBSession, limit: int = 50, offset: int = 0):
    """List past IP lookups, most recent first."""
    stmt = (
        select(IPLookup)
        .order_by(IPLookup.queried_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [_to_list_item(r) for r in rows]


@router.get("/api/tools/ip-lookup/history/{lookup_id}")
async def get_ip_lookup(lookup_id: str, session: DBSession):
    """Retrieve a specific saved IP lookup result."""
    try:
        uid = uuid.UUID(lookup_id)
    except ValueError:
        raise HTTPException(400, "Invalid lookup ID")

    row = await session.get(IPLookup, uid)
    if not row:
        raise HTTPException(404, "Lookup not found")
    return row.result_json | {"id": str(row.id)}


@router.delete("/api/tools/ip-lookup/history/{lookup_id}", status_code=204)
async def delete_ip_lookup(lookup_id: str, session: DBSession):
    """Delete a saved lookup from history."""
    try:
        uid = uuid.UUID(lookup_id)
    except ValueError:
        raise HTTPException(400, "Invalid lookup ID")

    await session.execute(delete(IPLookup).where(IPLookup.id == uid))


# ─── Helper ───

def _to_list_item(row: IPLookup) -> dict:
    return {
        "id": str(row.id),
        "ip": row.ip,
        "abuse_score": row.abuse_score,
        "isp": row.isp,
        "country_code": row.country_code,
        "threatfox_count": row.threatfox_count,
        "queried_at": row.queried_at.isoformat() if row.queried_at else None,
    }
