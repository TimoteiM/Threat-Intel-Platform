"""
Client Alert Service — checks whether a concluded investigation impacts any
registered client and creates ClientAlert records accordingly.

Called at the end of analysis_task.py after the investigation is concluded.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Client, ClientAlert, Investigation

logger = logging.getLogger(__name__)

CLASSIFICATION_SEVERITY: dict[str, str] = {
    "malicious": "critical",
    "suspicious": "high",
    "inconclusive": "medium",
    "benign": "low",
}

ALERT_TYPES = {
    "typosquatting": "Typosquatting / Domain Impersonation",
    "brand_impersonation": "Brand Keyword Match",
    "phishing_detected": "Phishing / Malicious Domain",
    "infrastructure_overlap": "Shared Infrastructure",
}


def _domain_root(domain: str) -> str:
    """Strip leading 'www.' and return lower-cased domain."""
    return domain.lower().removeprefix("www.")


def _keyword_in_domain(keywords: list[str], domain: str) -> str | None:
    """Return the first matching keyword found in the domain, or None."""
    d = domain.lower()
    for kw in keywords:
        if kw.lower() in d:
            return kw
    return None


async def check_and_create_client_alerts(
    db: AsyncSession,
    investigation: Investigation,
    report: object,  # AnalystReport Pydantic model
) -> None:
    """
    Examine a concluded investigation and create ClientAlert records for any
    registered clients whose assets are impacted.
    """
    inv_domain = _domain_root(investigation.domain)
    classification = getattr(report, "classification", None)
    if classification is None:
        return

    severity = CLASSIFICATION_SEVERITY.get(str(classification).lower(), "medium")

    # Only alert on suspicious or worse
    if str(classification).lower() == "benign":
        return

    # Fetch all active clients
    result = await db.execute(
        select(Client).where(Client.status == "active")
    )
    clients: list[Client] = list(result.scalars().all())

    if not clients:
        return

    alerts_to_add: list[ClientAlert] = []
    client_ids_updated: list[Client] = []

    for client in clients:
        client_domain_root = _domain_root(client.domain)
        alerts_for_client: list[ClientAlert] = []

        # ── 1. Exact domain match (one of client's aliases) ──
        alias_roots = [_domain_root(a) for a in (client.aliases or [])]
        if inv_domain in alias_roots:
            alerts_for_client.append(ClientAlert(
                client_id=client.id,
                investigation_id=investigation.id,
                alert_type="phishing_detected",
                severity=severity,
                title=f"Monitored alias {investigation.domain} classified as {classification}",
                details_json={
                    "investigated_domain": investigation.domain,
                    "classification": str(classification),
                    "matched_alias": investigation.domain,
                },
            ))

        # ── 2. Typosquatting: investigation was run with this client's domain as
        #       client_domain (typosquatting check), AND signals found ──
        client_domain_set = getattr(investigation, "client_domain", None)
        if client_domain_set and _domain_root(client_domain_set) == client_domain_root:
            report_signals = getattr(report, "findings", []) or []
            typo_signals = [
                f for f in report_signals
                if any(kw in (getattr(f, "title", "") + getattr(f, "description", "")).lower()
                       for kw in ("typosquat", "homoglyph", "visual", "similarity"))
            ]
            if typo_signals or str(classification).lower() in ("suspicious", "malicious"):
                alerts_for_client.append(ClientAlert(
                    client_id=client.id,
                    investigation_id=investigation.id,
                    alert_type="typosquatting",
                    severity=severity,
                    title=f"Potential typosquatting of {client.domain} detected: {investigation.domain}",
                    details_json={
                        "investigated_domain": investigation.domain,
                        "client_domain": client.domain,
                        "classification": str(classification),
                        "signals_found": len(typo_signals),
                    },
                ))

        # ── 3. Brand keyword match ──
        matched_kw = _keyword_in_domain(client.brand_keywords or [], investigation.domain)
        if matched_kw and not any(
            a.alert_type in ("phishing_detected", "typosquatting") for a in alerts_for_client
        ):
            alerts_for_client.append(ClientAlert(
                client_id=client.id,
                investigation_id=investigation.id,
                alert_type="brand_impersonation",
                severity=severity,
                title=f"Brand keyword '{matched_kw}' found in {str(classification).lower()} domain: {investigation.domain}",
                details_json={
                    "investigated_domain": investigation.domain,
                    "classification": str(classification),
                    "matched_keyword": matched_kw,
                    "client_name": client.name,
                },
            ))

        if alerts_for_client:
            alerts_to_add.extend(alerts_for_client)
            client_ids_updated.append(client)

    if not alerts_to_add:
        return

    # Persist alerts
    now = datetime.now(timezone.utc)
    for alert in alerts_to_add:
        db.add(alert)

    # Update client counters
    for client in client_ids_updated:
        client.alert_count = (client.alert_count or 0) + sum(
            1 for a in alerts_to_add if a.client_id == client.id
        )
        client.last_alert_at = now

    await db.commit()

    logger.info(
        "Created %d client alert(s) for investigation %s (%s)",
        len(alerts_to_add),
        investigation.id,
        investigation.domain,
    )
