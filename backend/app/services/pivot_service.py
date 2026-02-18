"""
Infrastructure Pivot Service — finds related investigations sharing infrastructure.

Given an investigation, extracts "pivot points" (IPs, cert hashes, ASN, registrar,
name servers) from its evidence, then queries other investigations for matches.

This enables campaign detection: if multiple investigated domains share the same
IP, cert, or registrar, they may be part of the same threat infrastructure.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Evidence, Investigation

logger = logging.getLogger(__name__)


class PivotService:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def find_related(self, investigation_id: str) -> dict:
        """
        Find investigations sharing infrastructure with the given investigation.

        Returns:
            {
                "pivot_points": { "ips": [...], "cert_sha256": "...", ... },
                "related_investigations": [
                    {
                        "id": "...", "domain": "...", "classification": "...",
                        "risk_score": N, "state": "...",
                        "shared_infrastructure": [{"type": "ip", "value": "1.2.3.4"}, ...]
                    }
                ]
            }
        """
        inv_id = uuid.UUID(investigation_id)

        # 1. Load the source investigation's evidence
        result = await self.session.execute(
            select(Evidence).where(Evidence.investigation_id == inv_id)
        )
        source_ev = result.scalar_one_or_none()

        if not source_ev or not source_ev.evidence_json:
            return {"pivot_points": {}, "related_investigations": []}

        ej = source_ev.evidence_json

        # 2. Extract pivot points
        pivot_points = self._extract_pivot_points(ej)

        if not any(pivot_points.values()):
            return {"pivot_points": pivot_points, "related_investigations": []}

        # 3. Find other concluded investigations and check for matches
        related = await self._find_matches(inv_id, pivot_points)

        return {
            "pivot_points": pivot_points,
            "related_investigations": related,
        }

    def _extract_pivot_points(self, evidence_json: dict) -> dict:
        """Extract searchable infrastructure identifiers from evidence."""
        points: dict = {
            "ips": [],
            "cert_sha256": None,
            "asn": None,
            "registrar": None,
            "name_servers": [],
        }

        # IPs from DNS A records
        dns_data = evidence_json.get("dns", {})
        ips = set()
        for ip in (dns_data.get("a") or []):
            if ip and isinstance(ip, str):
                ips.add(ip)

        # IP from hosting/ASN
        hosting = evidence_json.get("hosting", {})
        if hosting.get("ip"):
            ips.add(hosting["ip"])

        points["ips"] = sorted(ips)

        # Certificate SHA256
        tls_data = evidence_json.get("tls", {})
        if tls_data.get("cert_sha256"):
            points["cert_sha256"] = tls_data["cert_sha256"]

        # ASN
        if hosting.get("asn"):
            points["asn"] = hosting["asn"]

        # Registrar
        whois_data = evidence_json.get("whois", {})
        if whois_data.get("registrar"):
            points["registrar"] = whois_data["registrar"]

        # Name servers
        ns_list = whois_data.get("name_servers") or []
        points["name_servers"] = [ns.lower() for ns in ns_list if ns]

        return points

    async def _find_matches(
        self,
        source_id: uuid.UUID,
        pivot_points: dict,
    ) -> list[dict]:
        """
        Find other concluded investigations sharing infrastructure.

        Uses a two-step approach:
        1. Fetch all concluded investigations' evidence (excluding source)
        2. Check each for shared pivot points in Python

        This is simpler and more portable than dynamic JSONB queries,
        and perfectly adequate for the expected scale (hundreds of investigations).
        """
        query = (
            select(
                Investigation.id,
                Investigation.domain,
                Investigation.classification,
                Investigation.risk_score,
                Investigation.state,
                Investigation.created_at,
                Evidence.evidence_json,
            )
            .join(Evidence, Evidence.investigation_id == Investigation.id)
            .where(
                Investigation.id != source_id,
                Investigation.state == "concluded",
            )
            .order_by(Investigation.created_at.desc())
            .limit(200)
        )

        result = await self.session.execute(query)
        rows = result.all()

        related = []
        for inv_id, domain, classification, risk_score, state, created_at, ev_json in rows:
            if not ev_json:
                continue
            shared = self._determine_shared(pivot_points, ev_json)
            if shared:
                related.append({
                    "id": str(inv_id),
                    "domain": domain,
                    "classification": classification,
                    "risk_score": risk_score,
                    "state": state,
                    "created_at": created_at.isoformat() if created_at else None,
                    "shared_infrastructure": shared,
                })

        # Sort by number of shared attributes (most shared first)
        related.sort(key=lambda r: len(r["shared_infrastructure"]), reverse=True)
        return related[:50]

    def _determine_shared(self, pivot_points: dict, other_evidence: dict) -> list[dict]:
        """Determine which infrastructure attributes are shared between two investigations."""
        shared = []

        other_dns = other_evidence.get("dns", {})
        other_hosting = other_evidence.get("hosting", {})
        other_tls = other_evidence.get("tls", {})
        other_whois = other_evidence.get("whois", {})

        # IPs
        other_ips = set(other_dns.get("a") or [])
        if other_hosting.get("ip"):
            other_ips.add(other_hosting["ip"])

        for ip in pivot_points.get("ips", []):
            if ip in other_ips:
                shared.append({"type": "ip", "value": ip})

        # Certificate
        cert = pivot_points.get("cert_sha256")
        if cert and other_tls.get("cert_sha256") == cert:
            shared.append({"type": "certificate", "value": cert[:16] + "..."})

        # ASN (only if same ASN AND it's not a mega-provider like Cloudflare/AWS)
        asn = pivot_points.get("asn")
        if asn and other_hosting.get("asn") == asn:
            org = other_hosting.get("asn_org", f"AS{asn}")
            shared.append({"type": "asn", "value": f"AS{asn} ({org})"})

        # Registrar
        registrar = pivot_points.get("registrar")
        if registrar and other_whois.get("registrar") == registrar:
            shared.append({"type": "registrar", "value": registrar})

        # Name servers
        other_ns = set(
            ns.lower() for ns in (other_whois.get("name_servers") or []) if ns
        )
        for ns in pivot_points.get("name_servers", []):
            if ns in other_ns:
                shared.append({"type": "nameserver", "value": ns})

        return shared
