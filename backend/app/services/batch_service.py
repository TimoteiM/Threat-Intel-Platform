"""
Batch Investigation Service — business logic for bulk domain investigations.

Handles CSV/TXT parsing, batch creation, and campaign detection.
"""

from __future__ import annotations

import uuid
from typing import Optional, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repository import BatchRepository, InvestigationRepository
from app.models.database import Batch, Investigation
from app.services.pivot_service import PivotService


class BatchService:

    def __init__(self, session: AsyncSession):
        self.session = session
        self.batch_repo = BatchRepository(session)
        self.inv_repo = InvestigationRepository(session)

    async def create(
        self,
        domains: list[str],
        name: Optional[str] = None,
        context: Optional[str] = None,
        client_domain: Optional[str] = None,
    ) -> dict:
        """
        Create a batch and dispatch investigations for each domain.

        Returns dict with batch_id and domain count.
        """
        from app.utils.domain_utils import normalize_domain, validate_domain

        # Deduplicate and validate
        seen = set()
        valid_domains = []
        for raw in domains:
            d = normalize_domain(raw.strip())
            if d and validate_domain(d) and d not in seen:
                seen.add(d)
                valid_domains.append(d)

        if not valid_domains:
            raise ValueError("No valid domains found in input")

        # Create batch record
        batch = await self.batch_repo.create(
            name=name or f"Batch ({len(valid_domains)} domains)",
            total_domains=len(valid_domains),
        )
        await self.session.flush()

        batch_id = batch.id

        # Dispatch Celery task to process the batch
        from app.tasks.batch_task import process_batch
        process_batch.delay(
            batch_id=str(batch_id),
            domains=valid_domains,
            context=context,
            client_domain=client_domain,
        )

        return {
            "batch_id": str(batch_id),
            "name": batch.name,
            "total_domains": len(valid_domains),
            "domains": valid_domains,
            "status": "created",
        }

    async def get(self, batch_id: str) -> Optional[Batch]:
        return await self.batch_repo.get(uuid.UUID(batch_id))

    async def list_all(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Batch]:
        return await self.batch_repo.list_all(limit=limit, offset=offset)

    async def get_with_investigations(self, batch_id: str) -> Optional[dict]:
        """Get batch detail with all its investigations."""
        bid = uuid.UUID(batch_id)
        batch = await self.batch_repo.get(bid)
        if not batch:
            return None

        investigations = await self.batch_repo.get_investigations(bid)

        return {
            "id": str(batch.id),
            "name": batch.name,
            "total_domains": batch.total_domains,
            "completed_count": batch.completed_count,
            "status": batch.status,
            "created_at": batch.created_at.isoformat() if batch.created_at else None,
            "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
            "investigations": [
                {
                    "id": str(inv.id),
                    "domain": inv.domain,
                    "state": inv.state,
                    "classification": inv.classification,
                    "confidence": inv.confidence,
                    "risk_score": inv.risk_score,
                    "recommended_action": inv.recommended_action,
                    "created_at": inv.created_at.isoformat() if inv.created_at else None,
                    "concluded_at": inv.concluded_at.isoformat() if inv.concluded_at else None,
                }
                for inv in investigations
            ],
        }

    async def detect_campaigns(self, batch_id: str) -> dict:
        """
        Detect campaigns by finding shared infrastructure across batch investigations.

        Uses the PivotService to find overlap between investigations in the batch.
        Groups investigations that share infrastructure into "campaigns".
        """
        bid = uuid.UUID(batch_id)
        investigations = await self.batch_repo.get_investigations(bid)

        concluded = [inv for inv in investigations if inv.state == "concluded"]
        if not concluded:
            return {"campaigns": [], "unclustered": []}

        pivot_svc = PivotService(self.session)

        # Build a map of investigation_id -> shared connections
        # For each investigation, find which others in the batch share infra
        adjacency: dict[str, set[str]] = {str(inv.id): set() for inv in concluded}
        shared_details: dict[tuple[str, str], list[dict]] = {}

        for inv in concluded:
            inv_id_str = str(inv.id)
            result = await pivot_svc.find_related(inv_id_str)
            batch_inv_ids = {str(i.id) for i in concluded}

            for rel in result.get("related_investigations", []):
                rel_id = rel["id"]
                if rel_id in batch_inv_ids and rel_id != inv_id_str:
                    adjacency[inv_id_str].add(rel_id)
                    adjacency.setdefault(rel_id, set()).add(inv_id_str)
                    key = tuple(sorted([inv_id_str, rel_id]))
                    if key not in shared_details:
                        shared_details[key] = rel["shared_infrastructure"]

        # Connected components = campaigns
        visited: set[str] = set()
        campaigns = []

        for inv_id_str in adjacency:
            if inv_id_str in visited:
                continue
            # BFS to find connected component
            component: list[str] = []
            queue = [inv_id_str]
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                component.append(node)
                for neighbor in adjacency.get(node, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(component) > 1:
                # This is a campaign (multiple connected investigations)
                inv_map = {str(inv.id): inv for inv in concluded}
                # Collect all shared infra types across this cluster
                shared_types: dict[str, set[str]] = {}
                for i, a in enumerate(component):
                    for b in component[i + 1:]:
                        key = tuple(sorted([a, b]))
                        for detail in shared_details.get(key, []):
                            t = detail["type"]
                            shared_types.setdefault(t, set()).add(detail["value"])

                campaigns.append({
                    "domains": [
                        {
                            "id": cid,
                            "domain": inv_map[cid].domain,
                            "classification": inv_map[cid].classification,
                            "risk_score": inv_map[cid].risk_score,
                        }
                        for cid in component if cid in inv_map
                    ],
                    "shared_infrastructure": [
                        {"type": t, "values": sorted(vals)}
                        for t, vals in shared_types.items()
                    ],
                    "size": len(component),
                })

        # Sort campaigns by size descending
        campaigns.sort(key=lambda c: c["size"], reverse=True)

        # Unclustered = concluded investigations not in any campaign
        clustered_ids = visited & {str(inv.id) for inv in concluded}
        unclustered_ids = {str(inv.id) for inv in concluded} - clustered_ids
        # Actually: unclustered are those in visited but with component size 1
        # Let me recalculate: the above `visited` includes singletons
        campaign_ids = set()
        for c in campaigns:
            for d in c["domains"]:
                campaign_ids.add(d["id"])

        unclustered = [
            {
                "id": str(inv.id),
                "domain": inv.domain,
                "classification": inv.classification,
                "risk_score": inv.risk_score,
            }
            for inv in concluded
            if str(inv.id) not in campaign_ids
        ]

        return {
            "campaigns": campaigns,
            "unclustered": unclustered,
        }
