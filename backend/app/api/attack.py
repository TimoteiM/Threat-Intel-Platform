"""
MITRE ATT&CK technique reference endpoint.
"""

from fastapi import APIRouter

from app.analyst.attack_mapping import get_all_techniques

router = APIRouter(prefix="/api/attack", tags=["attack"])


@router.get("/techniques")
async def list_techniques():
    """Return all ATT&CK techniques relevant to domain investigations."""
    return get_all_techniques()
