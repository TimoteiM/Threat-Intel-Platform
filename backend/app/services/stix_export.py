"""
STIX 2.1 export — builds a STIX Bundle from IOC records.

No external STIX library needed; generates spec-compliant JSON dicts.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

# IOCType → STIX SCO type mapping
_SCO_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "email": "email-addr",
}


def build_stix_bundle(iocs: list[dict], investigation_detail: dict) -> dict:
    """Build a STIX 2.1 Bundle from a list of IOC dicts."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict] = []

    for ioc in iocs:
        sco = _build_sco(ioc)
        if not sco:
            continue
        objects.append(sco)

        indicator = _build_indicator(ioc, sco["id"], investigation_detail, now)
        objects.append(indicator)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _build_sco(ioc: dict) -> dict | None:
    """Build a STIX Cyber-Observable Object from an IOC."""
    ioc_type = ioc.get("type", "")
    sco_type = _SCO_TYPE_MAP.get(ioc_type)
    if not sco_type:
        return None

    sco_id = f"{sco_type}--{uuid.uuid4()}"
    value = ioc.get("value", "")

    if sco_type == "ipv4-addr":
        return {"type": sco_type, "id": sco_id, "value": value}
    elif sco_type == "domain-name":
        return {"type": sco_type, "id": sco_id, "value": value}
    elif sco_type == "url":
        return {"type": sco_type, "id": sco_id, "value": value}
    elif sco_type == "email-addr":
        return {"type": sco_type, "id": sco_id, "value": value}
    elif sco_type == "file":
        return {"type": sco_type, "id": sco_id, "hashes": {"SHA-256": value}}
    return None


def _build_indicator(
    ioc: dict,
    sco_id: str,
    investigation_detail: dict,
    created: str,
) -> dict:
    """Build a STIX Indicator SDO referencing a SCO."""
    ioc_type = ioc.get("type", "unknown")
    value = ioc.get("value", "")
    context = ioc.get("context", "")
    domain = investigation_detail.get("domain", "unknown")

    pattern_map = {
        "ip": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "hash": f"[file:hashes.'SHA-256' = '{value}']",
        "email": f"[email-addr:value = '{value}']",
    }

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": f"{ioc_type.upper()}: {value}",
        "description": context or f"IOC extracted from investigation of {domain}",
        "pattern": pattern_map.get(ioc_type, f"[domain-name:value = '{value}']"),
        "pattern_type": "stix",
        "valid_from": created,
        "labels": ["malicious-activity"],
    }
