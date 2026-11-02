"""
Evidence Diff Service — compares two evidence_json snapshots and returns
a structured dict of what changed between watchlist re-checks.
"""

from __future__ import annotations


def diff_evidence(prev: dict, curr: dict) -> dict:
    """
    Compare two evidence_json dicts and return a dict of detected changes.
    Only keys that actually changed are included.
    Returns an empty dict when nothing meaningful changed.
    """
    changes: dict = {}

    # ── Risk score ────────────────────────────────────────────────────────────
    prev_score = (prev.get("final_risk") or {}).get("risk_score")
    curr_score = (curr.get("final_risk") or {}).get("risk_score")
    if prev_score != curr_score and (prev_score is not None or curr_score is not None):
        changes["risk_score"] = {
            "prev": prev_score,
            "curr": curr_score,
            "delta": (curr_score or 0) - (prev_score or 0),
        }

    # ── DNS A records ─────────────────────────────────────────────────────────
    prev_ips = set((prev.get("dns") or {}).get("a") or [])
    curr_ips = set((curr.get("dns") or {}).get("a") or [])
    if prev_ips != curr_ips:
        changes["dns_ips"] = {
            "added": sorted(curr_ips - prev_ips),
            "removed": sorted(prev_ips - curr_ips),
        }

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    prev_w = prev.get("whois") or {}
    curr_w = curr.get("whois") or {}
    for field, key in (
        ("registrar", "whois_registrar"),
        ("registrant_org", "whois_org"),
        ("registrant_country", "whois_country"),
    ):
        pv, cv = prev_w.get(field), curr_w.get(field)
        if pv != cv:
            changes[key] = {"prev": pv, "curr": cv}

    # ── Hosting IP ────────────────────────────────────────────────────────────
    prev_hip = (prev.get("hosting") or {}).get("ip")
    curr_hip = (curr.get("hosting") or {}).get("ip")
    if prev_hip != curr_hip:
        changes["hosting_ip"] = {"prev": prev_hip, "curr": curr_hip}

    # ── VirusTotal malicious count ────────────────────────────────────────────
    prev_vt = (prev.get("vt") or {}).get("malicious_count", 0) or 0
    curr_vt = (curr.get("vt") or {}).get("malicious_count", 0) or 0
    if prev_vt != curr_vt:
        changes["vt_malicious"] = {
            "prev": prev_vt,
            "curr": curr_vt,
            "delta": curr_vt - prev_vt,
        }

    # ── ThreatFox new matches ─────────────────────────────────────────────────
    prev_tf = {
        m.get("ioc_value", "")
        for m in ((prev.get("threat_feeds") or {}).get("threatfox_matches") or [])
    }
    curr_tf = {
        m.get("ioc_value", "")
        for m in ((curr.get("threat_feeds") or {}).get("threatfox_matches") or [])
    }
    new_tf = sorted(curr_tf - prev_tf - {""})
    if new_tf:
        changes["threatfox_added"] = new_tf

    return changes
