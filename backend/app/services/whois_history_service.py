"""
WHOIS History Service — computes diffs between WHOIS snapshots.
"""

from __future__ import annotations


# Fields to skip when computing diffs (volatile or derived)
_SKIP_KEYS = {"meta", "domain_age_days"}


def compute_whois_diff(old: dict, new: dict) -> dict:
    """
    Compare two WHOIS snapshots and return changed fields.

    Returns dict of {field: {"old": old_val, "new": new_val}} for each
    field that changed between snapshots.
    """
    changes = {}
    all_keys = set(list(old.keys()) + list(new.keys()))

    for key in sorted(all_keys):
        if key in _SKIP_KEYS:
            continue
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            changes[key] = {"old": old_val, "new": new_val}

    return changes
