"""
Evidence bundle -> the agent's virtual filesystem.

The pre-LangGraph build had nowhere to put evidence except the prompt, so it grew ~500
lines of trim tables, depth caps and "prompt is too long" retry tiers. deepagents gives
the model a filesystem instead: write the bundle to `state["files"]`, put only
`digest.md` in the prompt, and let the model `read_file` / `grep` what its reasoning
actually depends on.

Layout:

    /investigations/{id}/
      digest.md            orientation, the only artefact resident in the prompt
      manifest.json        source -> status, derived, duration, error, path, bytes
      signals.json         the full deterministic signal list
      data_gaps.json       what we could not collect, and why it matters
      decision.json        the deterministic verdict
      evidence/*.json      one file per collector / analyzer

Files are only reachable *inside* graph execution (`StateBackend` reads and writes
through the graph's config channels), so anything the caller needs afterwards must be
taken from the returned state, not from the backend.
"""

from __future__ import annotations

import json
from typing import Any

# Scalars describing the investigation, plus the sections that get their own top-level
# file. Without the second group, `signals` and `data_gaps` would be written twice —
# once at the root and again under `evidence/` — which costs context and leaves the
# model guessing which copy is authoritative.
_SKIP_KEYS = {
    "domain",
    "investigation_id",
    "observable_type",
    "signals",
    "data_gaps",
    "analyst_digest",  # rendered as digest.md
    # A {name: sha256} map with no analytic content. The pre-LangGraph prompt builder
    # blocklisted it too (prompt_builder._compact_value).
    "artifact_hashes",
    # Investigation bookkeeping rather than evidence, and already surfaced whole in the
    # manifest. Left in evidence/ it reads as a source the model should consider.
    "timestamps",
}


def investigation_root(investigation_id: str) -> str:
    return f"/investigations/{investigation_id}"


def _dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str, ensure_ascii=False)


def build_manifest(
    evidence: dict[str, Any],
    statuses: dict[str, str],
    *,
    investigation_id: str,
) -> dict[str, Any]:
    """
    Index of what was collected, what failed, and where to read each piece.

    This is the file the model is told to read first: it turns "what is even available?"
    into one small read instead of an `ls` plus guesswork.
    """
    root = investigation_root(investigation_id)
    entries: list[dict[str, Any]] = []
    for name in sorted(k for k in evidence if k not in _SKIP_KEYS):
        section = evidence.get(name)
        if not isinstance(section, dict):
            continue
        meta = section.get("meta") or {}
        # Sections with no collector meta and no recorded status are computed from other
        # evidence (final_risk, cert_timeline, domain_similarity...). Flagging them keeps
        # the model from reading "completed" as "we queried an external source and it
        # agreed".
        derived = not meta and name not in statuses
        body = _dump(section)
        entries.append(
            {
                "source": name,
                "status": meta.get("status") or statuses.get(name) or "derived",
                "derived": derived,
                "duration_ms": meta.get("duration_ms"),
                "error": meta.get("error"),
                "path": f"{root}/evidence/{name}.json",
                "bytes": len(body.encode("utf-8")),
            }
        )
    return {
        "investigation_id": investigation_id,
        "domain": evidence.get("domain"),
        "observable_type": evidence.get("observable_type", "domain"),
        # Scalar context that gets no file of its own, surfaced here so the model does
        # not have to guess whether it exists.
        "target_domain": evidence.get("target_domain"),
        "timestamps": evidence.get("timestamps"),
        "sources": entries,
        "collected_sources": [e["source"] for e in entries if not e["derived"]],
        "failed_sources": [e["source"] for e in entries if e["status"] == "failed"],
    }


def build(
    evidence: dict[str, Any],
    *,
    investigation_id: str,
    statuses: dict[str, str] | None = None,
    digest_markdown: str = "",
    signals: list[dict[str, Any]] | None = None,
    data_gaps: list[dict[str, Any]] | None = None,
    decision: dict[str, Any] | None = None,
) -> dict[str, str]:
    """
    Render the bundle as `{path: contents}` for `agent.ainvoke({"files": ...})`.

    Every value is a string — that is what the filesystem backend stores.

    Only dict sections get a file, matching `build_manifest` exactly. Without the
    isinstance test the scalars on `evidence_data` (`target_domain`, and anything else
    added later) become `evidence/target_domain.json` holding a bare JSON string — files
    the model can `ls` but that the manifest never indexes, which breaks the "read the
    manifest first" contract the whole design rests on.
    """
    root = investigation_root(investigation_id)
    files: dict[str, str] = {}

    for name, section in evidence.items():
        if name in _SKIP_KEYS or not isinstance(section, dict):
            continue
        files[f"{root}/evidence/{name}.json"] = _dump(section)

    files[f"{root}/manifest.json"] = _dump(
        build_manifest(evidence, statuses or {}, investigation_id=investigation_id)
    )
    if digest_markdown:
        files[f"{root}/digest.md"] = digest_markdown
    if signals is not None:
        files[f"{root}/signals.json"] = _dump(signals)
    if data_gaps is not None:
        files[f"{root}/data_gaps.json"] = _dump(data_gaps)
    if decision is not None:
        files[f"{root}/decision.json"] = _dump(decision)

    return files


# ── digest.md ────────────────────────────────────────────────────────────────────
#
# Section order and headings for `collector_summaries`. Reading order for an analyst —
# identity, then reputation, then behaviour, then impersonation — not dict order.
#
# `hybrid_analysis` is renamed. It is the legacy internal storage key for the ANY.RUN
# integration and the analyst must never see "Hybrid Analysis": the system prompt says
# so, `provider_branding.normalize_anyrun_branding` enforces it on the report, and the
# deleted `prompt_builder._build_supporting_evidence` enforced it on the prompt. This
# map is where that guarantee now lives.
_DIGEST_SECTIONS: tuple[tuple[str, str], ...] = (
    ("whois", "WHOIS"),
    ("http", "HTTP / page"),
    ("urlscan", "URLScan"),
    ("vt", "VirusTotal"),
    ("threat_feeds", "Threat feeds"),
    ("brave_osint", "OSINT (Brave search)"),
    ("js_analysis", "JavaScript behaviour"),
    ("hybrid_analysis", "AnyRun sandbox"),
    ("domain_similarity", "Domain similarity"),
    ("visual_comparison", "Visual comparison"),
    ("redirect_destination_intel", "Redirect destination"),
)

# Only where `key.replace("_", " ")` reads badly or loses a proper noun.
_DIGEST_LABELS = {
    "abuse_confidence_score": "abuse confidence",
    "abuseipdb": "AbuseIPDB",
    "analysis_id": "analysis id",
    "contacted_ips": "contacted IPs",
    "credential_post_endpoints": "credential POST endpoints",
    "domain_age_days": "domain age (days)",
    "extracted_iocs": "extracted IOCs",
    "final_status_code": "HTTP status",
    "has_login_form": "login form present",
    "ioc_value": "IOC",
    "is_potential_typosquat": "potential typosquat",
    "is_visual_clone": "visual clone",
    "openphish_listed": "OpenPhish listed",
    "otx": "OTX",
    "phishtank": "PhishTank",
    "process_tree_summary": "process tree",
    "sandbox_intelligence": "sandbox intelligence",
    "threatfox_matches": "ThreatFox matches",
    "whois_registrant_org": "WHOIS registrant org",
}

# Matches the 800-char cap every digest string already passed through on its way into
# the old prompt (prompt_builder._compact_scalar). Not a new truncation — the same one.
_MAX_DIGEST_SCALAR = 800

# Depth guard. The old prompt builder replaced anything at depth >= 4 with "[omitted]";
# this renderer goes deeper (sandbox process trees are high-value and are exactly what a
# small local model wants resident), but not unboundedly.
_MAX_DIGEST_DEPTH = 6


def _is_blank(value: Any) -> bool:
    """
    None / "" / [] / {} are absences. `False` and `0` are kept.

    Every `_digest_*` summarizer in analysis_task.py returns all of its keys even for a
    collector that never ran, so without this the digest is eleven sections of "None".
    But `reachable: no`, `openphish_listed: no` and `malicious_count: 0` are findings,
    and dropping them would make an absent collector indistinguishable from a clean one.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return False


def _label(key: str) -> str:
    return _DIGEST_LABELS.get(key, key.replace("_", " "))


def _render_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = " ".join(str(value).split())
    return text if len(text) <= _MAX_DIGEST_SCALAR else text[:_MAX_DIGEST_SCALAR] + "…"


def _inline(value: Any) -> str | None:
    """One-line form for a scalar or a flat list of scalars; None when it needs a block."""
    if _is_blank(value) or isinstance(value, dict):
        return None
    if isinstance(value, (list, tuple)):
        kept = [item for item in value if not _is_blank(item)]
        if any(isinstance(item, (dict, list, tuple)) for item in kept):
            return None
        return ", ".join(_render_scalar(item) for item in kept) or None
    return _render_scalar(value)


def _render_value(value: Any, *, indent: int = 0) -> list[str]:
    """Bullet lines for one digest node; [] when it prunes away entirely."""
    if _is_blank(value) or indent > _MAX_DIGEST_DEPTH:
        return []
    pad = "  " * indent

    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            label = _label(str(key))
            if (flat := _inline(item)) is not None:
                lines.append(f"{pad}- {label}: {flat}")
            elif nested := _render_value(item, indent=indent + 1):
                lines.append(f"{pad}- {label}:")
                lines.extend(nested)
        return lines

    if isinstance(value, (list, tuple)):
        lines = []
        for item in value:
            if (flat := _inline(item)) is not None:
                lines.append(f"{pad}- {flat}")
                continue
            if not isinstance(item, dict):
                continue
            # Flatten the item's own scalars onto one bullet, indent whatever is left.
            head = "; ".join(
                f"{_label(str(key))}={flat_sub}"
                for key, sub in item.items()
                if (flat_sub := _inline(sub)) is not None
            )
            rest = {
                key: sub
                for key, sub in item.items()
                if _inline(sub) is None and not _is_blank(sub)
            }
            lines.append(f"{pad}- {head}" if head else f"{pad}-")
            lines.extend(_render_value(rest, indent=indent + 1))
        return lines

    return [f"{pad}- {_render_scalar(value)}"]


def render_markdown(digest: dict[str, Any]) -> str:
    """
    Render `_build_analyst_evidence_digest`'s dict (analysis_task.py) as markdown.

    This is the one artefact the model reads without spending a tool call, so it is
    bullets and prose rather than JSON — braces, quotes and repeated key names buy
    nothing here and cost tokens in the resident context on every turn.

    Structure is fixed and pruned: eleven collector sections in reading order, any of
    which disappears when its collector produced nothing, then the deterministic signals
    and the data gaps. The counts in the headings are load-bearing — "Top signals (15)"
    tells the model the list is capped and that signals.json holds the rest.

    `observable_summary.tier` is deliberately not rendered: it is always "standard" now
    and means nothing to the model.
    """
    lines: list[str] = ["# Evidence digest", ""]

    summary = digest.get("observable_summary") or {}
    observable = str(summary.get("observable") or "").strip()
    if observable:
        observable_type = str(summary.get("observable_type") or "domain")
        lines += [f"**Observable:** `{observable}`  **Type:** {observable_type}", ""]

    associated = str(digest.get("associated_with") or "").strip()
    basis = [str(i).strip() for i in (digest.get("association_basis") or []) if str(i).strip()]
    if associated or basis:
        lines += ["## Apparent association", ""]
        lines += [associated or "No brand or organisation could be attributed from the evidence.", ""]
        if basis:
            lines += ["Grounded in:", ""] + [f"- {item}" for item in basis] + [""]

    body: list[str] = []
    summaries = digest.get("collector_summaries") or {}
    for key, heading in _DIGEST_SECTIONS:
        if rendered := _render_value(summaries.get(key)):
            body += [f"### {heading}", ""] + rendered + [""]
    if body:
        lines += ["## Collector summaries", ""] + body

    signals = [item for item in (digest.get("top_signals") or []) if isinstance(item, dict)]
    if signals:
        lines += [
            f"## Top signals ({len(signals)})",
            "",
            "Deterministic investigative clues — clues, not conclusions. "
            "The full list is in `signals.json`.",
            "",
        ]
        for item in signals:
            severity = str(item.get("severity") or "info").upper()
            description = str(item.get("description") or "").strip()
            identifier = str(item.get("id") or "?")
            lines.append(
                f"- **[{severity}]** `{identifier}`" + (f" — {description}" if description else "")
            )
        lines.append("")

    gaps = [item for item in (digest.get("top_data_gaps") or []) if isinstance(item, dict)]
    if gaps:
        lines += [
            f"## Data gaps ({len(gaps)})",
            "",
            "What could not be collected. Missing evidence is not malicious evidence. "
            "The full list is in `data_gaps.json`.",
            "",
        ]
        for item in gaps:
            description = str(item.get("description") or "").strip()
            impact = str(item.get("impact") or "").strip()
            identifier = str(item.get("id") or "?")
            suffix = f" (impact: {impact})" if impact else ""
            lines.append(
                f"- `{identifier}`" + (f" — {description}" if description else "") + suffix
            )
        lines.append("")

    return "\n".join(lines).strip() + "\n"
