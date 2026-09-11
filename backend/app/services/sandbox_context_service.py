"""Flatten ANY.RUN's sandbox evidence into something an LLM can actually read.

The case context bounds every branch of the evidence tree to four levels. The
sandbox payload is nested one level deeper than that budget allows —
`evidence → hybrid_analysis → items[] → item{}` spends all four — so every
field of the analysis, the verdict and the process tree included, reached the
model as the literal string "[truncated]". Asked what the sandbox found, the
assistant correctly answered that it had none of it.

Raising the depth limit is the wrong fix. The raw payload for one run carries
183 processes, 88 contacted IPs and 101 extracted indicators, nearly all of it
Windows and Edge telemetry; sending it whole buries the three lines that matter
in several thousand of noise, and costs tokens for the privilege.

So this projects the payload instead: the verdict and what ANY.RUN named, the
shape of the process tree, the processes it scored as high-risk, the commands
it called suspicious, and only those hosts, addresses and indicators that carry
a threat level of their own. Everything discarded is still counted, so the
model can say "88 addresses were contacted, none flagged" rather than implying
nothing was there.
"""

from __future__ import annotations

from typing import Any

# Long enough for the argument that matters, short enough that eight Chromium
# command lines do not become the bulk of the prompt.
COMMAND_LINE_LIMIT = 420

# ANY.RUN scores an indicator's reputation 0-2; 2 is "known bad".
FLAGGED_REPUTATION = 2


def _trim(value: Any, limit: int = COMMAND_LINE_LIMIT) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_threat_bearing(row: dict[str, Any]) -> bool:
    """Kept only if the sandbox attached a verdict to this row itself."""
    try:
        level = int(row.get("threat_level") or 0)
    except (TypeError, ValueError):
        level = 0
    return level > 0 or bool(str(row.get("threat_name") or "").strip())


def summarize_sandbox_evidence(evidence: dict[str, Any]) -> dict[str, Any] | None:
    """The sandbox run, projected for a prompt. None when nothing was detonated."""
    block = evidence.get("hybrid_analysis") or evidence.get("anyrun") or {}
    items = block.get("items") or []
    if not isinstance(items, list) or not items:
        return None

    runs: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        intel = item.get("sandbox_intelligence") or {}
        raw = item.get("raw_summary") or {}
        tree = intel.get("process_tree_summary") or {}

        hosts = [h for h in (intel.get("contacted_hosts") or []) if isinstance(h, dict)]
        ips = [i for i in (intel.get("contacted_ips") or []) if isinstance(i, dict)]
        iocs = [i for i in (raw.get("iocs") or []) if isinstance(i, dict)]

        flagged_iocs = []
        for ioc in iocs:
            try:
                reputation = int(ioc.get("reputation") or 0)
            except (TypeError, ValueError):
                reputation = 0
            if reputation >= FLAGGED_REPUTATION:
                flagged_iocs.append(
                    {
                        "indicator": ioc.get("ioc"),
                        "type": ioc.get("type"),
                        "seen_in": ioc.get("category"),
                        "reputation": reputation,
                    }
                )

        run: dict[str, Any] = {
            "verdict": item.get("verdict"),
            # ANY.RUN's own one-line reading of the run. Usually the most
            # directly quotable answer to "what did the sandbox find".
            "anyrun_summary": _trim(raw.get("anyrun_ai_summary"), 900) or None,
            "verdict_text": raw.get("verdict_text"),
            "threat_names": item.get("threat_names") or raw.get("threatName") or [],
            "tags": item.get("tags") or raw.get("tags") or [],
            "analysis_link": item.get("analysis_link"),
            "analysis_id": item.get("analysis_id"),
            "behaviour_counts": raw.get("behavior_counts") or {},
            "process_tree": {
                "process_count": tree.get("process_count"),
                "edge_count": tree.get("edge_count"),
                "narrative": _trim(tree.get("narrative"), 700) or None,
                "root_processes": [
                    {"pid": p.get("pid"), "name": p.get("name")}
                    for p in (tree.get("root_processes") or [])[:10]
                    if isinstance(p, dict)
                ],
                "high_risk_processes": [
                    {
                        "pid": p.get("pid"),
                        "ppid": p.get("ppid"),
                        "name": p.get("name"),
                        "risk_rank": p.get("risk_rank"),
                        "threat_level": p.get("threat_level"),
                        "threat_score": p.get("threat_score"),
                        "network_events": p.get("network_events"),
                        "file_events": p.get("file_events"),
                        "registry_events": p.get("registry_events"),
                        "command_line": _trim(p.get("command_line")),
                    }
                    for p in (tree.get("high_risk_processes") or [])[:12]
                    if isinstance(p, dict)
                ],
            },
            "suspicious_commands": [
                {
                    "pid": c.get("pid"),
                    "process": c.get("process"),
                    "reason": c.get("reason"),
                    "threat_level": c.get("threat_level"),
                    "command_line": _trim(c.get("command_line")),
                }
                for c in (intel.get("suspicious_commands") or [])[:12]
                if isinstance(c, dict)
            ],
            "flagged_indicators": flagged_iocs[:25],
            "threat_bearing_hosts": [
                {
                    "host": h.get("host"),
                    "threat_name": h.get("threat_name"),
                    "threat_level": h.get("threat_level"),
                    "source": h.get("source"),
                }
                for h in hosts
                if _is_threat_bearing(h)
            ][:25],
            "threat_bearing_ips": [
                {
                    "ip": i.get("ip"),
                    "port": i.get("port"),
                    "threat_name": i.get("threat_name"),
                    "threat_level": i.get("threat_level"),
                    "source": i.get("source"),
                }
                for i in ips
                if _is_threat_bearing(i)
            ][:25],
            "dropped_files": [
                {"name": f.get("name"), "type": f.get("type"), "sha256": f.get("sha256")}
                for f in (intel.get("dropped_files") or [])[:15]
                if isinstance(f, dict)
            ],
            # What was left out, so "none flagged" is distinguishable from
            # "nothing was looked at".
            "omitted": {
                "contacted_hosts_total": len(hosts),
                "contacted_ips_total": len(ips),
                "extracted_iocs_total": len(intel.get("extracted_iocs") or []),
                "note": (
                    "Only hosts, addresses and indicators the sandbox scored as "
                    "threat-bearing are listed; the totals above include benign "
                    "OS and browser telemetry."
                ),
            },
        }
        runs.append(run)

    if not runs:
        return None
    return {"provider": "ANY.RUN", "runs": runs}
