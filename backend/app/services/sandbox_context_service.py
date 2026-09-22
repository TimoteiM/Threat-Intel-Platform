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


def _collapse_network_threats(raw: dict[str, Any]) -> dict[str, Any] | None:
    """The IDS events, grouped by the rule that fired.

    This is what "13 network threats" actually means, and it is the question an
    analyst asks next. Raw, the events repeat: thirteen here are two Suricata
    rules, one seen nine times and one four. Grouping by signature id keeps the
    rule text, the class and the destinations while dropping twelve near
    duplicates that would otherwise crowd the prompt.
    """
    events = ((raw.get("behavior_details") or {}).get("network_threats")) or []
    if not isinstance(events, list) or not events:
        return None

    grouped: dict[Any, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        key = event.get("sid") or event.get("msg")
        entry = grouped.setdefault(
            key,
            {
                "rule": _trim(event.get("msg"), 300),
                "signature_id": event.get("sid"),
                "class": event.get("class"),
                "priority": event.get("priority"),
                "events": 0,
                "_destinations": set(),
                "_processes": set(),
                "_times": [],
            },
        )
        entry["events"] += 1
        dst_ip = str(event.get("dstip") or "").strip()
        if dst_ip:
            port = str(event.get("dstport") or "").strip()
            entry["_destinations"].add(f"{dst_ip}:{port}" if port else dst_ip)
        process = str(event.get("processName") or "").strip()
        if process:
            entry["_processes"].add(f"{process} (pid {event.get('pid')})" if event.get("pid") else process)
        when = str(event.get("time") or "").strip()
        if when:
            entry["_times"].append(when)

    rules = []
    for entry in sorted(grouped.values(), key=lambda e: -e["events"])[:15]:
        times = sorted(entry.pop("_times"))
        entry["destinations"] = sorted(entry.pop("_destinations"))[:10]
        entry["processes"] = sorted(entry.pop("_processes"))[:6]
        entry["first_seen"] = times[0] if times else None
        entry["last_seen"] = times[-1] if times else None
        rules.append(entry)

    return {"event_count": len(events), "distinct_rules": len(grouped), "rules": rules}


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
            # The IDS detections, by rule. Without these the model can say
            # "13 network threats" and nothing about what they were.
            "network_threats": _collapse_network_threats(raw),
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


# ── CAPEv2 ────────────────────────────────────────────────────────────────────
#
# The same problem as ANY.RUN above, for the same reason. A CAPE report is the
# largest single document this platform ingests — 41MB of JSON for one sample,
# measured on the live instance — and its useful findings sit four and five
# levels down (`cape → report → network → domains → []`), which is exactly
# where the generic evidence walk stops and writes "[truncated]".
#
# So it is projected rather than bounded: the verdict, what CAPE named, what it
# did, and where it went. Everything dropped is counted, so the model can say
# "57 files were dropped" instead of implying none were.

# Enough for a person to read in a summary; the full lists stay in the report.
_CAPE_LIST_LIMIT = 15
_CAPE_SIGNATURE_LIMIT = 12


def summarize_cape_evidence(evidence: dict[str, Any]) -> dict[str, Any] | None:
    """Project CAPE evidence into something worth putting in a prompt.

    Returns None when the collector did not run, so the prompt can omit the
    section entirely rather than asserting an empty sandbox result.
    """
    cape = evidence.get("cape") if isinstance(evidence, dict) else None
    if not isinstance(cape, dict):
        return None

    if not cape.get("available"):
        # Said out loud. "CAPE was not consulted" and "CAPE found nothing" are
        # different facts, and a model given silence will assume the second.
        reason = str(cape.get("reason") or "").strip()
        return {
            "analysed": False,
            "why_not": reason or "The CAPE sandbox did not return an analysis for this observable.",
            "caution": "Absence of a sandbox result is not evidence that the sample is safe.",
        }

    report = cape.get("report")
    if not isinstance(report, dict):
        return {"analysed": False, "why_not": "CAPE returned no usable report."}

    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    behaviour = report.get("behaviour") if isinstance(report.get("behaviour"), dict) else {}
    dropped = report.get("dropped_files") if isinstance(report.get("dropped_files"), list) else []
    signatures = report.get("signatures") if isinstance(report.get("signatures"), list) else []

    malscore = report.get("malscore")
    out: dict[str, Any] = {
        "analysed": True,
        "provider": "CAPEv2 (on-premises detonation)",
        "task_id": report.get("task_id"),
        "verdict": report.get("verdict"),
        # Stated as a sentence rather than a bare number, because "0" and "not
        # scored" are wildly different and a bare field invites the second to
        # be read as the first.
        "malware_score": (
            f"{malscore}/10" if malscore is not None
            else "not scored by CAPE — treat as unknown, not as clean"
        ),
        "named_families": report.get("detections") or None,
        "file_type": report.get("file_type"),
        "machine": report.get("machine"),
        "network_route": report.get("route"),
    }

    if signatures:
        out["top_signatures"] = [
            {
                "name": s.get("name"),
                "severity": s.get("severity"),
                "description": _trim(s.get("description"), 200),
                "attack": s.get("ttps") or None,
            }
            for s in signatures[:_CAPE_SIGNATURE_LIMIT]
            if isinstance(s, dict)
        ]
        out["signature_count"] = len(signatures)

    contacted = _cape_list(network.get("domains"))
    destinations = _cape_list(network.get("destinations"))
    if contacted or destinations:
        out["network"] = _cape_counted({
            "contacted_domains": network.get("domains"),
            "destinations": network.get("destinations"),
            "dns_queries": network.get("dns_queries"),
            "tls_sni": network.get("tls_sni"),
        })
    elif str(report.get("route") or "").lower() in ("none", "", "drop"):
        # The commonest way a CAPE report misleads: no network activity because
        # the analysis had no network, not because the sample was quiet.
        out["network"] = {
            "note": "No network activity recorded, and the analysis ran without internet "
                    "access (route=%s). Absence of C2 traffic here means nothing."
                    % (report.get("route") or "none"),
        }
    else:
        out["network"] = {"note": "No network activity recorded, with internet access enabled."}

    if behaviour:
        out["behaviour"] = _cape_counted({
            "commands": behaviour.get("commands"),
            "mutexes": behaviour.get("mutexes"),
            "files_written": behaviour.get("files_written"),
            "registry_keys": behaviour.get("registry_keys"),
        })
        out["behaviour"]["process_count"] = behaviour.get("process_count")

    if dropped:
        payloads = [d for d in dropped if isinstance(d, dict) and d.get("is_cape_payload")]
        out["dropped_files"] = {
            "total": len(dropped),
            "cape_extracted_payloads": len(payloads),
            "payload_types": _cape_list([p.get("cape_type") for p in payloads]) or None,
        }

    if report.get("extracted_configs"):
        out["extracted_config_count"] = len(report["extracted_configs"])

    for key in ("errors", "limitations"):
        values = report.get(key)
        if values:
            out[key] = [_trim(v, 300) for v in values[:5]]

    return out


def _cape_list(values: Any) -> list[str]:
    """Trimmed, deduplicated, capped. Three identical payload family names read
    as three findings when they are one."""
    if not isinstance(values, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
        if len(out) >= _CAPE_LIST_LIMIT:
            break
    return out


def _cape_counted(sections: dict[str, Any]) -> dict[str, Any]:
    """Show a sample of each list and always say how many there really were."""
    out: dict[str, Any] = {}
    for name, values in sections.items():
        if not isinstance(values, list) or not values:
            continue
        shown = _cape_list(values)
        out[name] = shown
        if len(values) > len(shown):
            out[f"{name}_total"] = len(values)
    return out
