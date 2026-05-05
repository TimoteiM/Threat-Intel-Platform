"""
Derived SOC intelligence for investigation reports.

The functions in this module intentionally work from the existing investigation
detail, evidence JSON, and analyst report JSON. That keeps the feature useful
for old investigations without adding a migration or a new persistence model.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


IOC_TYPE_BASE_SCORE = {
    "hash": 78,
    "url": 68,
    "ip": 62,
    "domain": 58,
    "email": 38,
}

EVIDENCE_MATRIX_FALLBACK_REFS: tuple[tuple[str, str], ...] = (
    ("final_risk.risk_score", "Composite risk score"),
    ("final_risk.risk_level", "Composite risk level"),
    ("vt.malicious_count", "VirusTotal malicious detections"),
    ("vt.suspicious_count", "VirusTotal suspicious detections"),
    ("vt.reputation_score", "VirusTotal reputation"),
    ("threat_feeds.abuseipdb.abuse_confidence_score", "AbuseIPDB confidence"),
    ("threat_feeds.phishtank.in_database", "PhishTank listing"),
    ("threat_feeds.phishtank.verified", "PhishTank verification"),
    ("threat_feeds.threatfox_matches", "ThreatFox matches"),
    ("threat_feeds.openphish_listed", "OpenPhish listing"),
    ("opencti.found", "OpenCTI observable lookup"),
    ("opencti.score", "OpenCTI score"),
    ("opencti.observable_value", "OpenCTI matched observable"),
    ("hybrid_analysis.items", "Sandbox submissions"),
    ("url_lexical_ml.score", "URL lexical ML score"),
    ("ml_url_score.score", "Normalized URL ML score"),
    ("url_behavior.classification", "URL behavior classification"),
    ("http.final_url", "HTTP final URL"),
    ("http.final_status_code", "HTTP final status"),
    ("http.has_login_form", "HTTP login form"),
    ("http.phishing_indicators", "HTTP phishing indicators"),
    ("redirect_analysis.cloaking_detected", "Redirect cloaking"),
    ("domain_similarity.overall_similarity_score", "Domain similarity"),
    ("whois.domain_age_days", "WHOIS domain age"),
    ("dns.a", "DNS A records"),
    ("dns.mx", "DNS MX records"),
    ("tls.issuer_org", "TLS issuer"),
    ("hosting.asn_org", "Hosting ASN organization"),
)


def build_investigation_intelligence(
    evidence: dict[str, Any] | None,
    report: dict[str, Any] | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the unified intelligence payload used by UI and exports."""
    evidence = evidence if isinstance(evidence, dict) else {}
    report = report if isinstance(report, dict) else {}
    detail = detail if isinstance(detail, dict) else {}

    timeline = build_evidence_timeline(evidence=evidence, report=report, detail=detail)
    ioc_quality = build_ioc_quality(evidence=evidence, report=report, detail=detail)
    confidence = build_confidence_engine(
        evidence=evidence,
        report=report,
        detail=detail,
        ioc_quality=ioc_quality,
    )
    graph = build_investigation_graph(
        evidence=evidence,
        report=report,
        detail=detail,
        ioc_quality=ioc_quality,
    )
    opencti = build_opencti_resolver(evidence=evidence, detail=detail)
    soc_report = build_soc_report_outline(
        evidence=evidence,
        report=report,
        detail=detail,
        timeline=timeline,
        confidence=confidence,
        graph=graph,
        ioc_quality=ioc_quality,
        opencti=opencti,
    )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "timeline_events": len(timeline),
            "graph_nodes": len(graph.get("nodes") or []),
            "graph_edges": len(graph.get("edges") or []),
            "iocs": len(ioc_quality.get("items") or []),
            "actionable_iocs": ioc_quality.get("summary", {}).get("actionable_count", 0),
            "opencti_status": opencti.get("status"),
            "confidence_verdict": confidence.get("verdict"),
            "confidence_score": confidence.get("score"),
        },
        "confidence_engine": confidence,
        "evidence_timeline": timeline,
        "investigation_graph": graph,
        "ioc_quality": ioc_quality,
        "opencti_resolver": opencti,
        "soc_report_builder": soc_report,
    }


def build_evidence_matrix_rows(
    *,
    evidence: dict[str, Any] | None,
    report: dict[str, Any] | None = None,
    max_rows: int = 28,
) -> list[dict[str, str]]:
    """Build SOC report evidence rows from analyst refs, findings, signals, and collector facts."""
    evidence = evidence if isinstance(evidence, dict) else {}
    report = report if isinstance(report, dict) else {}
    rows: list[dict[str, str]] = []
    seen: set[str] = set()

    def add_ref(ref: Any, source: str, relevance: Any = "") -> None:
        ref_text = _clean(ref)
        if not ref_text or len(rows) >= max_rows:
            return
        if ref_text.startswith("evidence."):
            ref_text = ref_text[len("evidence.") :]
        key = ref_text.casefold()
        if key in seen:
            return
        value = _resolve_evidence_path(evidence, ref_text)
        if not _has_matrix_value(value):
            return
        compact_value = _compact_matrix_value(value)
        if not compact_value:
            return
        seen.add(key)
        rows.append(
            {
                "source": source,
                "ref": ref_text,
                "value": compact_value,
                "relevance": _clean(relevance),
            }
        )

    for ref in _as_list(report.get("key_evidence")):
        add_ref(ref, "Analyst key evidence", "Listed by the analyst report as evidence supporting the verdict.")

    for finding in _as_list(report.get("findings"))[:12]:
        if not isinstance(finding, dict):
            continue
        title = _clean(finding.get("title")) or "Finding"
        for ref in _as_list(finding.get("evidence_refs"))[:4]:
            add_ref(ref, f"Finding: {title}", finding.get("description"))

    signals = [
        signal for signal in _as_list(evidence.get("signals"))
        if isinstance(signal, dict)
    ]
    severity_rank = {"critical": 0, "danger": 0, "high": 0, "warning": 1, "medium": 1, "info": 2, "low": 3}
    signals.sort(key=lambda signal: severity_rank.get(str(signal.get("severity") or "").lower(), 2))
    for signal in signals[:18]:
        label = _clean(signal.get("category")) or "Signal"
        severity = _clean(signal.get("severity")).upper()
        source = f"{severity} signal: {label}" if severity else f"Signal: {label}"
        for ref in _as_list(signal.get("evidence_refs"))[:3]:
            add_ref(ref, source, signal.get("description"))

    for ref, source in EVIDENCE_MATRIX_FALLBACK_REFS:
        add_ref(ref, source)

    return rows[:max_rows]


def build_evidence_timeline(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    detail: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create one analyst-facing timeline across collectors and intelligence."""
    events: list[dict[str, Any]] = []
    seq = 0

    def add(
        *,
        timestamp: Any = None,
        source: str,
        title: str,
        description: Any = "",
        severity: str = "info",
        entity_type: str = "",
        value: Any = "",
    ) -> None:
        nonlocal seq
        title_text = _clean(title)
        if not title_text:
            return
        events.append(
            {
                "id": f"evt-{seq + 1}",
                "timestamp": _iso_or_none(timestamp),
                "source": source,
                "title": title_text,
                "description": _clean(description),
                "severity": severity,
                "entity_type": entity_type,
                "value": _clean(value),
                "_seq": seq,
            }
        )
        seq += 1

    observable = _primary_observable(evidence, detail)
    add(
        timestamp=detail.get("created_at") or (evidence.get("timestamps") or {}).get("created_at"),
        source="platform",
        title="Investigation created",
        description=f"Primary observable submitted as {detail.get('observable_type') or evidence.get('observable_type') or 'domain'}.",
        severity="info",
        entity_type=str(detail.get("observable_type") or evidence.get("observable_type") or ""),
        value=observable,
    )
    add(
        timestamp=detail.get("concluded_at"),
        source="platform",
        title="Investigation concluded",
        description=detail.get("classification") or report.get("classification") or detail.get("state"),
        severity=_severity_from_verdict(detail.get("classification") or report.get("classification")),
        entity_type="verdict",
        value=detail.get("risk_score") or report.get("risk_score"),
    )

    for key, value in evidence.items():
        if not isinstance(value, dict):
            continue
        meta = value.get("meta")
        if not isinstance(meta, dict):
            continue
        label = _titleize(str(meta.get("collector") or key))
        status = str(meta.get("status") or "completed")
        add(
            timestamp=meta.get("started_at"),
            source=key,
            title=f"{label} collection started",
            description=status,
            severity="info",
        )
        add(
            timestamp=meta.get("completed_at"),
            source=key,
            title=f"{label} collection completed",
            description=meta.get("error") or status,
            severity="danger" if status == "failed" else "success",
        )

    whois = _as_dict(evidence.get("whois"))
    add(timestamp=whois.get("created_date"), source="whois", title="Domain registered", description=whois.get("registrar"), entity_type="domain", value=observable)
    add(timestamp=whois.get("expiry_date"), source="whois", title="Domain expiry observed", description=whois.get("registrar"), entity_type="domain", value=observable)

    tls = _as_dict(evidence.get("tls"))
    add(timestamp=tls.get("valid_from"), source="tls", title="TLS certificate became valid", description=tls.get("issuer") or tls.get("issuer_org"), entity_type="certificate", value=tls.get("cert_sha256"))
    add(timestamp=tls.get("valid_to"), source="tls", title="TLS certificate expiry", description=tls.get("subject"), severity="warning", entity_type="certificate", value=tls.get("cert_sha256"))

    vt = _as_dict(evidence.get("vt"))
    add(timestamp=vt.get("vt_creation_date"), source="virustotal", title="VirusTotal object creation date", description=vt.get("file_name") or observable, entity_type="observable", value=observable)
    add(
        timestamp=vt.get("last_analysis_date") or vt.get("vt_last_modified"),
        source="virustotal",
        title="VirusTotal reputation observed",
        description=f"{vt.get('malicious_count', 0)} malicious / {vt.get('suspicious_count', 0)} suspicious vendors",
        severity="danger" if _num(vt.get("malicious_count")) else "warning" if _num(vt.get("suspicious_count")) else "info",
        entity_type="reputation",
        value=observable,
    )

    urlscan = _as_dict(evidence.get("urlscan"))
    if urlscan:
        add(
            timestamp=urlscan.get("task_time") or urlscan.get("scan_time") or urlscan.get("created_at"),
            source="urlscan",
            title="URLScan verdict observed",
            description=urlscan.get("verdict") or _compact(urlscan.get("verdicts")),
            severity=_severity_from_verdict(urlscan.get("verdict")),
            entity_type="url",
            value=urlscan.get("page_url") or urlscan.get("scan_id"),
        )

    for item in _anyrun_items(evidence):
        summary = _as_dict(item.get("sandbox_intelligence")).get("summary") or {}
        add(
            timestamp=item.get("completed_at") or item.get("created_at") or (_as_dict(item.get("raw_summary")).get("created_at")),
            source="anyrun",
            title="AnyRun sandbox/intelligence verdict",
            description=f"{item.get('verdict') or summary.get('verdict') or 'unknown'} score {item.get('threat_score') or summary.get('threat_score') or '-'}",
            severity=_severity_from_verdict(item.get("verdict") or summary.get("verdict")),
            entity_type="sandbox",
            value=item.get("analysis_id") or summary.get("analysis_id"),
        )
        intel = _as_dict(item.get("sandbox_intelligence"))
        for cmd in _as_list(intel.get("suspicious_commands"))[:8]:
            add(
                source="anyrun",
                title="Suspicious sandbox command",
                description=cmd.get("reason"),
                severity="danger" if _num(cmd.get("threat_level")) >= 2 else "warning",
                entity_type="process",
                value=cmd.get("process") or cmd.get("command_line"),
            )
        for dropped in _as_list(intel.get("dropped_files"))[:8]:
            add(
                source="anyrun",
                title="Dropped or created file observed",
                description=dropped.get("process"),
                severity="warning",
                entity_type="file",
                value=dropped.get("path") or dropped.get("name"),
            )

    opencti = _as_dict(evidence.get("opencti"))
    if opencti.get("found"):
        add(
            timestamp=opencti.get("created_at"),
            source="opencti",
            title="OpenCTI observable created",
            description=opencti.get("author"),
            severity=_severity_from_score(opencti.get("score")),
            entity_type=opencti.get("observable_entity_type") or "observable",
            value=opencti.get("observable_value") or observable,
        )
        add(
            timestamp=opencti.get("updated_at"),
            source="opencti",
            title="OpenCTI observable modified",
            description=_join(opencti.get("labels")),
            severity=_severity_from_score(opencti.get("score")),
            entity_type=opencti.get("observable_entity_type") or "observable",
            value=opencti.get("standard_id"),
        )
        for row in _as_list(opencti.get("reports"))[:8]:
            add(
                timestamp=row.get("published") or row.get("created"),
                source="opencti",
                title="OpenCTI report linked",
                description=row.get("name"),
                severity=_severity_from_score(opencti.get("score")),
                entity_type="report",
                value=row.get("id"),
            )
        for row in _as_list(opencti.get("indicators"))[:8]:
            add(
                timestamp=row.get("valid_from"),
                source="opencti",
                title="OpenCTI indicator validity started",
                description=row.get("pattern") or row.get("name"),
                severity=_severity_from_score(row.get("confidence") or opencti.get("score")),
                entity_type="indicator",
                value=row.get("id"),
            )

    threat_feeds = _as_dict(evidence.get("threat_feeds"))
    for row in _as_list(threat_feeds.get("threatfox_matches"))[:8]:
        add(
            timestamp=row.get("first_seen") or row.get("last_seen"),
            source="threatfox",
            title="ThreatFox IOC match",
            description=row.get("malware") or row.get("threat_type"),
            severity="danger",
            entity_type=row.get("ioc_type") or "ioc",
            value=row.get("ioc_value"),
        )
    phishtank = _as_dict(threat_feeds.get("phishtank"))
    if phishtank.get("in_database"):
        add(timestamp=phishtank.get("verified_at"), source="phishtank", title="PhishTank listing observed", description=phishtank.get("target_brand"), severity="danger", entity_type="url", value=observable)

    cert_timeline = _as_dict(evidence.get("cert_timeline"))
    for row in _as_list(cert_timeline.get("entries"))[:12]:
        add(
            timestamp=row.get("entry_timestamp") or row.get("not_before"),
            source="certificate_transparency",
            title="Certificate Transparency entry",
            description=row.get("issuer_name"),
            severity="warning" if row.get("is_short_lived") else "info",
            entity_type="certificate",
            value=row.get("common_name"),
        )

    events.sort(key=lambda row: (_parse_dt(row.get("timestamp")) is None, _parse_dt(row.get("timestamp")) or datetime.max.replace(tzinfo=timezone.utc), row.get("_seq", 0)))
    for row in events:
        row.pop("_seq", None)
    return events[:160]


def build_confidence_engine(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    detail: dict[str, Any],
    ioc_quality: dict[str, Any],
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []

    def add_component(source: str, score: Any, verdict: str, reasons: list[str], weight: float) -> None:
        numeric = max(0.0, min(100.0, _num(score)))
        if numeric <= 0 and not reasons:
            return
        components.append(
            {
                "source": source,
                "score": round(numeric, 1),
                "verdict": verdict or _verdict_from_score(numeric),
                "weight": weight,
                "reasons": [r for r in reasons if r][:6],
            }
        )

    report_score = report.get("risk_score") or detail.get("risk_score")
    report_verdict = str(report.get("classification") or detail.get("classification") or "")
    add_component(
        "analyst_report",
        report_score or _score_from_verdict(report_verdict),
        report_verdict,
        [_clean(report.get("primary_reasoning"))[:220] if report.get("primary_reasoning") else ""],
        1.25,
    )

    final_risk = _as_dict(evidence.get("final_risk"))
    add_component(
        "final_risk",
        final_risk.get("risk_score"),
        final_risk.get("risk_level") or final_risk.get("verdict") or "",
        _as_list(final_risk.get("rationale")),
        1.05,
    )

    vt = _as_dict(evidence.get("vt"))
    if vt:
        mal = _num(vt.get("malicious_count"))
        susp = _num(vt.get("suspicious_count"))
        total = max(1.0, _num(vt.get("total_vendors")))
        score = min(100.0, (mal / total) * 120 + (susp / total) * 55 + max(0.0, -_num(vt.get("reputation_score"))) * 0.35)
        add_component(
            "virustotal",
            score,
            "malicious" if mal else "suspicious" if susp else "benign",
            [f"{int(mal)} malicious and {int(susp)} suspicious vendors out of {int(total)}."],
            1.0,
        )

    urlscan = _as_dict(evidence.get("urlscan"))
    if urlscan:
        verdict = str(urlscan.get("verdict") or "")
        add_component(
            "urlscan",
            urlscan.get("score") or _score_from_verdict(verdict),
            verdict,
            [f"URLScan verdict: {verdict or 'unknown'}", _compact(urlscan.get("verdicts"))],
            0.75,
        )

    anyrun_scores: list[float] = []
    anyrun_reasons: list[str] = []
    anyrun_verdict = ""
    for item in _anyrun_items(evidence):
        summary = _as_dict(item.get("sandbox_intelligence")).get("summary") or {}
        score = _num(item.get("threat_score") or summary.get("threat_score"))
        if score:
            anyrun_scores.append(score)
        verdict = str(item.get("verdict") or summary.get("verdict") or "")
        if verdict and not anyrun_verdict:
            anyrun_verdict = verdict
        if summary:
            anyrun_reasons.append(
                f"AnyRun observed {summary.get('process_count', 0)} process(es), "
                f"{summary.get('contacted_host_count', 0)} host(s), "
                f"{summary.get('suspicious_command_count', 0)} suspicious command(s)."
            )
    if anyrun_scores or anyrun_reasons:
        anyrun_score_value = max(anyrun_scores) if anyrun_scores else _score_from_verdict(anyrun_verdict)
        add_component(
            "anyrun",
            anyrun_score_value,
            anyrun_verdict,
            anyrun_reasons,
            1.2 if anyrun_score_value >= 35 else 0.35,
        )

    opencti = _as_dict(evidence.get("opencti"))
    if opencti.get("found"):
        linked_count = sum(
            len(_as_list(opencti.get(key)))
            for key in ("indicators", "reports", "threat_actors", "malware_families", "attack_patterns", "campaigns", "intrusion_sets")
        )
        score = _num(opencti.get("score")) + min(20.0, linked_count * 3.0)
        add_component(
            "opencti",
            score if opencti.get("found") else 0,
            "malicious" if _num(opencti.get("score")) >= 70 else "suspicious" if opencti.get("found") else "unknown",
            [f"OpenCTI score {opencti.get('score', 0)} with {linked_count} linked object(s)." if opencti.get("found") else _join(opencti.get("notes"))],
            1.1,
        )

    threat_feeds = _as_dict(evidence.get("threat_feeds"))
    if threat_feeds:
        score = 0.0
        reasons: list[str] = []
        if threat_feeds.get("openphish_listed"):
            score += 70
            reasons.append("Listed by OpenPhish.")
        if _as_dict(threat_feeds.get("phishtank")).get("in_database"):
            score += 70
            reasons.append("Present in PhishTank.")
        tf_count = len(_as_list(threat_feeds.get("threatfox_matches")))
        if tf_count:
            score += min(85, 35 + tf_count * 10)
            reasons.append(f"{tf_count} ThreatFox match(es).")
        abuse = _as_dict(threat_feeds.get("abuseipdb"))
        if _num(abuse.get("abuse_confidence_score")) > 0:
            score += min(85, _num(abuse.get("abuse_confidence_score")))
            reasons.append(f"AbuseIPDB confidence {abuse.get('abuse_confidence_score')}.")
        if reasons:
            add_component("threat_feeds", min(100, score / max(1, len(reasons))), "malicious", reasons, 0.95)

    quality_summary = ioc_quality.get("summary") or {}
    if quality_summary.get("actionable_count"):
        add_component(
            "ioc_quality",
            min(100, 35 + quality_summary.get("actionable_count", 0) * 8 + quality_summary.get("high_value_count", 0) * 10),
            "suspicious",
            [f"{quality_summary.get('actionable_count', 0)} actionable IOC(s), {quality_summary.get('high_value_count', 0)} high-value IOC(s)."],
            0.65,
        )

    weighted_total = sum(row["score"] * row["weight"] for row in components)
    total_weight = sum(row["weight"] for row in components) or 1.0
    score = round(weighted_total / total_weight)
    high_scores = [row["score"] for row in components if row["score"] >= 70]
    malicious_votes = sum(
        1
        for row in components
        if str(row.get("verdict") or "").lower() in {"malicious", "critical", "high"}
        or row.get("score", 0) >= 80
    )
    if high_scores and malicious_votes >= 2:
        score = max(score, round(max(high_scores) * 0.82))
    if report_verdict.lower() == "malicious" and _num(report_score) >= 80 and malicious_votes >= 2:
        score = max(score, 80)
    verdict = _verdict_from_score(score)

    votes = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}
    for row in components:
        v = str(row.get("verdict") or _verdict_from_score(row.get("score"))).lower()
        if v in {"high", "critical"}:
            v = "malicious"
        elif v in {"medium"}:
            v = "suspicious"
        elif v in {"low"}:
            v = "benign"
        elif v not in votes:
            v = "unknown"
        votes[v] += 1
    agreement = max(votes.values()) / max(1, sum(votes.values()))
    coverage = min(1.0, len(components) / 5.0)
    confidence_pct = round((agreement * 0.55 + coverage * 0.45) * 100)
    confidence_level = "high" if confidence_pct >= 75 else "medium" if confidence_pct >= 45 else "low"

    reasons = []
    mitigating = []
    for row in sorted(components, key=lambda r: (-r["weight"], -r["score"])):
        if row["score"] >= 35:
            reasons.extend(row.get("reasons") or [])
        elif row["score"] <= 15:
            mitigating.extend(row.get("reasons") or [])

    return {
        "verdict": verdict,
        "score": score,
        "confidence": confidence_level,
        "confidence_percent": confidence_pct,
        "source_agreement": votes,
        "components": components,
        "reasons": _dedupe(reasons)[:8],
        "mitigating_factors": _dedupe(mitigating)[:6],
        "explanation": _confidence_explanation(verdict, confidence_level, components),
    }


def build_ioc_quality(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    detail: dict[str, Any],
) -> dict[str, Any]:
    raw_iocs: list[dict[str, Any]] = []

    def add(ioc_type: Any, value: Any, source: str, context: Any = "", confidence: Any = "medium") -> None:
        value_text = _clean(value)
        ioc_type_text = _normalize_ioc_type(ioc_type, value_text)
        if not value_text or not ioc_type_text:
            return
        raw_iocs.append(
            {
                "type": ioc_type_text,
                "value": value_text,
                "source": source,
                "context": _clean(context),
                "confidence": str(confidence or "medium").lower(),
            }
        )

    observable = _primary_observable(evidence, detail)
    add(detail.get("observable_type") or evidence.get("observable_type") or "domain", observable, "platform", "Primary investigated observable", report.get("confidence") or detail.get("confidence") or "medium")

    for row in _as_list(report.get("iocs")):
        if isinstance(row, dict):
            add(row.get("type"), row.get("value"), "analyst_report", row.get("context"), row.get("confidence"))

    for ip in _as_list(_as_dict(evidence.get("dns")).get("a")) + _as_list(_as_dict(evidence.get("dns")).get("aaaa")):
        add("ip", ip, "dns", "Resolved DNS address", "medium")

    http = _as_dict(evidence.get("http"))
    add("url", http.get("final_url"), "http", "Final observed URL", "medium")
    for row in _as_list(http.get("redirect_chain")) + _as_list(http.get("redirects")):
        if isinstance(row, dict):
            add("url", row.get("url") or row.get("location"), "http", "Redirect chain hop", "medium")
    for url in _as_list(http.get("external_resources"))[:40]:
        add("url", url, "http", "External web resource", "low")

    urlscan = _as_dict(evidence.get("urlscan"))
    add("url", urlscan.get("page_url"), "urlscan", "URLScan page URL", "medium")
    add("ip", urlscan.get("page_ip") or urlscan.get("ip"), "urlscan", "URLScan page IP", "medium")

    vt = _as_dict(evidence.get("vt"))
    if vt.get("found"):
        for name in _as_list(vt.get("file_names"))[:10]:
            add("hash", observable if _normalize_ioc_type("hash", observable) == "hash" else "", "virustotal", f"VT file name: {name}", "medium")

    for item in _anyrun_items(evidence):
        intel = _as_dict(item.get("sandbox_intelligence"))
        for row in _as_list(intel.get("extracted_iocs")):
            if isinstance(row, dict):
                add(row.get("type"), row.get("value"), row.get("source") or "anyrun", row.get("context"), row.get("confidence"))
        for row in _as_list(intel.get("contacted_hosts")):
            if isinstance(row, dict):
                add("domain", row.get("host"), "anyrun", row.get("source") or "Contacted host", "high" if _num(row.get("threat_level")) >= 2 else "medium")
        for row in _as_list(intel.get("contacted_ips")):
            if isinstance(row, dict):
                add("ip", row.get("ip"), "anyrun", row.get("source") or "Contacted IP", "high" if _num(row.get("threat_level")) >= 2 else "medium")
        for row in _as_list(intel.get("dropped_files")):
            if isinstance(row, dict):
                for hash_key in ("sha256", "sha1", "md5"):
                    add("hash", row.get(hash_key), "anyrun", row.get("path") or row.get("name") or "Dropped file", "high")

    opencti = _as_dict(evidence.get("opencti"))
    if opencti.get("found"):
        add(opencti.get("observable_entity_type"), opencti.get("observable_value"), "opencti", "Matched OpenCTI observable", "high")
        for indicator in _as_list(opencti.get("indicators")):
            for ioc_type, value in _extract_iocs_from_pattern(indicator.get("pattern")):
                add(ioc_type, value, "opencti", indicator.get("name") or "OpenCTI indicator pattern", "high" if _num(indicator.get("confidence")) >= 70 else "medium")

    threat_feeds = _as_dict(evidence.get("threat_feeds"))
    for row in _as_list(threat_feeds.get("threatfox_matches")):
        if isinstance(row, dict):
            add(row.get("ioc_type"), row.get("ioc_value"), "threatfox", row.get("threat_type") or row.get("malware"), "high")

    hosting = _as_dict(evidence.get("hosting"))
    final: dict[tuple[str, str], dict[str, Any]] = {}
    for row in raw_iocs:
        key = (row["type"], row["value"].lower())
        if key not in final:
            final[key] = row.copy()
            final[key]["sources"] = [row["source"]]
            final[key]["contexts"] = [row["context"]] if row["context"] else []
            continue
        merged = final[key]
        if row["source"] not in merged["sources"]:
            merged["sources"].append(row["source"])
        if row["context"] and row["context"] not in merged["contexts"]:
            merged["contexts"].append(row["context"])
        merged["confidence"] = _stronger_confidence(merged.get("confidence"), row.get("confidence"))

    quality_items: list[dict[str, Any]] = []
    for row in final.values():
        quality = _score_ioc(row, hosting=hosting, opencti=opencti)
        quality_items.append({**row, **quality})

    quality_items.sort(key=lambda row: (-_num(row.get("quality_score")), row.get("type", ""), row.get("value", "")))
    summary = {
        "total_count": len(quality_items),
        "actionable_count": sum(1 for row in quality_items if "actionable" in row.get("labels", [])),
        "high_value_count": sum(1 for row in quality_items if "high-value" in row.get("labels", [])),
        "low_value_count": sum(1 for row in quality_items if "low-value" in row.get("labels", [])),
        "volatile_count": sum(1 for row in quality_items if "volatile" in row.get("labels", [])),
    }
    return {"summary": summary, "items": quality_items[:300]}


def build_investigation_graph(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    detail: dict[str, Any],
    ioc_quality: dict[str, Any],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def node(node_type: str, value: Any, label: Any = "", **extra: Any) -> str:
        value_text = _clean(value)
        if not value_text:
            return ""
        node_id = _node_id(node_type, value_text)
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": _clean(label) or value_text,
                "value": value_text,
                **extra,
            }
        else:
            for key, value in extra.items():
                if value in (None, "", [], {}):
                    continue
                if key not in nodes[node_id] or nodes[node_id].get(key) in (None, "", [], {}):
                    nodes[node_id][key] = value
        return node_id

    def edge(source: str, target: str, label: str, edge_type: str = "", severity: str = "info") -> None:
        if not source or not target or source == target:
            return
        edge_id = hashlib.sha1(f"{source}|{target}|{label}|{edge_type}".encode("utf-8")).hexdigest()[:16]
        edges.setdefault(
            edge_id,
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "label": label,
                "type": edge_type or label,
                "severity": severity,
            },
        )

    observable = _primary_observable(evidence, detail)
    root = node(
        str(detail.get("observable_type") or evidence.get("observable_type") or "observable"),
        observable,
        "Investigated observable",
        group="observable",
        score=report.get("risk_score") or detail.get("risk_score"),
    )

    for row in (ioc_quality.get("items") or [])[:80]:
        ioc_node = node(row.get("type") or "ioc", row.get("value"), row.get("value"), group="ioc", score=row.get("quality_score"), labels=row.get("labels"))
        edge(root, ioc_node, "derived IOC", "ioc", "warning" if row.get("quality_score", 0) >= 60 else "info")

    dns = _as_dict(evidence.get("dns"))
    for ip in _as_list(dns.get("a")) + _as_list(dns.get("aaaa")):
        ip_node = node("ip", ip, group="infrastructure")
        edge(root, ip_node, "resolves to", "dns", "info")
    for ns in _as_list(dns.get("ns")):
        ns_node = node("nameserver", ns, group="infrastructure")
        edge(root, ns_node, "uses nameserver", "dns", "info")

    hosting = _as_dict(evidence.get("hosting"))
    ip_node = node("ip", hosting.get("ip"), group="infrastructure")
    edge(root, ip_node, "hosted on", "hosting", "info")
    asn_node = node("asn", f"AS{hosting.get('asn')}" if hosting.get("asn") else "", hosting.get("asn_org"), group="infrastructure")
    edge(ip_node, asn_node, "announced by", "asn", "info")

    http = _as_dict(evidence.get("http"))
    final_url_node = node("url", http.get("final_url"), "Final URL", group="web")
    edge(root, final_url_node, "loads as", "http", "info")
    previous = root
    for row in _as_list(http.get("redirect_chain")) + _as_list(http.get("redirects")):
        if not isinstance(row, dict):
            continue
        url_node = node("url", row.get("url") or row.get("location"), group="web")
        edge(previous, url_node, "redirects to", "redirect", "warning")
        previous = url_node or previous

    for item in _anyrun_items(evidence):
        intel = _as_dict(item.get("sandbox_intelligence"))
        analysis_node = node("sandbox", item.get("analysis_id") or _as_dict(intel.get("summary")).get("analysis_id"), "AnyRun analysis", group="sandbox", score=item.get("threat_score"))
        edge(root, analysis_node, "sandboxed in", "sandbox", _severity_from_verdict(item.get("verdict")))
        for proc in _as_list(_as_dict(intel.get("process_tree_summary")).get("root_processes")) + _as_list(_as_dict(intel.get("process_tree_summary")).get("high_risk_processes")):
            if not isinstance(proc, dict):
                continue
            proc_node = node("process", f"{proc.get('name')}:{proc.get('pid')}", proc.get("name"), group="process", score=proc.get("risk_rank") or proc.get("threat_score"))
            edge(analysis_node, proc_node, "executed", "process", "warning" if _num(proc.get("risk_rank") or proc.get("threat_level")) else "info")
        for row in _as_list(intel.get("contacted_hosts"))[:40]:
            if isinstance(row, dict):
                host_node = node("domain", row.get("host"), group="network", score=row.get("threat_level"))
                edge(analysis_node, host_node, "contacted host", "network", "danger" if _num(row.get("threat_level")) >= 2 else "warning")
        for row in _as_list(intel.get("contacted_ips"))[:40]:
            if isinstance(row, dict):
                contact_node = node("ip", row.get("ip"), group="network", score=row.get("threat_level"))
                edge(analysis_node, contact_node, "contacted IP", "network", "danger" if _num(row.get("threat_level")) >= 2 else "warning")
        for row in _as_list(intel.get("dropped_files"))[:40]:
            if isinstance(row, dict):
                file_value = row.get("sha256") or row.get("path") or row.get("name")
                file_node = node("file", file_value, row.get("name") or row.get("path"), group="file")
                edge(analysis_node, file_node, "dropped file", "file", "warning")

    opencti = _as_dict(evidence.get("opencti"))
    if opencti.get("found"):
        cti_node = node("opencti_observable", opencti.get("observable_value") or observable, "OpenCTI match", group="opencti", score=opencti.get("score"))
        edge(root, cti_node, "matched in OpenCTI", "opencti", _severity_from_score(opencti.get("score")))
        for key, node_type, label in (
            ("indicators", "indicator", "has indicator"),
            ("reports", "report", "reported in"),
            ("threat_actors", "threat_actor", "linked actor"),
            ("malware_families", "malware", "associated malware"),
            ("attack_patterns", "attack_pattern", "maps to ATT&CK"),
        ):
            for row in _as_list(opencti.get(key))[:25]:
                if isinstance(row, dict):
                    value = row.get("id") or row.get("name") or row.get("pattern")
                    label_text = row.get("name") or row.get("pattern") or row.get("id")
                    child = node(node_type, value, label_text, group="opencti")
                    edge(cti_node, child, label, "opencti", _severity_from_score(opencti.get("score")))
        for key, node_type, label in (("campaigns", "campaign", "campaign"), ("intrusion_sets", "intrusion_set", "intrusion set")):
            for value in _as_list(opencti.get(key))[:25]:
                child = node(node_type, value, group="opencti")
                edge(cti_node, child, label, "opencti", _severity_from_score(opencti.get("score")))

    return {
        "nodes": list(nodes.values())[:180],
        "edges": [edge for edge in edges.values() if edge["source"] in nodes and edge["target"] in nodes][:260],
    }


def build_opencti_resolver(
    *,
    evidence: dict[str, Any],
    detail: dict[str, Any],
) -> dict[str, Any]:
    opencti = _as_dict(evidence.get("opencti"))
    observable = _primary_observable(evidence, detail)
    observable_type = str(detail.get("observable_type") or evidence.get("observable_type") or "domain")
    notes = _as_list(opencti.get("notes"))
    searched_terms = _extract_opencti_search_terms(notes) or _build_search_variants(observable, observable_type)
    matched_term = _extract_opencti_matched_term(notes)
    found = bool(opencti.get("found"))

    relationship_counts = {
        "indicators": len(_as_list(opencti.get("indicators"))),
        "reports": len(_as_list(opencti.get("reports"))),
        "threat_actors": len(_as_list(opencti.get("threat_actors"))),
        "malware": len(_as_list(opencti.get("malware_families"))),
        "attack_patterns": len(_as_list(opencti.get("attack_patterns"))),
        "campaigns": len(_as_list(opencti.get("campaigns"))),
        "intrusion_sets": len(_as_list(opencti.get("intrusion_sets"))),
    }

    related_entities: list[dict[str, Any]] = []
    for key, entity_type in (
        ("indicators", "indicator"),
        ("reports", "report"),
        ("threat_actors", "threat_actor"),
        ("malware_families", "malware"),
        ("attack_patterns", "attack_pattern"),
    ):
        for row in _as_list(opencti.get(key))[:20]:
            if isinstance(row, dict):
                related_entities.append(
                    {
                        "type": entity_type,
                        "name": row.get("name") or row.get("pattern") or row.get("id"),
                        "description": row.get("description") or row.get("mitre_id") or row.get("confidence") or _join(row.get("report_types") or row.get("malware_types")),
                        "date": row.get("published") or row.get("created") or row.get("valid_from") or row.get("first_seen"),
                    }
                )
    for key, entity_type in (("campaigns", "campaign"), ("intrusion_sets", "intrusion_set")):
        for value in _as_list(opencti.get(key))[:20]:
            related_entities.append({"type": entity_type, "name": value, "description": "", "date": ""})

    if not opencti:
        status = "not_collected"
    elif found:
        status = "matched"
    elif any("not configured" in str(note).lower() for note in notes):
        status = "not_configured"
    else:
        status = "no_match"

    recommendations = []
    if found:
        recommendations.append("Use the matched OpenCTI observable as the internal source of truth for escalation and tagging.")
        if sum(relationship_counts.values()):
            recommendations.append("Pivot on linked OpenCTI indicators, reports, malware, intrusion sets, and ATT&CK context before closure.")
        if opencti.get("score") and _num(opencti.get("score")) >= 70:
            recommendations.append("Treat the internal CTI score as a high-confidence corroborating signal.")
    elif status == "no_match":
        recommendations.append("No OpenCTI match was resolved; review the searched variants and consider adding a new observable if external evidence is strong.")
    elif status == "not_configured":
        recommendations.append("Configure OpenCTI API URL/key to enable internal CTI matching.")

    return {
        "status": status,
        "searched_terms": searched_terms,
        "matched_term": matched_term,
        "matched_observable": {
            "id": opencti.get("observable_id"),
            "standard_id": opencti.get("standard_id"),
            "entity_type": opencti.get("observable_entity_type"),
            "value": opencti.get("observable_value"),
            "score": opencti.get("score"),
            "author": opencti.get("author"),
            "labels": opencti.get("labels") or [],
            "markings": opencti.get("markings") or [],
            "created_at": opencti.get("created_at"),
            "updated_at": opencti.get("updated_at"),
        } if found else None,
        "relationship_counts": relationship_counts,
        "related_entities": related_entities[:80],
        "notes": notes[:12],
        "recommendations": recommendations,
    }


def build_soc_report_outline(
    *,
    evidence: dict[str, Any],
    report: dict[str, Any],
    detail: dict[str, Any],
    timeline: list[dict[str, Any]],
    confidence: dict[str, Any],
    graph: dict[str, Any],
    ioc_quality: dict[str, Any],
    opencti: dict[str, Any],
) -> dict[str, Any]:
    """Build an official SOC documentation outline from derived intelligence."""
    evidence_matrix = build_evidence_matrix_rows(evidence=evidence, report=report)
    sections = [
        {
            "id": "executive_summary",
            "title": "Executive Summary",
            "purpose": "Document the observable, verdict, confidence, and business-level exposure.",
            "status": "ready" if report.get("primary_reasoning") or confidence.get("reasons") else "needs_review",
        },
        {
            "id": "verdict_confidence",
            "title": "Verdict and Confidence Rationale",
            "purpose": "Explain the platform verdict, component scores, source agreement, and mitigating evidence.",
            "status": "ready" if confidence.get("components") else "needs_data",
        },
        {
            "id": "evidence_matrix",
            "title": "Evidence Matrix",
            "purpose": "Map analyst conclusions to concrete collected evidence references and observed values.",
            "status": "ready" if evidence_matrix else "needs_data",
        },
        {
            "id": "findings",
            "title": "Findings",
            "purpose": "Summarize the material technical findings that support SOC triage.",
            "status": "ready" if report.get("findings") else "needs_review",
        },
        {
            "id": "indicators",
            "title": "Indicators of Compromise",
            "purpose": "List primary and derived IOCs with confidence, context, and actionability.",
            "status": "ready" if report.get("iocs") or ioc_quality.get("items") else "needs_data",
        },
        {
            "id": "soc_actions",
            "title": "Recommended SOC Actions",
            "purpose": "Define containment, hunting, monitoring, and evidence-retention actions.",
            "status": "ready",
        },
        {
            "id": "derived_verdict",
            "title": "Derived SOC Intelligence Verdict",
            "purpose": "Record the platform-derived verdict, score, source components, and rationale.",
            "status": "ready" if confidence.get("components") else "needs_data",
        },
        {
            "id": "ioc_quality",
            "title": "IOC Quality and Actionability",
            "purpose": "Classify IOCs as high-value, actionable, low-value, volatile, or contextual.",
            "status": "ready" if ioc_quality.get("items") else "needs_data",
        },
    ]
    ready = sum(1 for section in sections if section["status"] == "ready")
    readiness_score = round((ready / len(sections)) * 100)
    priority_actions = _build_priority_actions(confidence, ioc_quality, opencti, report, detail)
    recommended_title = f"SOC Investigation Report - {_primary_observable(evidence, detail) or 'Observable'}"

    return {
        "readiness_score": readiness_score,
        "sections": sections,
        "evidence_matrix": evidence_matrix,
        "preview": _build_soc_report_preview(
            title=recommended_title,
            evidence=evidence,
            report=report,
            confidence=confidence,
            ioc_quality=ioc_quality,
            priority_actions=priority_actions,
            evidence_matrix=evidence_matrix,
        ),
        "priority_actions": priority_actions,
        "export_profile": "official_soc_documentation",
        "recommended_title": recommended_title,
        "missing_sections": [section["title"] for section in sections if section["status"] not in {"ready"}],
    }


def _build_soc_report_preview(
    *,
    title: str,
    evidence: dict[str, Any],
    report: dict[str, Any],
    confidence: dict[str, Any],
    ioc_quality: dict[str, Any],
    priority_actions: list[str],
    evidence_matrix: list[dict[str, str]],
) -> dict[str, Any]:
    summary = (
        _clean(report.get("executive_summary"))
        or _clean(report.get("primary_reasoning"))
        or _clean(confidence.get("explanation"))
        or "No analyst executive summary is available for this investigation yet."
    )
    findings: list[dict[str, str]] = []
    for finding in _as_list(report.get("findings"))[:8]:
        if not isinstance(finding, dict):
            continue
        findings.append(
            {
                "severity": _clean(finding.get("severity")) or "info",
                "title": _clean(finding.get("title")) or "Untitled finding",
                "description": _clean(finding.get("description")),
                "ttp": _clean(finding.get("ttp")),
            }
        )

    report_iocs = [
        {
            "type": _clean(ioc.get("type")).upper(),
            "value": _clean(ioc.get("value")),
            "context": _clean(ioc.get("context")),
            "confidence": _clean(ioc.get("confidence")).upper(),
        }
        for ioc in _as_list(report.get("iocs"))[:20]
        if isinstance(ioc, dict) and _clean(ioc.get("value"))
    ]
    quality_iocs = [
        {
            "type": _clean(ioc.get("type")).upper(),
            "value": _clean(ioc.get("value")),
            "quality": str(ioc.get("quality_score") or ""),
            "labels": _join(ioc.get("labels")),
            "action": _clean(ioc.get("recommended_action")),
        }
        for ioc in _as_list(ioc_quality.get("items"))[:20]
        if isinstance(ioc, dict) and _clean(ioc.get("value"))
    ]

    return {
        "title": title,
        "classification": _clean(confidence.get("verdict") or report.get("classification")).upper(),
        "confidence": _clean(confidence.get("confidence") or report.get("confidence")).upper(),
        "risk_score": confidence.get("score") if confidence.get("score") is not None else report.get("risk_score"),
        "summary": summary,
        "verdict_rationale": _as_list(confidence.get("reasons"))[:8],
        "evidence_matrix": evidence_matrix[:16],
        "findings": findings,
        "iocs": report_iocs,
        "recommended_actions": priority_actions[:8],
        "derived_verdict": {
            "verdict": _clean(confidence.get("verdict")).upper(),
            "score": confidence.get("score"),
            "confidence": _clean(confidence.get("confidence")).upper(),
            "explanation": _clean(confidence.get("explanation")),
        },
        "ioc_quality": quality_iocs,
        "observable": _primary_observable(evidence, {}),
    }


def _score_ioc(row: dict[str, Any], *, hosting: dict[str, Any], opencti: dict[str, Any]) -> dict[str, Any]:
    ioc_type = row.get("type") or "domain"
    value = row.get("value") or ""
    sources = [str(source).lower() for source in row.get("sources", [])]
    contexts = [str(ctx).lower() for ctx in row.get("contexts", [])]
    labels: list[str] = []
    reasons: list[str] = []
    score = IOC_TYPE_BASE_SCORE.get(ioc_type, 45)

    confidence = str(row.get("confidence") or "").lower()
    if confidence == "high":
        score += 18
    elif confidence == "medium":
        score += 8

    if "anyrun" in sources:
        score += 15
        labels.append("sandbox-derived")
        reasons.append("Observed in sandbox behavior.")
    if "opencti" in sources:
        score += 18
        labels.append("opencti-linked")
        reasons.append("Linked to internal OpenCTI intelligence.")
    if "threatfox" in sources or "threat_feeds" in sources:
        score += 16
        labels.append("feed-confirmed")
        reasons.append("Confirmed by external threat feed data.")
    if "analyst_report" in sources:
        score += 10
        reasons.append("Included in analyst report IOCs.")
    if "virustotal" in sources:
        score += 8
        reasons.append("Present in VirusTotal context.")

    if _is_known_platform_noise(value, sources):
        score = min(score, 38)
        labels.extend(["low-value", "platform-noise"])
        reasons.append("Looks like routine sandbox background traffic to a major platform or certificate endpoint.")
        return {
            "quality_score": int(max(0, min(100, score))),
            "labels": _dedupe(labels),
            "recommended_action": "monitor",
            "rationale": _dedupe(reasons)[:5],
        }

    if any("dropped" in ctx or "file" in ctx for ctx in contexts) and ioc_type == "hash":
        score += 12
        labels.append("high-value")
    if any("contacted" in ctx or "c2" in ctx or "command" in ctx for ctx in contexts):
        score += 10
        labels.append("high-value")
    if ioc_type == "url" and ("?" in value or len(value) > 120):
        labels.append("volatile")
        score -= 5
    if ioc_type in {"domain", "ip"} and _looks_shared_infra(value, hosting):
        labels.append("low-value")
        score -= 26
        reasons.append("May represent shared infrastructure or CDN/cloud hosting.")
    if ioc_type == "domain" and _looks_generic_domain(value):
        labels.append("low-value")
        score -= 12

    if score >= 78:
        labels.append("high-value")
    if score >= 66:
        labels.append("actionable")
    if score <= 45 and "low-value" not in labels:
        labels.append("low-value")

    score = int(max(0, min(100, score)))
    action = "block_or_hunt" if score >= 74 else "hunt" if score >= 58 else "monitor"
    return {
        "quality_score": score,
        "labels": _dedupe(labels),
        "recommended_action": action,
        "rationale": _dedupe(reasons)[:5],
    }


def _build_priority_actions(confidence: dict[str, Any], ioc_quality: dict[str, Any], opencti: dict[str, Any], report: dict[str, Any], detail: dict[str, Any]) -> list[str]:
    report_steps = [_clean(step) for step in _as_list(report.get("recommended_steps")) if _clean(step)]
    if report_steps:
        return report_steps[:8]
    verdict = str(confidence.get("verdict") or report.get("classification") or detail.get("classification") or "").lower()
    actionable = ioc_quality.get("summary", {}).get("actionable_count", 0)
    actions: list[str] = []
    if verdict == "malicious":
        actions.append("Block the primary observable and high-quality derived IOCs at proxy, DNS, email, and endpoint controls.")
    elif verdict == "suspicious":
        actions.append("Hunt for the observable and derived IOCs in proxy, DNS, EDR, and SIEM telemetry before applying broad blocking.")
    else:
        actions.append("Monitor for new intelligence and retain the investigation record.")
    if actionable:
        actions.append(f"Prioritize {actionable} actionable IOC(s) for threat hunting and control validation.")
    if opencti.get("status") == "matched":
        actions.append("Pivot through the matched OpenCTI relationships and preserve the internal CTI context in the report.")
    actions.append("Record evidence gaps and re-run stale or missing collectors before final closure.")
    return actions


def _confidence_explanation(verdict: str, confidence: str, components: list[dict[str, Any]]) -> str:
    if not components:
        return "No trusted scoring components were available, so the platform cannot produce a confident derived verdict."
    sources = ", ".join(row["source"] for row in components[:5])
    return f"Derived {verdict} verdict with {confidence} confidence from {len(components)} source component(s): {sources}."


def _extract_iocs_from_pattern(pattern: Any) -> list[tuple[str, str]]:
    text = _clean(pattern)
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for stix_type, ioc_type in (
        ("url", "url"),
        ("domain-name", "domain"),
        ("ipv4-addr", "ip"),
        ("ipv6-addr", "ip"),
        ("file", "hash"),
    ):
        for match in re.finditer(rf"{re.escape(stix_type)}:[a-zA-Z0-9_.'-]+\s*=\s*'([^']+)'", text, re.I):
            out.append((ioc_type, match.group(1)))
    return out


def _extract_opencti_search_terms(notes: list[Any]) -> list[str]:
    joined = "\n".join(str(note) for note in notes)
    match = re.search(r"searched:\s*([^)]+)\)", joined, re.I)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()]


def _extract_opencti_matched_term(notes: list[Any]) -> str:
    joined = "\n".join(str(note) for note in notes)
    match = re.search(r"matched via search term:\s*'([^']+)'", joined, re.I)
    return match.group(1).strip() if match else ""


def _build_search_variants(value: str, observable_type: str) -> list[str]:
    value = _clean(value)
    if not value:
        return []
    if observable_type == "domain":
        return _dedupe([value, f"http://{value}", f"https://{value}"])
    if observable_type == "url":
        host = urlparse(value).hostname or ""
        return _dedupe([value, host])
    return [value]


def _anyrun_items(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    hybrid = _as_dict(evidence.get("hybrid_analysis"))
    return [item for item in _as_list(hybrid.get("items")) if isinstance(item, dict)]


def _primary_observable(evidence: dict[str, Any], detail: dict[str, Any]) -> str:
    return _clean(detail.get("domain") or evidence.get("domain"))


def _normalize_ioc_type(ioc_type: Any, value: str) -> str:
    text = str(ioc_type or "").strip().lower().replace("_", "-")
    if text in {"domain", "domain-name", "hostname", "host"}:
        return "domain"
    if text in {"ip", "ipv4", "ipv6", "ipv4-addr", "ipv6-addr"}:
        return "ip"
    if text in {"url", "uri"}:
        return "url"
    if text in {"hash", "sha256", "sha1", "md5", "file", "stixfile"}:
        return "hash"
    if text == "email":
        return "email"
    if value.startswith(("http://", "https://")):
        return "url"
    if _is_ip(value):
        return "ip"
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return "hash"
    if "@" in value and "." in value:
        return "email"
    if "." in value and " " not in value:
        return "domain"
    return ""


def _looks_shared_infra(value: str, hosting: dict[str, Any]) -> bool:
    if hosting.get("is_cdn") or hosting.get("is_cloud"):
        if value == _clean(hosting.get("ip")) or _clean(hosting.get("asn_org")).lower() in value.lower():
            return True
    lowered = value.lower()
    return any(token in lowered for token in ("cloudflare", "akamai", "fastly", "azureedge", "amazonaws", "googleusercontent"))


def _is_known_platform_noise(value: str, sources: list[str]) -> bool:
    if "anyrun" not in sources:
        return False
    lowered = value.lower()
    host = lowered
    if lowered.startswith(("http://", "https://")):
        host = (urlparse(lowered).hostname or lowered).lower()
    known_suffixes = (
        "microsoft.com",
        "windows.com",
        "live.com",
        "bing.com",
        "skype.com",
        "azureedge.net",
        "microsoftapp.net",
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "gstatic.com",
    )
    known_markers = (
        "/pki/",
        "/pkiops/",
        "/crl/",
        "browsernetworktime",
        "componentupdater",
        "filestreamingservice",
        "delivery.mp.microsoft.com",
        "update.googleapis.com",
    )
    return host.endswith(known_suffixes) or any(marker in lowered for marker in known_markers)


def _looks_generic_domain(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("cdn.", "static.", "assets.", "analytics.", "fonts.", "ajax."))


def _stronger_confidence(left: Any, right: Any) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    l = str(left or "low").lower()
    r = str(right or "low").lower()
    return r if order.get(r, 1) > order.get(l, 1) else l


def _node_id(node_type: str, value: str) -> str:
    digest = hashlib.sha1(f"{node_type}:{value}".encode("utf-8")).hexdigest()[:12]
    safe_type = re.sub(r"[^a-z0-9_-]", "_", node_type.lower())
    return f"{safe_type}:{digest}"


def _score_from_verdict(verdict: Any) -> float:
    text = str(verdict or "").lower()
    if text in {"malicious", "critical", "high"}:
        return 86.0
    if text in {"suspicious", "medium"}:
        return 55.0
    if text in {"benign", "clean", "low"}:
        return 8.0
    return 0.0


def _verdict_from_score(score: Any) -> str:
    value = _num(score)
    if value >= 70:
        return "malicious"
    if value >= 35:
        return "suspicious"
    if value > 0:
        return "benign"
    return "unknown"


def _severity_from_verdict(verdict: Any) -> str:
    text = str(verdict or "").lower()
    if text in {"malicious", "critical", "high"}:
        return "danger"
    if text in {"suspicious", "medium"}:
        return "warning"
    if text in {"benign", "clean", "low"}:
        return "success"
    return "info"


def _severity_from_score(score: Any) -> str:
    value = _num(score)
    if value >= 70:
        return "danger"
    if value >= 35:
        return "warning"
    return "info"


def _iso_or_none(value: Any) -> str | None:
    parsed = _parse_dt(value)
    return parsed.isoformat() if parsed else None


def _parse_dt(value: Any) -> datetime | None:
    text = _clean(value)
    if not text:
        return None
    if text.isdigit():
        try:
            numeric = int(text)
            if numeric > 10_000_000_000:
                numeric = int(numeric / 1000)
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except Exception:
            return None
    try:
        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(_clean(value).strip("[]"))
        return True
    except Exception:
        return False


def _num(value: Any) -> float:
    try:
        return float(str(value))
    except Exception:
        return 0.0


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def _join(values: Any, limit: int = 8) -> str:
    if isinstance(values, dict):
        values = [f"{k}: {v}" for k, v in values.items()]
    if not isinstance(values, list):
        return _clean(values)
    cleaned = [_clean(v) for v in values if _clean(v)]
    if len(cleaned) > limit:
        return ", ".join(cleaned[:limit]) + f", +{len(cleaned) - limit} more"
    return ", ".join(cleaned)


def _resolve_evidence_path(evidence: dict[str, Any], ref: str) -> Any:
    current: Any = evidence
    for raw_segment in ref.split("."):
        segment = _clean(raw_segment)
        if not segment:
            return None
        key, idx = _parse_path_segment(segment)
        if key:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current.get(key)
        if idx is not None:
            if not isinstance(current, list) or idx < 0 or idx >= len(current):
                return None
            current = current[idx]
    return current


def _parse_path_segment(segment: str) -> tuple[str, int | None]:
    if "[" not in segment or not segment.endswith("]"):
        return segment, None
    key, _, idx_raw = segment.partition("[")
    idx_text = idx_raw[:-1].strip()
    if not idx_text.isdigit():
        return key, None
    return key, int(idx_text)


def _has_matrix_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(_clean(value))
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _compact_matrix_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        text = _clean(value)
        return text if len(text) <= 260 else text[:257] + "..."
    if isinstance(value, list):
        if not value:
            return ""
        scalar_items = [item for item in value if isinstance(item, (str, int, float, bool))]
        if len(scalar_items) == len(value):
            shown = [_clean(item) for item in scalar_items[:8] if _clean(item)]
            suffix = f" (+{len(value) - 8} more)" if len(value) > 8 else ""
            return ", ".join(shown) + suffix
        return f"{len(value)} structured item(s) collected."
    if isinstance(value, dict):
        important = (
            "status",
            "verdict",
            "classification",
            "risk_score",
            "risk_level",
            "confidence",
            "score",
            "found",
            "present",
            "malicious_count",
            "suspicious_count",
            "abuse_confidence_score",
            "registrar",
            "issuer_org",
            "asn_org",
            "country",
            "observable_value",
        )
        pairs = [
            f"{key}={value[key]}"
            for key in important
            if key in value and isinstance(value[key], (str, int, float, bool))
        ]
        if pairs:
            return "; ".join(pairs[:8])
        return "Structured fields: " + ", ".join(list(value.keys())[:8])
    return _clean(value)[:260]


def _compact(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, (str, int, float, bool)):
        return _clean(value)[:260]
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    if isinstance(value, dict):
        return "Structured fields: " + ", ".join(list(value.keys())[:8])
    return _clean(value)[:260]


def _dedupe(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _clean(value)
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _titleize(value: str) -> str:
    return _clean(value).replace("_", " ").replace("-", " ").title()
