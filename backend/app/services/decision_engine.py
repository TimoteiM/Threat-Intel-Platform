"""
Deterministic investigation decision engine.

The engine produces the canonical verdict fields from collected evidence.
LLM analysts may explain and contextualize the decision, but should not be the
source of truth for classification, risk score, or action.
"""

from __future__ import annotations

from typing import Any


_ANYRUN_MALICIOUS_LABEL_MARKERS = (
    "phish",
    "clickfix",
    "clearfake",
    "fake captcha",
    "fake-captcha",
    "exploit-kit",
    "exploit kit",
    "exploit",
    "obfuscated-js",
    "obfuscated js",
    "etherhiding",
    "tdsshop",
    "credential theft",
    "credential harvesting",
    "stealer",
)


def build_decision_report(evidence_data: dict[str, Any], observable_type: str) -> dict[str, Any]:
    vt = evidence_data.get("vt") or {}
    threat_feeds = evidence_data.get("threat_feeds") or {}
    domain = evidence_data.get("domain", "")

    classification = "benign"
    confidence = "medium"
    risk_score: int | None = 10
    recommended_action = "monitor"
    key_evidence: list[str] = []
    findings: list[dict[str, Any]] = []
    data_needed: list[str] = []
    recommended_steps: list[str] = []

    if observable_type in {"hash", "file"}:
        vt_found = bool(vt.get("found", False))
        vt_malicious = int(vt.get("malicious_count") or 0)
        vt_suspicious = int(vt.get("suspicious_count") or 0)
        vt_total = int(vt.get("total_vendors") or 0)
        flagged_by = vt.get("flagged_malicious_by", []) or []

        if not vt_found:
            classification = "inconclusive"
            confidence = "low"
            risk_score = None
            recommended_action = "investigate"
            key_evidence = ["Hash not found in VirusTotal database"]
        elif vt_malicious >= 5:
            classification = "malicious"
            confidence = "high"
            risk_score = min(98, 70 + vt_malicious)
            recommended_action = "block"
            vendors = ", ".join(flagged_by[:5]) + (f" +{len(flagged_by) - 5} more" if len(flagged_by) > 5 else "")
            key_evidence = [
                f"Detected malicious by {vt_malicious}/{vt_total} antivirus vendors",
                f"Flagged by: {vendors}",
            ]
        elif vt_malicious >= 2 or vt_suspicious >= 3:
            classification = "suspicious"
            confidence = "medium"
            risk_score = 65
            recommended_action = "investigate"
            key_evidence = [f"{vt_malicious} malicious, {vt_suspicious} suspicious vendor flags"]
        elif vt_malicious == 1:
            classification = "suspicious"
            confidence = "low"
            risk_score = 35
            recommended_action = "monitor"
            vendor = flagged_by[0] if flagged_by else "unknown vendor"
            key_evidence = [f"Single vendor detection ({vendor}) - may be a false positive"]
        else:
            classification = "benign"
            confidence = "medium"
            risk_score = 5
            recommended_action = "monitor"
            key_evidence = [f"Clean - 0/{vt_total} detections in VirusTotal"]

    elif observable_type == "ip":
        vt_found = bool(vt.get("found", False))
        vt_malicious = int(vt.get("malicious_count") or 0) if vt_found else 0
        vt_total = int(vt.get("total_vendors") or 0)
        abuseipdb = threat_feeds.get("abuseipdb") or {}
        abuse_score = int(abuseipdb.get("abuse_confidence_score") or 0)
        abuse_reports = int(abuseipdb.get("total_reports") or 0)
        tf_matches = threat_feeds.get("threatfox_matches") or []

        if vt_malicious >= 5 or abuse_score >= 80 or tf_matches:
            classification = "malicious"
            confidence = "high"
            risk_score = max(85, min(98, abuse_score))
            recommended_action = "block"
            if vt_malicious:
                key_evidence.append(f"Flagged malicious by {vt_malicious}/{vt_total} VT vendors")
            if abuse_score:
                key_evidence.append(f"AbuseIPDB confidence: {abuse_score}% ({abuse_reports} reports)")
            if tf_matches:
                key_evidence.append(f"ThreatFox IOC matches: {len(tf_matches)}")
        elif vt_malicious >= 2 or abuse_score >= 40:
            classification = "suspicious"
            confidence = "medium"
            risk_score = max(45, min(70, abuse_score))
            recommended_action = "investigate"
            if vt_malicious:
                key_evidence.append(f"Flagged by {vt_malicious} VT vendors")
            if abuse_score:
                key_evidence.append(f"AbuseIPDB score: {abuse_score}%")
        else:
            classification = "benign"
            confidence = "medium"
            risk_score = 10
            recommended_action = "monitor"
            if vt_found:
                key_evidence.append(f"VT clean: 0/{vt_total} detections")
            if abuse_score == 0 and abuse_reports == 0:
                key_evidence.append("No AbuseIPDB reports")

    elif observable_type in {"domain", "url"}:
        (
            classification,
            confidence,
            risk_score,
            recommended_action,
            key_evidence,
            findings,
            data_needed,
        ) = _decide_domain_url(evidence_data)

    if not findings:
        findings.append(_default_finding(evidence_data, observable_type))

    if not recommended_steps:
        recommended_steps = _recommended_steps(classification)

    headline_evidence = _headline_evidence(key_evidence)
    evidence_str = "; ".join(headline_evidence) if headline_evidence else "No significant threat indicators found."
    risk_text = f"Risk score: {risk_score}/100." if risk_score is not None else "Risk score undetermined."
    summary = (
        f"Deterministic decision for {observable_type.upper()} - {domain}. "
        f"Classification: {classification.upper()} ({confidence} confidence). "
        f"{risk_text} Key evidence: {evidence_str}"
    )

    return {
        "classification": classification,
        "confidence": confidence,
        "investigation_state": "concluded",
        "primary_reasoning": summary,
        "key_evidence": key_evidence,
        "contradicting_evidence": [],
        "data_needed": data_needed,
        "findings": findings,
        "recommended_action": recommended_action,
        "recommended_steps": recommended_steps,
        "risk_score": risk_score,
        "risk_rationale": evidence_str,
        "decision_engine": {
            "version": 1,
            "source": "deterministic",
            "canonical_fields": ["classification", "confidence", "risk_score", "recommended_action"],
        },
    }


def apply_decision_to_report(report_data: dict[str, Any], decision_report: dict[str, Any]) -> dict[str, Any]:
    """Overlay canonical decision fields onto an analyst/fallback report."""
    merged = dict(report_data or {})
    for key in ("classification", "confidence", "risk_score", "recommended_action", "risk_rationale"):
        merged[key] = decision_report.get(key)

    merged["decision_engine"] = decision_report.get("decision_engine")
    merged["key_evidence"] = _merge_str_lists(
        decision_report.get("key_evidence") or [],
        merged.get("key_evidence") or [],
    )
    merged["data_needed"] = _merge_str_lists(
        decision_report.get("data_needed") or [],
        merged.get("data_needed") or [],
    )
    merged["recommended_steps"] = _merge_str_lists(
        decision_report.get("recommended_steps") or [],
        merged.get("recommended_steps") or [],
    )
    merged["findings"] = _merge_findings(
        decision_report.get("findings") or [],
        merged.get("findings") or [],
    )
    return merged


def _decide_domain_url(evidence_data: dict[str, Any]) -> tuple[str, str, int, str, list[str], list[dict[str, Any]], list[str]]:
    vt = evidence_data.get("vt") or {}
    threat_feeds = evidence_data.get("threat_feeds") or {}
    intel = evidence_data.get("intel") or {}
    http = evidence_data.get("http") or {}

    vt_found = bool(vt.get("found", False))
    vt_malicious = int(vt.get("malicious_count") or 0) if vt_found else 0
    vt_suspicious = int(vt.get("suspicious_count") or 0) if vt_found else 0
    vt_total = int(vt.get("total_vendors") or 0)

    intel_hits = [
        hit for hit in (intel.get("blocklist_hits") or [])
        if str((hit or {}).get("source") or "").strip().lower() != "uribl"
    ]
    tf_matches = threat_feeds.get("threatfox_matches") or []
    openphish_listed = bool(threat_feeds.get("openphish_listed"))
    phishtank = threat_feeds.get("phishtank") or {}
    phishtank_positive = bool(phishtank.get("in_database"))
    phishtank_verified = bool(phishtank.get("verified"))

    http_phishing = list(http.get("phishing_indicators") or [])
    http_has_login = bool(http.get("has_login_form"))
    domain_context = _has_domain_suspicion_context(evidence_data)
    high_conf_http = [s for s in http_phishing if _is_high_confidence_http_signal(s)]
    contextual_http = [s for s in http_phishing if _is_contextual_http_signal(s)]
    strong_http = [
        s for s in http_phishing
        if _is_high_confidence_http_signal(s) or (domain_context and _is_contextual_http_signal(s))
    ]
    scored_http = [
        s for s in http_phishing
        if _is_high_confidence_http_signal(s) or (domain_context and not _is_contextual_http_signal(s))
    ]
    http_score = len(strong_http) * 2 + len(scored_http)
    weak_score, weak_evidence = _domain_weak_signal_score(evidence_data, contextual_http=bool(contextual_http))

    anyrun_verdict, anyrun_names, anyrun_context = _best_anyrun_verdict(evidence_data.get("hybrid_analysis") or {})
    anyrun_malicious = anyrun_verdict == "malicious"
    anyrun_suspicious = anyrun_verdict == "suspicious"

    if vt_malicious >= 5 or phishtank_verified or tf_matches or openphish_listed or anyrun_malicious:
        classification, confidence, risk_score, action = "malicious", "high", 90, "block"
    elif high_conf_http and (http_has_login or len(http_phishing) >= 2):
        classification, confidence, risk_score, action = "malicious", "medium", 82, "block"
    elif vt_malicious >= 2 or vt_suspicious >= 5 or len(intel_hits) >= 2 or anyrun_suspicious:
        classification, confidence, risk_score, action = "suspicious", "medium", 60, "investigate"
    elif http_score >= 3 or (strong_http and http_has_login):
        classification, confidence, risk_score, action = "suspicious", "medium", 65, "investigate"
    elif phishtank_positive:
        classification, confidence, risk_score, action = "inconclusive", "low", 30, "investigate"
    elif http_score >= 1:
        classification, confidence, risk_score, action = "suspicious", "low", 40, "monitor"
    elif weak_score >= 4:
        classification, confidence, risk_score, action = "suspicious", "medium", 50, "investigate"
    elif weak_score >= 3:
        classification, confidence, risk_score, action = "suspicious", "low", 40, "monitor"
    else:
        classification, confidence, risk_score, action = "benign", "medium", 15, "monitor"

    key_evidence: list[str] = []
    findings: list[dict[str, Any]] = []
    data_needed: list[str] = []
    if anyrun_verdict:
        names = (", ".join(anyrun_names[:4]) + " ") if anyrun_names else ""
        source_label = "sandbox" if anyrun_context.get("sandbox") else "TI"
        network_label = f" via {anyrun_context['network']}" if anyrun_context.get("network") else ""
        score_label = f" score {anyrun_context['threat_score']}" if anyrun_context.get("threat_score") is not None else ""
        details: list[str] = [
            f"AnyRun {source_label} returned a {anyrun_verdict.upper()} verdict for the investigated indicator."
        ]
        if anyrun_context.get("threat_score") is not None:
            details.append(f"Provider threat score: {anyrun_context['threat_score']}/100.")
        if anyrun_context.get("network"):
            details.append(f"Execution network profile: {anyrun_context['network']}.")
        if anyrun_names:
            details.append(f"Structured provider labels: {', '.join(anyrun_names[:6])}.")
        else:
            details.append("No structured AnyRun threat labels were returned; review the linked sandbox telemetry before treating the verdict as confirmed malicious behavior.")
        if anyrun_malicious:
            details.append("Decision impact: a MALICIOUS sandbox verdict sets the deterministic domain/URL score to 90 before lexical blending and trusted-source floors.")
        elif anyrun_suspicious:
            details.append("Decision impact: a SUSPICIOUS sandbox verdict sets the deterministic domain/URL score to 60 before lexical blending and trusted-source floors.")
        else:
            details.append("Decision impact: a CLEAN AnyRun verdict does not independently raise the deterministic risk score.")
        key_evidence.append(
            f"AnyRun {source_label} verdict: {anyrun_verdict.upper()}{score_label}{network_label} - {names}provider evidence"
        )
        findings.append({
            "id": "anyrun_verdict",
            "title": f"AnyRun {source_label} verdict: {anyrun_verdict.upper()}",
            "description": " ".join(details),
            "severity": "critical" if anyrun_malicious else ("high" if anyrun_suspicious else "info"),
            "evidence_refs": ["hybrid_analysis.items"],
        })
    if vt_found and (vt_malicious > 0 or vt_suspicious > 0 or not (anyrun_malicious or anyrun_suspicious)):
        key_evidence.append(f"VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious of {vt_total}")
    if intel_hits:
        key_evidence.append(f"Intel blocklist hits: {len(intel_hits)}")
    if tf_matches:
        key_evidence.append(f"ThreatFox matches: {len(tf_matches)}")
    if openphish_listed:
        key_evidence.append("OpenPhish listed")
    if phishtank_positive:
        key_evidence.append("PhishTank match" + (" (verified)" if phishtank_verified else " (unverified)"))
        findings.append({
            "id": "fallback_phishtank_hit",
            "title": "PhishTank listing observed",
            "description": "Domain/URL was found in PhishTank feed" + (" with verified status." if phishtank_verified else " but not verified."),
            "severity": "high" if phishtank_verified else "medium",
            "evidence_refs": ["threat_feeds.phishtank"],
        })
        if not phishtank_verified:
            data_needed.append("Confirm whether the PhishTank listing is a true positive or stale/unverified entry.")
    if not anyrun_malicious:
        for sig in strong_http:
            key_evidence.append(f"Static HTTP: {sig}")
    if contextual_http and not domain_context and not anyrun_malicious:
        key_evidence.append("Static HTTP input/brand observations were treated as contextual because no independent suspicious-domain signal was present")
    if not anyrun_malicious:
        for item in weak_evidence:
            key_evidence.append(item)

    if vt_malicious > 0 or vt_suspicious > 0:
        findings.append({
            "id": "fallback_vt_signal",
            "title": "VirusTotal detection signal",
            "description": f"VT reports {vt_malicious} malicious and {vt_suspicious} suspicious detections.",
            "severity": "high" if vt_malicious >= 3 else "medium",
            "evidence_refs": ["vt.malicious_count", "vt.suspicious_count"],
        })
    if http_phishing:
        findings.append({
            "id": "static_http_phishing",
            "title": "Static HTTP content observations detected",
            "description": _http_finding_description(http_phishing, http_has_login, bool(contextual_http and not domain_context)),
            "severity": "high" if high_conf_http else ("medium" if strong_http else "low"),
            "evidence_refs": ["http.phishing_indicators", "http.has_login_form"],
        })
    if weak_score >= 3:
        findings.append({
            "id": "weak_signal_cluster",
            "title": "Suspicious weak-signal cluster",
            "description": "Multiple medium-confidence signals combine into suspicious context: " + "; ".join(weak_evidence[:6]),
            "severity": "medium" if weak_score >= 4 else "low",
            "evidence_refs": ["url_lexical_ml", "signals", "infrastructure_pivot", "email_security"],
        })

    return classification, confidence, risk_score, action, key_evidence, findings, data_needed


def _domain_weak_signal_score(evidence_data: dict[str, Any], *, contextual_http: bool = False) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    lexical = evidence_data.get("url_lexical_ml") or {}
    if not isinstance(lexical, dict) or not lexical:
        lexical = (evidence_data.get("ml_url_score") or {}).get("raw") or evidence_data.get("ml_url_score") or {}
    if isinstance(lexical, dict):
        label = str(lexical.get("label") or lexical.get("risk_level") or "").lower()
        try:
            lexical_score = float(lexical.get("score") or lexical.get("phishing_probability") or 0.0)
        except Exception:
            lexical_score = 0.0
        top_features = [str(x).lower() for x in (lexical.get("top_features") or [])]
        if label == "high" or lexical_score >= 0.65:
            score += 2
            reasons.append(f"Lexical model high risk ({lexical_score:.2f})")
        elif label == "medium" or lexical_score >= 0.45:
            score += 1
            reasons.append(f"Lexical model medium risk ({lexical_score:.2f})")
        if "has_sensitive_keyword" in top_features:
            score += 1
            reasons.append("Hostname contains a sensitive keyword such as secure/login/account")

    email = evidence_data.get("email_security") or {}
    if isinstance(email, dict) and str(email.get("spoofability_score") or "").lower() == "high":
        score += 1
        reasons.append("High email spoofability")

    infra = evidence_data.get("infrastructure_pivot") or {}
    if isinstance(infra, dict):
        if infra.get("shared_hosting_detected"):
            score += 1
            reasons.append("Shared hosting or crowded infrastructure observed")
        if infra.get("registrant_pivots"):
            score += 1
            reasons.append("Registrant/registrar pivot links to other investigated domains")

    signals = evidence_data.get("signals") or []
    if isinstance(signals, list):
        signal_ids = {
            str(sig.get("id") or "")
            for sig in signals
            if isinstance(sig, dict)
        }
        if "sig_high_spoofability" in signal_ids and "High email spoofability" not in reasons:
            score += 1
            reasons.append("High email spoofability")
        if {"sig_shared_hosting", "sig_registrant_pivot"} & signal_ids and not any("infrastructure" in r for r in reasons):
            score += 1
            reasons.append("Infrastructure pivot signal observed")

    if contextual_http:
        score += 1
        reasons.append("Static HTTP brand/input observation present")

    return score, reasons


def _best_anyrun_verdict(hybrid: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]]:
    verdict = str(hybrid.get("verdict") or "").strip().lower()
    names: list[str] = _anyrun_labels_from_item(hybrid)
    context: dict[str, Any] = _anyrun_context_from_item(hybrid)
    malicious_labels = _anyrun_malicious_labels(names)
    for item in hybrid.get("items") or []:
        if not isinstance(item, dict):
            continue
        item_verdict = str(item.get("verdict") or "").strip().lower()
        item_names = _anyrun_labels_from_item(item)
        item_context = _anyrun_context_from_item(item)
        malicious_labels.extend(label for label in _anyrun_malicious_labels(item_names) if label not in malicious_labels)
        if item_verdict == "malicious":
            return "malicious", item_names or names, item_context or context
        if item_verdict == "suspicious" and verdict != "malicious":
            verdict = "suspicious"
            names = names or item_names
            context = item_context or context
    if malicious_labels:
        return "malicious", malicious_labels, context
    return verdict if verdict in {"malicious", "suspicious", "clean"} else "", names, context


def _anyrun_context_from_item(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("raw_summary") or {}
    dynamic = item.get("dynamic_io_summary") or {}
    mode = str((raw or {}).get("mode") or item.get("mode") or "").strip().lower()
    profile = {}
    if isinstance(raw, dict):
        profile = raw.get("network_profile") or {}
    if not profile and isinstance(dynamic, dict):
        profile = dynamic.get("network_profile") or {}
    network = ""
    if isinstance(profile, dict) and (profile.get("use_residential_proxy") or profile.get("anyrun_residential_proxy")):
        country = str(profile.get("proxy_country") or profile.get("anyrun_residential_proxy_geo") or "").strip().upper()
        network = f"Residential Proxy {country}" if country and country != "FASTEST" else "Residential Proxy fastest"
    return {
        "sandbox": mode == "sandbox",
        "network": network,
        "threat_score": item.get("threat_score"),
    }


def _headline_evidence(items: list[str], limit: int = 5) -> list[str]:
    def priority(value: str) -> int:
        text = value.casefold()
        if text.startswith("anyrun sandbox"):
            return 0
        if text.startswith("anyrun"):
            return 1
        if "openphish" in text or "phishtank" in text or "threatfox" in text:
            return 2
        if "virustotal" in text and not ("0 malicious" in text and "0 suspicious" in text):
            return 3
        if "static http" in text or "email spoofability" in text:
            return 8
        return 5

    filtered = [
        item for item in items
        if not (
            ("VirusTotal:" in item and "0 malicious" in item and "0 suspicious" in item)
            or item == "High email spoofability"
            or item == "Static HTTP brand/input observation present"
        )
    ]
    return sorted(filtered or items, key=priority)[:limit]


def _anyrun_labels_from_item(item: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        for raw in _as_list(value):
            text = ""
            if isinstance(raw, str):
                text = raw.strip()
            elif isinstance(raw, dict):
                for key in ("threatName", "name", "tag", "title", "label", "value", "detectedType", "tracker"):
                    text = str(raw.get(key) or "").strip()
                    if text:
                        break
            elif raw is not None:
                text = str(raw).strip()
            key = text.casefold()
            if text and key not in seen:
                seen.add(key)
                labels.append(text)

    add(item.get("threat_names") or item.get("threatName") or item.get("threat_name"))
    add(item.get("tags"))
    raw = item.get("raw_summary") or {}
    if isinstance(raw, dict):
        add(raw.get("threatName") or raw.get("threat_names") or raw.get("threat_name"))
        add(raw.get("tags"))
        add(raw.get("tracker") or raw.get("trackers"))
        summary = raw.get("summary") or {}
        if isinstance(summary, dict):
            add(summary.get("threatName") or summary.get("threatNames"))
            add(summary.get("tags"))
            add(summary.get("detectedType"))
            add(summary.get("tracker") or summary.get("trackers"))
    return labels


def _anyrun_malicious_labels(labels: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for label in labels:
        text = str(label or "").strip()
        lower = text.casefold()
        if not text or lower in seen:
            continue
        if any(marker in lower for marker in _ANYRUN_MALICIOUS_LABEL_MARKERS):
            seen.add(lower)
            out.append(text)
    return out


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _http_finding_description(indicators: list[str], has_login: bool, contextual_only: bool) -> str:
    parts = [f"Static HTTP analysis identified {len(indicators)} content observation(s):"]
    parts.extend(f"  * {item}" for item in indicators[:6])
    if has_login:
        parts.append("  * Login/account input field present on page")
    if contextual_only:
        parts.append("  * Input fields and third-party brand references are common on legitimate sites and were not used to raise risk without independent suspicious-domain context")
    return " ".join(parts)


def _default_finding(evidence_data: dict[str, Any], observable_type: str) -> dict[str, Any]:
    return {
        "id": "fallback_no_high_risk_findings",
        "title": "No high-risk technical findings detected",
        "description": (
            "Automated checks across available reputation, infrastructure, and behavior telemetry "
            "did not produce high-confidence malicious indicators."
        ),
        "severity": "info",
        "evidence_refs": ["vt", "threat_feeds", "final_risk"] if observable_type in {"domain", "url"} else ["vt"],
    }


def _recommended_steps(classification: str) -> list[str]:
    if classification == "malicious":
        return [
            "Open an incident ticket and escalate for SOC validation.",
            "Block or heavily monitor the observable at perimeter controls.",
            "Hunt for related indicators in recent logs and endpoint telemetry.",
        ]
    if classification in {"suspicious", "inconclusive"}:
        return [
            "Validate external feed matches with manual review.",
            "Correlate with internal telemetry for real user impact.",
            "Re-run investigation if infrastructure/content changes are observed.",
        ]
    return [
        "Keep the observable in passive monitoring for 7-14 days.",
        "Track certificate and DNS changes for sudden infrastructure shifts.",
        "Alert only if verified malicious feed matches appear.",
    ]


def _merge_str_lists(primary: list[Any], secondary: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in [*primary, *secondary]:
        text = str(item or "").strip()
        key = text.casefold()
        if not text or key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _merge_findings(primary: list[Any], secondary: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*primary, *secondary]:
        if not isinstance(item, dict):
            continue
        key = str(item.get("id") or item.get("title") or "").strip().casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _is_contextual_http_signal(signal: object) -> bool:
    text = str(signal or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "email-only input",
            "credential or account input fields",
            "third-party brand reference",
            "brand impersonation",
        )
    )


def _is_high_confidence_http_signal(signal: object) -> bool:
    text = str(signal or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "form posts to external domain",
            "telegram bot api",
            "hardcoded external url",
            "credential exfiltration",
            "clickfix fake captcha",
            "paste/run a command",
        )
    )


def _has_domain_suspicion_context(evidence_data: dict[str, Any]) -> bool:
    vt = evidence_data.get("vt") or {}
    if int(vt.get("malicious_count") or 0) > 0 or int(vt.get("suspicious_count") or 0) >= 3:
        return True
    threat_feeds = evidence_data.get("threat_feeds") or {}
    if threat_feeds.get("openphish_listed") or (threat_feeds.get("threatfox_matches") or []):
        return True
    if (threat_feeds.get("phishtank") or {}).get("verified"):
        return True
    intel = evidence_data.get("intel") or {}
    if any(
        str((hit or {}).get("source") or "").strip().lower() != "uribl"
        for hit in (intel.get("blocklist_hits") or [])
    ):
        return True
    verdict, _, _ = _best_anyrun_verdict(evidence_data.get("hybrid_analysis") or {})
    if verdict in {"malicious", "suspicious"}:
        return True
    similarity = evidence_data.get("domain_similarity") or {}
    if float(similarity.get("overall_similarity_score") or 0) >= 50:
        return True
    visual = evidence_data.get("visual_comparison") or {}
    if visual.get("is_visual_clone"):
        return True
    whois = evidence_data.get("whois") or {}
    age_days = whois.get("domain_age_days")
    if isinstance(age_days, int) and 0 <= age_days <= 30:
        return True
    redirect = evidence_data.get("redirect_analysis") or {}
    return bool(redirect.get("cloaking_detected"))
