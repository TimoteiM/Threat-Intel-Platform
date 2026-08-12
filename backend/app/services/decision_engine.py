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
    "etherhiding",
    "tdsshop",
    "credential theft",
    "credential harvesting",
    "stealer",
)


# A domain registered within this window is treated as a signal in its own right.
NEWLY_REGISTERED_DAYS = 30
YOUNG_DOMAIN_DAYS = 90


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
    vt_ran = str(((vt.get("meta") or {}).get("status") or "")).lower() != "failed"

    # URLScan was collected, displayed in every report — and never read here. A
    # scan that came back "malicious, score 100, tags: phishing" contributed
    # nothing to the verdict.
    urlscan = evidence_data.get("urlscan") or {}
    urlscan_verdict = str(urlscan.get("verdict") or "").strip().lower()
    urlscan_score = int(urlscan.get("score") or 0)
    urlscan_malicious = urlscan_verdict == "malicious" or urlscan_score >= 70
    urlscan_suspicious = urlscan_verdict == "suspicious" or (
        urlscan_verdict not in {"benign", "malicious", ""} and urlscan_score > 0
    )

    domain_age_days = (evidence_data.get("whois") or {}).get("domain_age_days")
    domain_age = int(domain_age_days) if isinstance(domain_age_days, (int, float)) else None
    newly_registered = domain_age is not None and domain_age <= NEWLY_REGISTERED_DAYS
    recently_registered = domain_age is not None and NEWLY_REGISTERED_DAYS < domain_age <= YOUNG_DOMAIN_DAYS

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
    form_detection = _best_sensitive_form_detection(evidence_data)
    anyrun_heuristics = _anyrun_heuristic_observations(evidence_data.get("hybrid_analysis") or {})
    # A clean observable is one nothing flagged — not one that also happens to
    # lack a login page. Requiring `anyrun == "clean"` meant a sandbox that never
    # ran (verdict None) blocked the benign verdict too, and requiring no login
    # form made every business site with a customer portal unclassifiable as
    # benign no matter how clean VirusTotal, the feeds and WHOIS were.
    anyrun_not_flagged = anyrun_verdict not in {"malicious", "suspicious"}
    observable_clean = (
        anyrun_not_flagged
        and vt_found
        and vt_malicious == 0
        and vt_suspicious == 0
        and not phishtank_positive
        and not openphish_listed
        and not tf_matches
        and not intel_hits
        and int((evidence_data.get("whois") or {}).get("domain_age_days") or 0) >= 365
        and not high_conf_http
        and weak_score < 4
    )

    # Reputation is only "clean" when something actually looked. A rate-limited
    # VirusTotal used to read exactly like a VirusTotal that found nothing.
    reputation_available = (
        (vt_found and vt_ran)
        or bool(urlscan_verdict)
        or bool(threat_feeds.get("feeds_checked"))
        or bool(anyrun_verdict)
        or bool(intel_hits)
    )

    if (
        vt_malicious >= 5
        or phishtank_verified
        or tf_matches
        or openphish_listed
        or anyrun_malicious
        or urlscan_malicious
    ):
        classification, confidence, risk_score, action = "malicious", "high", 90, "block"
    elif high_conf_http and (http_has_login or len(http_phishing) >= 2):
        classification, confidence, risk_score, action = "malicious", "medium", 82, "block"
    elif (
        vt_malicious >= 2
        or vt_suspicious >= 5
        or len(intel_hits) >= 2
        or anyrun_suspicious
        or urlscan_suspicious
    ):
        classification, confidence, risk_score, action = "suspicious", "medium", 60, "investigate"
    elif http_score >= 3 or (strong_http and http_has_login):
        classification, confidence, risk_score, action = "suspicious", "medium", 65, "investigate"
    elif phishtank_positive:
        classification, confidence, risk_score, action = "inconclusive", "low", 30, "investigate"
    elif http_score >= 1:
        classification, confidence, risk_score, action = "suspicious", "low", 40, "monitor"
    elif newly_registered:
        # Age is one of the strongest phishing predictors: infrastructure is
        # registered days before a campaign and abandoned after it. Clean
        # reputation on a two-week-old domain means nobody has reported it yet.
        classification, confidence, risk_score, action = "suspicious", "medium", 50, "investigate"
    elif not reputation_available:
        # Nothing was able to look. That is missing evidence, not a clean bill of
        # health — the previous behaviour turned a collector outage into "benign".
        classification, confidence, risk_score, action = "inconclusive", "low", 25, "investigate"
    elif observable_clean:
        # A medium lexical score, shared hosting, or a brand word found in a
        # CSP/resource list must not outweigh several direct clean controls.
        classification, confidence, risk_score, action = "benign", "high", 15, "monitor"
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
        verdict_names = [
            name for name in anyrun_names
            if str(name).strip().casefold() not in {"obfuscated-js", "obfuscated js"}
        ]
        names = (", ".join(verdict_names[:4]) + " ") if verdict_names else ""
        source_label = "sandbox" if anyrun_context.get("sandbox") else "TI"
        network_label = f" via {anyrun_context['network']}" if anyrun_context.get("network") else ""
        score_label = f" score {anyrun_context['threat_score']}" if anyrun_context.get("threat_score") is not None else ""
        details: list[str] = [_anyrun_verdict_sentence(anyrun_verdict, source_label, anyrun_context)]
        if anyrun_context.get("threat_score") is not None:
            details.append(f"Provider threat score: {anyrun_context['threat_score']}/100.")
        if anyrun_context.get("network"):
            details.append(f"Execution network profile: {anyrun_context['network']}.")
        if verdict_names:
            details.append(f"Structured provider labels: {', '.join(verdict_names[:6])}.")
        else:
            details.append("No structured AnyRun threat labels were returned; review the linked sandbox telemetry before treating the verdict as confirmed malicious behavior.")
        if form_detection.get("detected"):
            details.append(
                "A visible data-entry form was detected in the rendered page, but the form was not submitted; "
                "interaction-dependent behavior therefore remains untested."
            )
        if anyrun_malicious and anyrun_context.get("escalated_by"):
            details.append(
                "Decision impact: the provider label — not the provider verdict — set the deterministic "
                "domain/URL score to 90 before lexical blending and trusted-source floors."
            )
        elif anyrun_malicious:
            details.append("Decision impact: a MALICIOUS sandbox verdict sets the deterministic domain/URL score to 90 before lexical blending and trusted-source floors.")
        elif anyrun_suspicious:
            details.append("Decision impact: a SUSPICIOUS sandbox verdict sets the deterministic domain/URL score to 60 before lexical blending and trusted-source floors.")
        else:
            details.append("Decision impact: a CLEAN AnyRun verdict does not independently raise the deterministic risk score.")
        interaction_label = (
            " with incomplete form interaction"
            if form_detection.get("detected")
            else ""
        )
        # The headline must not read as a provider verdict when the provider did
        # not give one. An escalation by label says so in the title, so the
        # finding and the sandbox table on the same screen cannot disagree.
        escalated_labels = [str(label) for label in (anyrun_context.get("escalated_by") or []) if str(label).strip()]
        provider_verdict = str(anyrun_context.get("provider_verdict") or "").strip().upper()
        headline = (
            f"AnyRun {source_label} labelled {', '.join(escalated_labels[:2])}"
            f" (provider verdict: {provider_verdict or 'none'})"
            if escalated_labels
            else f"AnyRun {source_label} verdict: {anyrun_verdict.upper()}"
        )
        key_evidence.append(
            f"{headline}{score_label}{network_label}"
            f"{interaction_label} - {names}provider evidence"
        )
        findings.append({
            "id": "anyrun_verdict",
            "title": headline,
            "description": " ".join(details),
            "severity": "critical" if anyrun_malicious else ("high" if anyrun_suspicious else "info"),
            "evidence_refs": ["hybrid_analysis.items"],
        })
    if anyrun_heuristics:
        heuristic_text = ", ".join(anyrun_heuristics[:4])
        key_evidence.append(
            f"AnyRun heuristic observation: {heuristic_text} (non-verdict signal; no malicious score floor)"
        )
        findings.append({
            "id": "anyrun_heuristic_observation",
            "title": "AnyRun JavaScript-obfuscation heuristic",
            "description": (
                f"AnyRun observed {heuristic_text}. This is a heuristic suspicious indicator that may reflect "
                "decoding or reconstruction logic; by itself it does not prove malicious behavior and does not "
                "override a CLEAN provider verdict."
            ),
            "severity": "low",
            "evidence_refs": ["hybrid_analysis.items.raw_summary.behavior_details.network_threats"],
        })
    if form_detection.get("detected"):
        categories = [
            str(value).replace("_", " ")
            for value in form_detection.get("categories") or []
            if value
        ]
        category_text = ", ".join(categories) if categories else "user data"
        key_evidence.append(
            f"Rendered data-entry form detected ({category_text}); submission was not exercised"
        )
        findings.append({
            "id": "sensitive_data_entry_form",
            "title": "Rendered data-entry form requires interaction review",
            "description": (
                f"The rendered page visibly requests {category_text}. The detector did not submit the form, "
                "so a clean sandbox verdict does not cover behavior triggered after submission."
            ),
            "severity": "medium",
            "evidence_refs": [
                str(form_detection.get("_evidence_ref") or "hybrid_analysis.items.raw_summary.sensitive_form_detection")
            ],
        })
        data_needed.append(
            "Validate the form submission path in an isolated sandbox to determine whether entered data is transmitted or triggers malicious behavior."
        )
    excluded_anyrun_tasks = _excluded_anyrun_task_count(evidence_data.get("hybrid_analysis") or {})
    if excluded_anyrun_tasks:
        findings.append({
            "id": "anyrun_scope_exclusions",
            "title": "AnyRun third-party mentions excluded from domain risk",
            "description": (
                f"{excluded_anyrun_tasks} related AnyRun task(s) were not scored because their main-object hosts "
                "were third-party infrastructure. A domain appearing only in an email address, URL path, query, "
                "or fragment is victim/mention evidence, not proof that the investigated domain hosted the threat."
            ),
            "severity": "info",
            "evidence_refs": ["hybrid_analysis.items.scope_validation"],
        })
    if urlscan_verdict:
        key_evidence.append(
            f"URLScan verdict: {urlscan_verdict}"
            + (f" (score {urlscan_score})" if urlscan_score else "")
            + (f", tags: {', '.join(str(t) for t in (urlscan.get('tags') or [])[:4])}" if urlscan.get("tags") else "")
        )
    if newly_registered:
        key_evidence.append(f"Newly registered domain — {domain_age} day(s) old")
    elif recently_registered:
        key_evidence.append(f"Recently registered domain — {domain_age} day(s) old")
    if not reputation_available:
        key_evidence.append("No reputation source returned data for this observable")
        data_needed.append(
            "Reputation lookup unavailable (VirusTotal, URLScan and threat feeds all returned "
            "nothing or failed) — re-run the collectors before treating this as clean"
        )

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
    if weak_score >= 3 and classification != "benign":
        findings.append({
            "id": "weak_signal_cluster",
            "title": "Suspicious weak-signal cluster",
            "description": "Multiple medium-confidence signals combine into suspicious context: " + "; ".join(weak_evidence[:6]),
            "severity": "medium" if weak_score >= 4 else "low",
            "evidence_refs": ["url_lexical_ml", "signals", "infrastructure_pivot", "email_security"],
        })
    elif weak_score >= 3 and observable_clean:
        findings.append({
            "id": "weak_signals_overridden_by_clean_controls",
            "title": "Weak signals did not outweigh direct clean evidence",
            "description": (
                "Lexical, shared-hosting, or contextual HTTP observations were retained for review but did not "
                "raise the verdict because VirusTotal and AnyRun were clean, the domain is established, and no "
                "high-confidence phishing behavior or login collection was observed."
            ),
            "severity": "info",
            "evidence_refs": ["url_lexical_ml", "hybrid_analysis.items", "vt", "whois.domain_age_days"],
        })
    age_days = (evidence_data.get("whois") or {}).get("domain_age_days")
    if classification == "benign" and isinstance(age_days, int) and age_days >= 365:
        key_evidence.append(f"Established domain: approximately {age_days:,} days old")
        findings.append({
            "id": "established_domain_history",
            "title": "Established domain with long registration history",
            "description": (
                f"WHOIS reports the domain is approximately {age_days:,} days old, which is inconsistent "
                "with a newly registered disposable phishing domain."
            ),
            "severity": "info",
            "evidence_refs": ["whois.domain_age_days"],
        })

    return classification, confidence, risk_score, action, key_evidence, findings, data_needed


def _excluded_anyrun_task_count(hybrid: dict[str, Any]) -> int:
    total = 0
    if not isinstance(hybrid, dict):
        return total
    entries = hybrid.get("items") if isinstance(hybrid.get("items"), list) else [hybrid]
    for item in entries:
        if not isinstance(item, dict):
            continue
        scope = item.get("scope_validation") or (item.get("raw_summary") or {}).get("scope_validation") or {}
        if isinstance(scope, dict):
            try:
                total += max(0, int(scope.get("excluded_tasks") or 0))
            except (TypeError, ValueError):
                continue
    return total


def _best_sensitive_form_detection(evidence_data: dict[str, Any]) -> dict[str, Any]:
    js_detection = (evidence_data.get("js_analysis") or {}).get("sensitive_form_detection") or {}
    if isinstance(js_detection, dict) and js_detection.get("detected"):
        return {
            **js_detection,
            "_evidence_ref": "js_analysis.sensitive_form_detection",
        }

    hybrid = evidence_data.get("hybrid_analysis") or {}
    for index, item in enumerate(hybrid.get("items") or []):
        if not isinstance(item, dict):
            continue
        detection = (item.get("raw_summary") or {}).get("sensitive_form_detection") or {}
        if isinstance(detection, dict) and detection.get("detected"):
            return {
                **detection,
                "_evidence_ref": (
                    f"hybrid_analysis.items.{index}.raw_summary.sensitive_form_detection"
                ),
            }
    return {}


def _anyrun_heuristic_observations(hybrid: dict[str, Any]) -> list[str]:
    observations: list[str] = []

    def add(value: Any) -> None:
        text = str(value or "").strip()
        key = text.casefold()
        if key == "javascript obfuscation (parseint)":
            observations[:] = [
                existing for existing in observations
                if existing.casefold() != "javascript obfuscation"
            ]
        elif key == "javascript obfuscation" and any(
            existing.casefold() == "javascript obfuscation (parseint)"
            for existing in observations
        ):
            return
        if not text or any(key == existing.casefold() for existing in observations):
            return
        observations.append(text)

    for item in hybrid.get("items") or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw_summary") or {}
        tags = [
            *(_as_list(item.get("tags"))),
            *(_as_list(raw.get("tags")) if isinstance(raw, dict) else []),
        ]
        if any(str(tag).strip().casefold() in {"obfuscated-js", "obfuscated js"} for tag in tags):
            add("JavaScript obfuscation")
        details = (raw.get("behavior_details") or {}) if isinstance(raw, dict) else {}
        for event in details.get("network_threats") or []:
            if not isinstance(event, dict):
                continue
            message = str(event.get("msg") or event.get("signature") or "").strip()
            lower = message.casefold()
            if "javascript obfuscation" in lower and "parseint" in lower:
                add("JavaScript Obfuscation (ParseInt)")
    return observations


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

    age_days = (evidence_data.get("whois") or {}).get("domain_age_days")
    if isinstance(age_days, (int, float)) and NEWLY_REGISTERED_DAYS < int(age_days) <= YOUNG_DOMAIN_DAYS:
        score += 1
        reasons.append(f"Recently registered domain ({int(age_days)} days old)")

    email = evidence_data.get("email_security") or {}
    high_spoofability = (
        isinstance(email, dict) and str(email.get("spoofability_score") or "").lower() == "high"
    )

    infra = evidence_data.get("infrastructure_pivot") or {}
    shared_hosting = False
    if isinstance(infra, dict):
        shared_hosting = bool(infra.get("shared_hosting_detected"))
        if _pivots_to_other_domains(infra, evidence_data):
            score += 1
            reasons.append("Registrant/registrar pivot links to other investigated domains")

    signals = evidence_data.get("signals") or []
    if isinstance(signals, list):
        signal_ids = {
            str(sig.get("id") or "")
            for sig in signals
            if isinstance(sig, dict)
        }
        if "sig_high_spoofability" in signal_ids:
            high_spoofability = True
        # These two used to come in through a second door: when the checks above
        # declined to score a self-pivot, the signal id scored it anyway under
        # another name. Route them through the same rules instead.
        if "sig_shared_hosting" in signal_ids:
            shared_hosting = True
        if (
            "sig_registrant_pivot" in signal_ids
            and _pivots_to_other_domains(infra if isinstance(infra, dict) else {}, evidence_data)
            and not any("pivot" in reason.lower() for reason in reasons)
        ):
            score += 1
            reasons.append("Registrant/registrar pivot links to other investigated domains")

    if contextual_http:
        score += 1
        reasons.append("Static HTTP brand/input observation present")

    # Corroborating-only observations. Both are true of large numbers of
    # perfectly legitimate sites — most of the web is on shared infrastructure,
    # and plenty of real organisations have never published SPF/DMARC. They
    # sharpen a suspicion that already exists; they must not create one.
    for present, label in (
        (high_spoofability, "High email spoofability"),
        (shared_hosting, "Shared hosting or crowded infrastructure observed"),
    ):
        if present and score >= 1:
            score += 1
            reasons.append(label)
        elif present:
            reasons.append(f"{label} (not scored on its own)")

    return score, reasons


def _pivots_to_other_domains(infra: dict[str, Any], evidence_data: dict[str, Any]) -> bool:
    """
    Whether a registrant/registrar pivot reaches domains other than this one.

    A pivot listing only the investigated domain is the domain looking at itself;
    counting it made every domain corroborate its own suspicion.
    """
    pivots = infra.get("registrant_pivots")
    if not isinstance(pivots, list) or not pivots:
        return False

    investigated = {
        str(evidence_data.get(key) or "").strip().lower()
        for key in ("domain", "target_domain", "observable")
    } - {""}

    for pivot in pivots:
        if not isinstance(pivot, dict):
            continue
        others = {
            str(domain).strip().lower()
            for domain in (pivot.get("domains") or [])
            if str(domain).strip()
        } - investigated
        if others:
            return True
    return False


def _best_anyrun_verdict(hybrid: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]]:
    """
    The verdict this platform acts on, which is not always the one ANY.RUN gave.

    A threat label outranks a clean verdict. ANY.RUN routinely returns
    `verdict: clean` — "No threats detected" — on a task it has simultaneously
    tagged `phishing`, because the automated run never triggered the behaviour
    the label describes. Trusting the verdict there would let a known phishing
    kit through on the strength of a sandbox that did not click anything.

    The cost of that rule is a report that reads as if ANY.RUN called something
    malicious when it did not, so `context` carries the reason: `escalated_by`
    names the labels that overrode the verdict and `provider_verdict` keeps what
    the provider actually said. Anything describing this decision to an analyst
    must use both — see `_anyrun_verdict_sentence`.
    """
    verdict = str(hybrid.get("verdict") or "").strip().lower()
    names: list[str] = _anyrun_labels_from_item(hybrid)
    context: dict[str, Any] = _anyrun_context_from_item(hybrid)
    malicious_labels = _anyrun_malicious_labels(names)
    for item in hybrid.get("items") or []:
        if not isinstance(item, dict):
            continue
        scope = item.get("scope_validation") or (item.get("raw_summary") or {}).get("scope_validation") or {}
        if isinstance(scope, dict) and scope.get("scope_match") is False:
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
        elif item_verdict == "clean" and verdict not in {"malicious", "suspicious"}:
            verdict = "clean"
            names = names or item_names
            if (
                not context
                or (
                    item_context.get("sandbox")
                    and not context.get("sandbox")
                )
            ):
                context = item_context
    provider_verdict = verdict if verdict in {"malicious", "suspicious", "clean"} else ""
    context = {**context, "provider_verdict": provider_verdict}
    if malicious_labels:
        # Record that the label, not the verdict, is what escalated this — so the
        # finding can say so instead of claiming ANY.RUN returned MALICIOUS.
        if provider_verdict != "malicious":
            context = {**context, "escalated_by": list(malicious_labels)}
        return "malicious", malicious_labels, context
    return provider_verdict, names, context


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
        if text.startswith("rendered data-entry form"):
            return 0
        if text.startswith("anyrun") and "incomplete form interaction" in text:
            return 1
        if text.startswith("anyrun sandbox"):
            return 2
        if text.startswith("anyrun"):
            return 3
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
            if key in {"url", "domain", "file", "hash"}:
                return
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


def _anyrun_verdict_sentence(verdict: str, source_label: str, context: dict[str, Any]) -> str:
    """
    Say what ANY.RUN reported, and separately what this platform concluded.

    The old wording asserted "AnyRun sandbox returned a MALICIOUS verdict" from
    the *resolved* verdict, so a clean run carrying a `phishing` label was
    reported as a malicious provider verdict — a claim the provider never made,
    contradicted by the sandbox table on the same screen.
    """
    escalated_by = [str(label) for label in (context.get("escalated_by") or []) if str(label).strip()]
    provider = str(context.get("provider_verdict") or "").strip().upper()
    if not escalated_by:
        return f"AnyRun {source_label} returned a {verdict.upper()} verdict for the investigated indicator."

    labels = ", ".join(escalated_by[:4])
    provider_clause = (
        f"returned {provider} (\"no threats detected\")"
        if provider == "CLEAN"
        else f"returned {provider}" if provider else "returned no verdict"
    )
    return (
        f"AnyRun {source_label} {provider_clause} but labelled the sample {labels}. "
        "The label is treated as authoritative: an automated run that never interacts with the page "
        "routinely fails to trigger the behaviour its own label describes, so this platform escalates "
        "on the label and records the provider verdict as incomplete rather than clean."
    )


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
