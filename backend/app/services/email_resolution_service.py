"""
Builds structured SOC email investigation resolution output.

All statements must come from provided evidence. Missing fields are explicitly
rendered as: "Not present in the provided evidence."
"""

from __future__ import annotations

from typing import Any

NOT_PRESENT = "Not present in the provided evidence."


def build_email_resolution(
    extracted: dict[str, Any],
    outcomes: list[dict[str, Any]],
    ml_phishing_score: float | None = None,
) -> dict[str, Any]:
    by_type: dict[str, list[dict[str, Any]]] = {}
    for item in outcomes:
        by_type.setdefault(item.get("indicator_type") or "unknown", []).append(item)

    sender_domain = _s(extracted.get("sender_domain")) or NOT_PRESENT
    sender_ip = _s(extracted.get("sender_ip")) or NOT_PRESENT
    email_subject = _s(extracted.get("email_subject")) or NOT_PRESENT

    domain_outcome = _first(by_type.get("sender_domain", []))
    ip_outcome = _first(by_type.get("sender_ip", []))
    url_outcomes = by_type.get("url", [])
    hash_outcomes = by_type.get("attachment_sha256", [])

    domain_section = _build_sender_domain_section(sender_domain, domain_outcome)
    ip_section = _build_ip_section(sender_ip, ip_outcome)
    attachment_section = _build_attachment_section(extracted, hash_outcomes)
    url_section = _build_url_section(extracted, url_outcomes)
    auth_section = _build_auth_section(extracted)
    ml_section = _build_ml_section(ml_phishing_score, auth_section["spoofing_risk_assessment"])

    final_classification, confidence, justification = _final_conclusion(
        domain_section=domain_section,
        ip_section=ip_section,
        attachment_section=attachment_section,
        url_section=url_section,
        auth_section=auth_section,
    )

    lines = [
        f'Email subject: "{email_subject}"',
        "",
        "Sender Email Domain Analysis:",
        f"The sender domain {sender_domain} is {domain_section['domain_state']}.",
        f"Domain description: {domain_section['domain_description']}.",
        f"Domain reputation summary: {domain_section['domain_reputation_summary']}.",
        "",
        "Sender IP Analysis:",
        f"The sender IP address {sender_ip} (ISP: {ip_section['isp']}, Usage Type: {ip_section['usage_type']}) was analyzed.",
        f"Reputation findings: {ip_section['reputation_findings']}.",
        f"Hosting environment assessment: {ip_section['hosting_environment_assessment']}.",
        "",
        "Attachment Analysis:",
        f"Attachments present: {attachment_section['attachments_present']}.",
        f"If present: {attachment_section['hash_values']}.",
        f"VirusTotal detection summary: {attachment_section['vt_detection_summary']}.",
        f"Final attachment assessment: {attachment_section['final_attachment_assessment']}.",
        "",
        "URL Analysis:",
        f"Total URLs identified: {url_section['total_urls_identified']}.",
        f"Domains involved: {url_section['domains_involved']}.",
        f"Redirect behavior: {url_section['redirect_behavior']}.",
        f"Reputation findings: {url_section['reputation_findings']}.",
        f"Final URL assessment: {url_section['final_url_assessment']}.",
        "",
        "Email Authentication & Security:",
        f"SPF result: {auth_section['spf_result']}.",
        f"DKIM result: {auth_section['dkim_result']}.",
        f"DMARC result: {auth_section['dmarc_result']}.",
        f"Spoofing risk assessment: {auth_section['spoofing_risk_assessment']}.",
        "",
        "Machine Learning Signal (if provided):",
        f"Phishing probability: {ml_section['phishing_probability']}.",
        f"Contextual interpretation: {ml_section['contextual_interpretation']}.",
        "",
        "Conclusion:",
        f"Final classification: {final_classification}.",
        justification,
        "",
        f"Confidence Level: {confidence}",
    ]

    return {
        "email_subject": email_subject,
        "sections": {
            "sender_domain_analysis": domain_section,
            "sender_ip_analysis": ip_section,
            "attachment_analysis": attachment_section,
            "url_analysis": url_section,
            "email_authentication_security": auth_section,
            "machine_learning_signal": ml_section,
        },
        "conclusion": {
            "classification": final_classification,
            "confidence": confidence,
            "justification": justification,
        },
        "formatted_resolution": "\n".join(lines),
    }


def _build_sender_domain_section(sender_domain: str, outcome: dict[str, Any] | None) -> dict[str, Any]:
    if sender_domain == NOT_PRESENT:
        return {
            "domain_state": "unknown",
            "domain_description": NOT_PRESENT,
            "domain_reputation_summary": NOT_PRESENT,
            "_classification_rank": 0,
        }

    report = (outcome or {}).get("report") or {}
    evidence = (outcome or {}).get("evidence") or {}

    domain_state = _s(report.get("classification")) or "unknown"
    rank = _rank_classification(domain_state)

    whois = evidence.get("whois") or {}
    vt = evidence.get("vt") or {}
    hosting = evidence.get("hosting") or {}

    registrar = _s(whois.get("registrar"))
    age = whois.get("domain_age_days")
    asn_org = _s(hosting.get("asn_org"))
    desc_parts: list[str] = []
    if registrar:
        desc_parts.append(f"Registrar: {registrar}")
    if isinstance(age, int):
        desc_parts.append(f"Domain age days: {age}")
    if asn_org:
        desc_parts.append(f"Hosting ASN org: {asn_org}")
    description = "; ".join(desc_parts) if desc_parts else NOT_PRESENT

    rep_parts: list[str] = []
    if vt:
        rep_parts.append(
            f"VirusTotal detections: malicious={vt.get('malicious_count', 0)}, "
            f"suspicious={vt.get('suspicious_count', 0)}, total_vendors={vt.get('total_vendors', 0)}"
        )
    if isinstance(age, int):
        rep_parts.append(f"Domain age: {age} days")
    if asn_org:
        rep_parts.append(f"Hosting context: {asn_org}")
    reputation = "; ".join(rep_parts) if rep_parts else NOT_PRESENT

    return {
        "domain_state": domain_state,
        "domain_description": description,
        "domain_reputation_summary": reputation,
        "_classification_rank": rank,
    }


def _build_ip_section(sender_ip: str, outcome: dict[str, Any] | None) -> dict[str, Any]:
    evidence = (outcome or {}).get("evidence") or {}
    report = (outcome or {}).get("report") or {}

    threat = evidence.get("threat_feeds") or {}
    abuse = threat.get("abuseipdb") or {}
    vt = evidence.get("vt") or {}
    hosting = evidence.get("hosting") or {}

    isp = _s(abuse.get("isp")) or _s(hosting.get("asn_org")) or NOT_PRESENT
    usage_type = _s(abuse.get("usage_type")) or NOT_PRESENT

    rep_parts: list[str] = []
    if vt:
        rep_parts.append(
            f"VT malicious={vt.get('malicious_count', 0)}, suspicious={vt.get('suspicious_count', 0)}"
        )
    if abuse:
        rep_parts.append(
            f"AbuseIPDB confidence={abuse.get('abuse_confidence_score', 0)}, "
            f"reports={abuse.get('total_reports', 0)}"
        )
    if not rep_parts and report.get("primary_reasoning"):
        rep_parts.append(_s(report.get("primary_reasoning")) or "")
    reputation_findings = "; ".join([p for p in rep_parts if p]) if rep_parts else NOT_PRESENT

    env = "unknown"
    if hosting.get("is_cdn"):
        env = "CDN"
    elif hosting.get("is_cloud"):
        env = "cloud"
    elif hosting.get("is_hosting"):
        env = "shared hosting"

    return {
        "isp": isp,
        "usage_type": usage_type,
        "reputation_findings": reputation_findings,
        "hosting_environment_assessment": env if sender_ip != NOT_PRESENT else NOT_PRESENT,
        "_classification_rank": _rank_classification(_s(report.get("classification")) or "unknown"),
    }


def _build_attachment_section(extracted: dict[str, Any], hash_outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    attachments = extracted.get("attachments") or []
    present = "yes" if attachments else "no"
    hash_values = ", ".join([a.get("sha256", "") for a in attachments if isinstance(a, dict) and a.get("sha256")])
    hash_values = hash_values or NOT_PRESENT

    vt_hits: list[str] = []
    max_rank = 0
    for out in hash_outcomes:
        report = out.get("report") or {}
        ev = out.get("evidence") or {}
        vt = ev.get("vt") or {}
        v = vt.get("malicious_count")
        total = vt.get("total_vendors")
        if isinstance(v, int):
            vt_hits.append(f"{out.get('value')}: {v}/{total or 0}")
        max_rank = max(max_rank, _rank_classification(_s(report.get("classification")) or "unknown"))

    if not attachments:
        assessment = "inconclusive"
    elif max_rank >= 3:
        assessment = "malicious"
    elif max_rank >= 2:
        assessment = "suspicious"
    elif hash_outcomes:
        assessment = "safe"
    else:
        assessment = "inconclusive"

    return {
        "attachments_present": present,
        "hash_values": hash_values,
        "vt_detection_summary": "; ".join(vt_hits) if vt_hits else NOT_PRESENT,
        "final_attachment_assessment": assessment,
        "_classification_rank": max_rank,
    }


def _build_url_section(extracted: dict[str, Any], url_outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    urls = extracted.get("urls") or []
    domains = extracted.get("url_domains") or []

    redirects: list[str] = []
    rep_bits: list[str] = []
    max_rank = 0
    for out in url_outcomes:
        report = out.get("report") or {}
        ev = out.get("evidence") or {}
        http = ev.get("http") or {}
        vt = ev.get("vt") or {}
        urlscan = ev.get("urlscan") or {}
        chain = http.get("redirect_chain") or []
        if chain:
            redirects.append(f"{out.get('value')}: {len(chain)} redirect hops")
        if vt:
            rep_bits.append(
                f"{out.get('value')}: VT malicious={vt.get('malicious_count', 0)}, suspicious={vt.get('suspicious_count', 0)}"
            )
        if urlscan.get("verdict"):
            rep_bits.append(f"{out.get('value')}: URLScan verdict={urlscan.get('verdict')}")
        max_rank = max(max_rank, _rank_classification(_s(report.get("classification")) or "unknown"))

    if max_rank >= 3:
        final = "malicious"
    elif max_rank >= 2:
        final = "suspicious"
    elif urls:
        final = "safe"
    else:
        final = "safe"

    return {
        "total_urls_identified": str(len(urls)),
        "domains_involved": ", ".join(domains) if domains else NOT_PRESENT,
        "redirect_behavior": "; ".join(redirects) if redirects else NOT_PRESENT,
        "reputation_findings": "; ".join(rep_bits) if rep_bits else NOT_PRESENT,
        "final_url_assessment": final,
        "_classification_rank": max_rank,
    }


def _build_auth_section(extracted: dict[str, Any]) -> dict[str, Any]:
    auth = extracted.get("authentication") or {}
    spf = (_s(auth.get("spf")) or "none").lower()
    dkim = (_s(auth.get("dkim")) or "none").lower()
    dmarc = (_s(auth.get("dmarc")) or "none").lower()

    fails = sum(1 for v in (spf, dkim, dmarc) if v in {"fail", "none", "softfail", "permerror", "temperror"})
    if fails >= 2:
        spoof = "high"
    elif fails == 1:
        spoof = "medium"
    else:
        spoof = "low"

    return {
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "spoofing_risk_assessment": spoof,
    }


def _build_ml_section(score: float | None, spoofing_risk: str) -> dict[str, str]:
    if score is None:
        return {
            "phishing_probability": NOT_PRESENT,
            "contextual_interpretation": NOT_PRESENT,
        }

    if score >= 0.85:
        trend = "high phishing probability signal"
    elif score >= 0.6:
        trend = "moderate phishing probability signal"
    else:
        trend = "low phishing probability signal"

    return {
        "phishing_probability": f"{score:.3f}",
        "contextual_interpretation": (
            f"ML indicates {trend}. Authentication spoofing risk is {spoofing_risk}; "
            "this must be interpreted together with infrastructure and reputation findings."
        ),
    }


def _final_conclusion(
    domain_section: dict[str, Any],
    ip_section: dict[str, Any],
    attachment_section: dict[str, Any],
    url_section: dict[str, Any],
    auth_section: dict[str, Any],
) -> tuple[str, str, str]:
    max_rank = max(
        int(domain_section.get("_classification_rank", 0)),
        int(ip_section.get("_classification_rank", 0)),
        int(attachment_section.get("_classification_rank", 0)),
        int(url_section.get("_classification_rank", 0)),
    )

    spoof = auth_section.get("spoofing_risk_assessment")

    # Only classify malicious when strong infrastructure/reputation signals are present.
    if max_rank >= 3:
        classification = "malicious"
    elif max_rank >= 2 or spoof == "high":
        classification = "suspicious"
    elif max_rank == 1:
        classification = "inconclusive"
    else:
        classification = "benign"

    if classification == "malicious":
        confidence = "high" if spoof in {"medium", "high"} else "medium"
    elif classification == "suspicious":
        confidence = "medium"
    elif classification == "benign":
        confidence = "medium"
    else:
        confidence = "low"

    justification = (
        "Classification is based on available sender domain/IP reputation, URL and attachment investigation outcomes, "
        "and email authentication signals. "
        "No statement uses data outside the provided evidence."
    )
    return classification, confidence, justification


def _first(items: list[Any]) -> Any:
    return items[0] if items else None


def _s(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _rank_classification(value: str) -> int:
    v = (value or "").lower()
    return {
        "unknown": 0,
        "benign": 1,
        "inconclusive": 1,
        "suspicious": 2,
        "malicious": 3,
    }.get(v, 0)

