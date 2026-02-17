"""
Post-collection signal generation and data gap detection.

Signals = investigative clues derived from evidence. NOT conclusions.
Data gaps = what's missing and why it matters.

These are computed AFTER all collectors finish and BEFORE the analyst runs.
"""

from __future__ import annotations

from app.models.schemas import DataGap, Signal


def generate_signals(evidence: dict) -> list[Signal]:
    """
    Generate investigative signals from collected evidence.

    Each signal is a clue that the analyst will validate
    against technical plausibility. Signals do not determine
    classification — they are inputs to the reasoning process.
    """
    signals: list[Signal] = []

    # ── Domain age ──
    whois = evidence.get("whois", {})
    age_days = whois.get("domain_age_days")
    if age_days is not None:
        if age_days < 7:
            signals.append(Signal(
                id="sig_very_young_domain",
                category="infrastructure_age",
                description=f"Domain is {age_days} days old — registered this week",
                severity="high",
                evidence_refs=["whois.domain_age_days"],
            ))
        elif age_days < 30:
            signals.append(Signal(
                id="sig_young_domain",
                category="infrastructure_age",
                description=f"Domain is {age_days} days old — recently registered",
                severity="medium",
                evidence_refs=["whois.domain_age_days"],
            ))

    # ── WHOIS privacy ──
    if whois.get("privacy_protected"):
        signals.append(Signal(
            id="sig_whois_privacy",
            category="registration",
            description="WHOIS registration uses privacy protection",
            severity="info",
            evidence_refs=["whois.privacy_protected"],
        ))

    # ── TLS signals ──
    tls = evidence.get("tls", {})

    if tls.get("is_self_signed"):
        signals.append(Signal(
            id="sig_self_signed",
            category="certificate",
            description="TLS certificate is self-signed",
            severity="medium",
            evidence_refs=["tls.is_self_signed"],
        ))

    days_remaining = tls.get("valid_days_remaining")
    if days_remaining is not None and days_remaining < 7:
        signals.append(Signal(
            id="sig_cert_expiring",
            category="certificate",
            description=f"TLS certificate expires in {days_remaining} days",
            severity="medium",
            evidence_refs=["tls.valid_days_remaining"],
        ))

    sans = tls.get("sans", [])
    if len(sans) > 20:
        signals.append(Signal(
            id="sig_many_sans",
            category="certificate",
            description=f"Certificate has {len(sans)} SANs — shared hosting or CDN",
            severity="info",
            evidence_refs=["tls.sans"],
        ))

    issuer_org = (tls.get("issuer_org") or "").lower()
    if any(ca in issuer_org for ca in ["let's encrypt", "zerossl", "buypass"]):
        signals.append(Signal(
            id="sig_free_cert",
            category="certificate",
            description=f"Uses free/automated CA: {tls.get('issuer_org')}",
            severity="info",
            evidence_refs=["tls.issuer_org"],
        ))

    # ── HTTP signals ──
    http = evidence.get("http", {})

    if http.get("has_login_form"):
        signals.append(Signal(
            id="sig_login_form",
            category="content",
            description="Page contains a login/password form",
            severity="info",
            evidence_refs=["http.has_login_form"],
        ))

    chain = http.get("redirect_chain", [])
    if len(chain) > 3:
        signals.append(Signal(
            id="sig_long_redirect",
            category="behavior",
            description=f"HTTP request followed {len(chain)} redirects",
            severity="medium",
            evidence_refs=["http.redirect_chain"],
        ))

    # Cross-domain redirect
    if chain and http.get("final_url"):
        first_domain = _extract_domain(chain[0].get("url", ""))
        final_domain = _extract_domain(http["final_url"])
        if first_domain and final_domain and first_domain != final_domain:
            signals.append(Signal(
                id="sig_cross_domain_redirect",
                category="behavior",
                description=f"Redirects from {first_domain} to {final_domain}",
                severity="medium",
                evidence_refs=["http.redirect_chain", "http.final_url"],
            ))

    # Missing security headers
    sec_headers = http.get("security_headers", {})
    if http.get("reachable"):
        if not sec_headers.get("Strict-Transport-Security"):
            signals.append(Signal(
                id="sig_no_hsts",
                category="security_posture",
                description="No HSTS header present",
                severity="low",
                evidence_refs=["http.security_headers"],
            ))
        if not sec_headers.get("Content-Security-Policy"):
            signals.append(Signal(
                id="sig_no_csp",
                category="security_posture",
                description="No Content-Security-Policy header",
                severity="low",
                evidence_refs=["http.security_headers"],
            ))

    # ── DNS signals ──
    dns_data = evidence.get("dns", {})
    if not dns_data.get("dmarc"):
        signals.append(Signal(
            id="sig_no_dmarc",
            category="email_security",
            description="No DMARC record — domain can be spoofed in email",
            severity="low",
            evidence_refs=["dns.dmarc"],
        ))

    if not dns_data.get("mx"):
        signals.append(Signal(
            id="sig_no_mx",
            category="email_security",
            description="No MX records — domain does not receive email",
            severity="info",
            evidence_refs=["dns.mx"],
        ))

    # ── Hosting signals ──
    hosting = evidence.get("hosting", {})
    if hosting.get("is_hosting") and not hosting.get("is_cdn") and not hosting.get("is_cloud"):
        signals.append(Signal(
            id="sig_dedicated_hosting",
            category="infrastructure",
            description=f"Hosted on dedicated provider: {hosting.get('asn_org', 'unknown')}",
            severity="info",
            evidence_refs=["hosting.asn_org", "hosting.is_hosting"],
        ))

    # ── Intel signals ──
    intel = evidence.get("intel", {})
    blocklist_hits = intel.get("blocklist_hits", [])
    if blocklist_hits:
        sources = list(set(h.get("source", "unknown") for h in blocklist_hits))
        signals.append(Signal(
            id="sig_blocklisted",
            category="reputation",
            description=f"Domain listed in {len(blocklist_hits)} blocklist(s): {', '.join(sources)}",
            severity="high",
            evidence_refs=["intel.blocklist_hits"],
        ))

    related_subs = intel.get("related_subdomains", [])
    if len(related_subs) > 50:
        signals.append(Signal(
            id="sig_many_subdomains",
            category="infrastructure",
            description=f"crt.sh shows {len(related_subs)} subdomains — large infrastructure",
            severity="info",
            evidence_refs=["intel.related_subdomains"],
        ))

    # ── VirusTotal signals ──
    vt = evidence.get("vt", {})
    vt_malicious = vt.get("malicious_count", 0)
    vt_suspicious = vt.get("suspicious_count", 0)
    vt_total = vt.get("total_vendors", 0)

    if vt_malicious > 0:
        flagged_by = vt.get("flagged_malicious_by", [])
        signals.append(Signal(
            id="sig_vt_malicious",
            category="reputation",
            description=(
                f"VirusTotal: {vt_malicious}/{vt_total} vendors flag as malicious"
                f" ({', '.join(flagged_by[:5])}{'...' if len(flagged_by) > 5 else ''})"
            ),
            severity="high" if vt_malicious >= 3 else "medium",
            evidence_refs=["vt.malicious_count", "vt.flagged_malicious_by"],
        ))

    if vt_suspicious > 0 and vt_malicious == 0:
        signals.append(Signal(
            id="sig_vt_suspicious",
            category="reputation",
            description=f"VirusTotal: {vt_suspicious}/{vt_total} vendors flag as suspicious",
            severity="medium",
            evidence_refs=["vt.suspicious_count", "vt.flagged_suspicious_by"],
        ))

    if vt.get("reputation_score", 0) < -5:
        signals.append(Signal(
            id="sig_vt_bad_reputation",
            category="reputation",
            description=f"VirusTotal community reputation score: {vt.get('reputation_score')}",
            severity="medium",
            evidence_refs=["vt.reputation_score"],
        ))

    # ── Domain similarity signals ──
    similarity = evidence.get("domain_similarity")
    if similarity:
        signals.extend(generate_similarity_signals(similarity))

    # ── Visual comparison signals ──
    visual = evidence.get("visual_comparison")
    if visual:
        signals.extend(generate_visual_comparison_signals(visual))

    # ── Combined visual + domain impersonation ──
    if similarity and visual:
        is_typosquat = similarity.get("is_potential_typosquat", False)
        is_visual_clone = visual.get("is_visual_clone", False)
        if is_typosquat and is_visual_clone:
            client = similarity.get("client_domain", "unknown")
            signals.append(Signal(
                id="sig_combined_visual_domain_impersonation",
                category="impersonation",
                description=(
                    f"Domain is BOTH a typosquat AND a visual clone of client '{client}' — "
                    f"strong phishing/impersonation evidence"
                ),
                severity="critical",
                evidence_refs=[
                    "domain_similarity.is_potential_typosquat",
                    "visual_comparison.is_visual_clone",
                ],
            ))

    return signals


def generate_similarity_signals(similarity: dict) -> list[Signal]:
    """Generate signals from domain similarity analysis against a client domain."""
    signals: list[Signal] = []

    score = similarity.get("overall_similarity_score", 0)
    client = similarity.get("client_domain", "unknown")
    techniques = similarity.get("typosquatting_techniques", [])
    homoglyphs = similarity.get("homoglyph_matches", [])

    if score >= 80:
        signals.append(Signal(
            id="sig_high_domain_similarity",
            category="domain_similarity",
            description=f"High similarity score ({score}/100) with client domain '{client}'",
            severity="high",
            evidence_refs=["domain_similarity.overall_similarity_score"],
        ))
    elif score >= 50:
        signals.append(Signal(
            id="sig_moderate_domain_similarity",
            category="domain_similarity",
            description=f"Moderate similarity score ({score}/100) with client domain '{client}'",
            severity="medium",
            evidence_refs=["domain_similarity.overall_similarity_score"],
        ))

    if techniques:
        tech_names = [t.get("technique", "unknown") for t in techniques]
        signals.append(Signal(
            id="sig_typosquatting_detected",
            category="domain_similarity",
            description=(
                f"Typosquatting techniques detected vs client '{client}': "
                f"{', '.join(t.replace('_', ' ') for t in tech_names)}"
            ),
            severity="high",
            evidence_refs=["domain_similarity.typosquatting_techniques"],
        ))

    if homoglyphs:
        signals.append(Signal(
            id="sig_homoglyph_detected",
            category="domain_similarity",
            description=(
                f"{len(homoglyphs)} homoglyph substitution(s) detected vs client '{client}' — "
                f"visually confusable characters"
            ),
            severity="high",
            evidence_refs=["domain_similarity.homoglyph_matches"],
        ))

    if similarity.get("is_potential_typosquat") and similarity.get("is_visual_lookalike"):
        signals.append(Signal(
            id="sig_combined_impersonation",
            category="domain_similarity",
            description=(
                f"Domain is both a typosquat AND visual lookalike of client '{client}' — "
                f"strong impersonation indicators"
            ),
            severity="critical",
            evidence_refs=[
                "domain_similarity.is_potential_typosquat",
                "domain_similarity.is_visual_lookalike",
            ],
        ))

    return signals


def generate_visual_comparison_signals(visual: dict) -> list[Signal]:
    """Generate signals from screenshot-based visual comparison."""
    signals: list[Signal] = []

    overall = visual.get("overall_visual_similarity")
    if overall is None:
        return signals

    client = visual.get("client_domain", "unknown")

    if visual.get("is_visual_clone"):
        signals.append(Signal(
            id="sig_visual_clone",
            category="visual_comparison",
            description=(
                f"Website is a visual clone of client '{client}' — "
                f"{overall:.0%} screenshot similarity"
            ),
            severity="critical",
            evidence_refs=[
                "visual_comparison.overall_visual_similarity",
                "visual_comparison.is_visual_clone",
            ],
        ))
    elif visual.get("is_partial_clone"):
        signals.append(Signal(
            id="sig_partial_visual_clone",
            category="visual_comparison",
            description=(
                f"Website partially resembles client '{client}' — "
                f"{overall:.0%} screenshot similarity"
            ),
            severity="high",
            evidence_refs=[
                "visual_comparison.overall_visual_similarity",
                "visual_comparison.is_partial_clone",
            ],
        ))

    return signals


def detect_data_gaps(evidence: dict) -> list[DataGap]:
    """
    Identify what couldn't be collected and the impact on analysis.
    """
    gaps: list[DataGap] = []

    # ── Check each collector's meta status ──
    collector_impacts = {
        "dns": "Cannot assess DNS configuration or email security posture",
        "http": "Cannot assess web content, login forms, or redirect behavior",
        "tls": "Cannot assess certificate validity or issuer",
        "whois": "Cannot assess domain age, registrar, or registration privacy",
        "asn": "Cannot assess hosting provider, country, or infrastructure type",
    }

    for collector_name, impact in collector_impacts.items():
        col = evidence.get(collector_name, {})
        meta = col.get("meta", {})
        if meta.get("status") == "failed":
            gaps.append(DataGap(
                id=f"gap_{collector_name}_failed",
                description=f"{collector_name.upper()} collection failed: {meta.get('error', 'unknown')}",
                collector=collector_name,
                reason=meta.get("error", "unknown"),
                impact=impact,
            ))

    # ── Specific data gaps ──
    whois = evidence.get("whois", {})
    if whois.get("meta", {}).get("status") == "completed" and not whois.get("created_date"):
        gaps.append(DataGap(
            id="gap_whois_age",
            description="Domain creation date unavailable despite successful WHOIS query",
            collector="whois",
            reason="WHOIS data redacted or registrar does not expose dates",
            impact="Cannot assess infrastructure age — a key plausibility indicator",
        ))

    http = evidence.get("http", {})
    if http.get("meta", {}).get("status") == "completed" and not http.get("reachable"):
        gaps.append(DataGap(
            id="gap_http_unreachable",
            description="Domain not reachable over HTTP/HTTPS",
            collector="http",
            reason="Connection refused or timed out",
            impact="Cannot assess web content, login forms, or redirect behavior",
        ))

    return gaps


def _extract_domain(url: str) -> str | None:
    """Extract domain from a URL string."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None
