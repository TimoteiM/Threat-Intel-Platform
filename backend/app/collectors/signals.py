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

    # ── Content / phishing signals ──
    phishing_indicators = http.get("phishing_indicators", [])
    if phishing_indicators:
        signals.append(Signal(
            id="sig_phishing_indicators",
            category="content",
            description=(
                f"Phishing kit patterns detected: "
                f"{', '.join(phishing_indicators[:3])}"
                f"{'...' if len(phishing_indicators) > 3 else ''}"
            ),
            severity="high",
            evidence_refs=["http.phishing_indicators"],
        ))

    brand_indicators = http.get("brand_indicators", [])
    if brand_indicators:
        signals.append(Signal(
            id="sig_brand_impersonation",
            category="content",
            description=(
                f"Brand impersonation phrases detected: "
                f"{', '.join(brand_indicators[:3])}"
                f"{'...' if len(brand_indicators) > 3 else ''}"
            ),
            severity="medium",
            evidence_refs=["http.brand_indicators"],
        ))

    external_resources = http.get("external_resources", [])
    if len(external_resources) > 5:
        signals.append(Signal(
            id="sig_many_external_resources",
            category="content",
            description=f"Page loads resources from {len(external_resources)} external domains",
            severity="info",
            evidence_refs=["http.external_resources"],
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

    # ── Email security signals (from email_security post-processing) ──
    email_sec = evidence.get("email_security")
    if email_sec:
        dmarc_policy = email_sec.get("dmarc_policy")
        spf_all = email_sec.get("spf_all_qualifier")
        spoofability = email_sec.get("spoofability_score")

        if dmarc_policy == "none":
            signals.append(Signal(
                id="sig_dmarc_none",
                category="email_security",
                description="DMARC policy is 'none' — monitoring only, no enforcement",
                severity="medium",
                evidence_refs=["email_security.dmarc_policy"],
            ))

        if spf_all == "~all":
            signals.append(Signal(
                id="sig_spf_softfail",
                category="email_security",
                description="SPF uses softfail (~all) — spoofed mail may still be delivered",
                severity="medium",
                evidence_refs=["email_security.spf_all_qualifier"],
            ))

        if spf_all == "+all":
            signals.append(Signal(
                id="sig_spf_permissive",
                category="email_security",
                description="SPF uses +all — any server can send as this domain",
                severity="high",
                evidence_refs=["email_security.spf_all_qualifier"],
            ))

        if not email_sec.get("spf_record"):
            signals.append(Signal(
                id="sig_no_spf",
                category="email_security",
                description="No SPF record — no sender validation for this domain",
                severity="medium",
                evidence_refs=["email_security.spf_record"],
            ))

        if not email_sec.get("dkim_selectors_found"):
            signals.append(Signal(
                id="sig_no_dkim",
                category="email_security",
                description="No DKIM selectors found across 10 common selector names",
                severity="low",
                evidence_refs=["email_security.dkim_selectors_found"],
            ))

        # MX blocklist hits
        mx_records = email_sec.get("mx_records", [])
        all_bl_hits = []
        for mx in mx_records:
            all_bl_hits.extend(mx.get("blocklist_hits", []))
        if all_bl_hits:
            signals.append(Signal(
                id="sig_mx_blocklisted",
                category="email_security",
                description=f"MX server(s) found on blocklist: {', '.join(all_bl_hits[:3])}",
                severity="high",
                evidence_refs=["email_security.mx_records"],
            ))

        if spoofability == "high":
            signals.append(Signal(
                id="sig_high_spoofability",
                category="email_security",
                description=(
                    f"Domain is highly spoofable: "
                    f"{'; '.join(email_sec.get('spoofability_reasons', []))}"
                ),
                severity="high",
                evidence_refs=["email_security.spoofability_score"],
            ))

        sec_score = email_sec.get("email_security_score")
        if sec_score is not None and sec_score >= 85:
            signals.append(Signal(
                id="sig_email_security_strong",
                category="email_security",
                description=f"Strong email security posture (score: {sec_score}/100)",
                severity="info",
                evidence_refs=["email_security.email_security_score"],
            ))

    # ── Redirect analysis signals ──
    # NOTE: Most redirect/cloaking signals are INFORMATIONAL for legitimate sites.
    # Only flag as high/critical when combined with other malicious indicators.
    redirect = evidence.get("redirect_analysis")
    if redirect:
        if redirect.get("cloaking_detected"):
            cloaking_details = redirect.get("cloaking_details", [])
            signals.append(Signal(
                id="sig_cloaking_detected",
                category="evasion",
                description=(
                    f"UA-based cloaking detected (different URLs/status codes): "
                    f"{'; '.join(cloaking_details[:2])}"
                ),
                severity="medium",
                evidence_refs=["redirect_analysis.cloaking_detected", "redirect_analysis.cloaking_details"],
            ))

        # Bot blocking
        evasion = redirect.get("evasion_techniques", [])
        if any("bot blocking" in t.lower() for t in evasion):
            signals.append(Signal(
                id="sig_bot_blocking",
                category="evasion",
                description="Bot User-Agent gets blocked while browser succeeds — common on legitimate sites with bot protection",
                severity="low",
                evidence_refs=["redirect_analysis.evasion_techniques"],
            ))

        # Excessive redirects
        if redirect.get("max_chain_length", 0) > 5:
            signals.append(Signal(
                id="sig_excessive_redirects",
                category="behavior",
                description=f"Excessive redirect chain: {redirect['max_chain_length']} hops",
                severity="medium",
                evidence_refs=["redirect_analysis.max_chain_length"],
            ))

        # Tracker redirects
        intermediate = redirect.get("intermediate_domains", [])
        trackers = [d for d in intermediate if d.get("is_known_tracker")]
        if trackers:
            names = [d["domain"] for d in trackers[:3]]
            signals.append(Signal(
                id="sig_tracker_redirect",
                category="behavior",
                description=f"Redirect chain passes through known trackers: {', '.join(names)}",
                severity="info",
                evidence_refs=["redirect_analysis.intermediate_domains"],
            ))

        # Protocol downgrade
        if any("protocol downgrade" in t.lower() for t in evasion):
            signals.append(Signal(
                id="sig_protocol_downgrade",
                category="evasion",
                description="HTTPS to HTTP protocol downgrade detected in redirect chain",
                severity="medium",
                evidence_refs=["redirect_analysis.evasion_techniques"],
            ))

    # ── JavaScript analysis signals ──
    # NOTE: Fingerprinting, tracking pixels, and WebSocket connections are
    # extremely common on legitimate sites. Only credential harvesting with
    # external POSTs is a strong malicious indicator.
    js = evidence.get("js_analysis")
    if js:
        # Credential harvesting (external POST to auth endpoints) — this IS significant
        cred_posts = [p for p in js.get("post_endpoints", []) if p.get("is_credential_form")]
        if cred_posts:
            urls = [p["url"] for p in cred_posts[:3]]
            signals.append(Signal(
                id="sig_credential_harvesting",
                category="content",
                description=(
                    f"External POST to credential endpoint(s): "
                    f"{', '.join(urls)}"
                ),
                severity="high",
                evidence_refs=["js_analysis.post_endpoints"],
            ))

        # Tracking pixels
        pixels = js.get("tracking_pixels", [])
        if len(pixels) > 3:
            signals.append(Signal(
                id="sig_tracking_pixels",
                category="content",
                description=f"Multiple tracking pixels detected from {len(pixels)} domains — common on legitimate sites",
                severity="info",
                evidence_refs=["js_analysis.tracking_pixels"],
            ))

        # Fingerprinting
        fp_apis = js.get("fingerprinting_apis", [])
        if fp_apis:
            signals.append(Signal(
                id="sig_fingerprinting",
                category="content",
                description=f"Browser fingerprinting APIs detected: {', '.join(fp_apis[:5])} — common for analytics/fraud prevention",
                severity="info",
                evidence_refs=["js_analysis.fingerprinting_apis"],
            ))

        # WebSocket connections
        ws_connections = js.get("websocket_connections", [])
        if ws_connections:
            signals.append(Signal(
                id="sig_websocket_exfil",
                category="behavior",
                description=f"WebSocket connections detected: {len(ws_connections)} endpoint(s) — used by chat, real-time features",
                severity="info",
                evidence_refs=["js_analysis.websocket_connections"],
            ))

        # Many external requests
        ext_count = js.get("external_requests", 0)
        if ext_count > 20:
            signals.append(Signal(
                id="sig_many_external_requests",
                category="content",
                description=f"Page makes {ext_count} external requests to third-party domains",
                severity="info",
                evidence_refs=["js_analysis.external_requests"],
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

    # ── Subdomain enumeration signals ──
    subdomains = evidence.get("subdomains")
    if subdomains:
        resolved_count = len(subdomains.get("resolved", []))
        interesting = subdomains.get("interesting_subdomains", [])

        if resolved_count > 20:
            signals.append(Signal(
                id="sig_many_live_subdomains",
                category="infrastructure",
                description=f"{resolved_count} live subdomains resolved — large infrastructure footprint",
                severity="info",
                evidence_refs=["subdomains.resolved"],
            ))

        if interesting:
            names = [s.get("subdomain", "") for s in interesting[:5]]
            signals.append(Signal(
                id="sig_interesting_subdomains",
                category="infrastructure",
                description=(
                    f"{len(interesting)} interesting subdomain(s) found: "
                    f"{', '.join(names)}{'...' if len(interesting) > 5 else ''}"
                ),
                severity="medium",
                evidence_refs=["subdomains.interesting_subdomains"],
            ))

    # ── Infrastructure pivot signals ──
    infra_pivot = evidence.get("infrastructure_pivot", {})
    if infra_pivot:
        if infra_pivot.get("shared_hosting_detected"):
            for rip in infra_pivot.get("reverse_ip", []):
                total = rip.get("total_domains", 0)
                if total > 10:
                    signals.append(Signal(
                        id="sig_shared_hosting",
                        category="infrastructure",
                        description=(
                            f"IP {rip.get('ip')} hosts {total} domains — "
                            f"shared/bulletproof hosting environment"
                        ),
                        severity="medium",
                        evidence_refs=["infrastructure_pivot.reverse_ip"],
                    ))

        ns_clusters = infra_pivot.get("ns_clusters", [])
        for cluster in ns_clusters:
            cluster_domains = cluster.get("domains", [])
            if cluster_domains:
                signals.append(Signal(
                    id="sig_ns_cluster",
                    category="infrastructure",
                    description=(
                        f"Nameservers shared with {len(cluster_domains)} other investigated domain(s) in our database"
                    ),
                    severity="medium",
                    evidence_refs=["infrastructure_pivot.ns_clusters"],
                ))
                break  # one signal is enough

        registrant_pivots = infra_pivot.get("registrant_pivots", [])
        for pivot in registrant_pivots:
            pivot_domains = pivot.get("domains", [])
            if pivot_domains:
                signals.append(Signal(
                    id="sig_registrant_pivot",
                    category="infrastructure",
                    description=(
                        f"Registrant/registrar matches {len(pivot_domains)} other investigated domain(s) — "
                        f"possible same threat actor"
                    ),
                    severity="medium",
                    evidence_refs=["infrastructure_pivot.registrant_pivots"],
                ))
                break

    # ── Certificate Transparency Timeline signals ──
    cert_timeline = evidence.get("cert_timeline", {})
    if cert_timeline:
        if cert_timeline.get("cert_burst_detected"):
            burst_periods = cert_timeline.get("burst_periods", [])
            max_burst = max((bp.get("count", 0) for bp in burst_periods), default=0)
            signals.append(Signal(
                id="sig_cert_burst_detected",
                category="certificate",
                description=(
                    f"Certificate burst detected: {max_burst} certificates issued in a 7-day window — "
                    f"possible rapid domain repurposing or phishing kit deployment"
                ),
                severity="high",
                evidence_refs=["cert_timeline.cert_burst_detected", "cert_timeline.burst_periods"],
            ))

        short_lived = cert_timeline.get("short_lived_count", 0)
        if short_lived > 0:
            signals.append(Signal(
                id="sig_cert_short_lived",
                category="certificate",
                description=(
                    f"{short_lived} short-lived certificate(s) detected (<30 day validity) — "
                    f"common in phishing infrastructure using automated tooling"
                ),
                severity="medium",
                evidence_refs=["cert_timeline.short_lived_count"],
            ))

        unique_issuers = cert_timeline.get("unique_issuers", [])
        if len(unique_issuers) > 3:
            signals.append(Signal(
                id="sig_cert_issuer_diversity",
                category="certificate",
                description=(
                    f"{len(unique_issuers)} different certificate issuers across {cert_timeline.get('total_certs', 0)} certs — "
                    f"infrastructure changes over time"
                ),
                severity="info",
                evidence_refs=["cert_timeline.unique_issuers"],
            ))

    # ── Favicon hash intelligence signals ──
    favicon_intel = evidence.get("favicon_intel", {})
    if favicon_intel:
        total_sharing = favicon_intel.get("total_hosts_sharing", 0)
        is_default = favicon_intel.get("is_default_favicon", False)
        if total_sharing > 5 and not is_default:
            signals.append(Signal(
                id="sig_favicon_shared_infrastructure",
                category="infrastructure",
                description=(
                    f"Favicon hash shared by {total_sharing} other hosts on Shodan — "
                    f"potential shared phishing infrastructure"
                ),
                severity="medium",
                evidence_refs=["favicon_intel.total_hosts_sharing"],
            ))
        elif total_sharing <= 3 and not is_default and favicon_intel.get("favicon_hash"):
            signals.append(Signal(
                id="sig_favicon_unique",
                category="infrastructure",
                description="Favicon hash is unique or rare — custom/bespoke deployment",
                severity="info",
                evidence_refs=["favicon_intel.is_unique_favicon"],
            ))

    # ── Threat feed signals ──
    threat_feeds = evidence.get("threat_feeds", {})
    if threat_feeds:
        abuseipdb = threat_feeds.get("abuseipdb", {}) or {}
        abuse_score = abuseipdb.get("abuse_confidence_score", 0)
        if abuse_score >= 75:
            signals.append(Signal(
                id="sig_abuseipdb_high",
                category="reputation",
                description=(
                    f"AbuseIPDB: IP has {abuse_score}% abuse confidence score "
                    f"({abuseipdb.get('total_reports', 0)} reports)"
                ),
                severity="high",
                evidence_refs=["threat_feeds.abuseipdb.abuse_confidence_score"],
            ))
        elif abuse_score >= 25:
            signals.append(Signal(
                id="sig_abuseipdb_medium",
                category="reputation",
                description=(
                    f"AbuseIPDB: IP has {abuse_score}% abuse confidence score "
                    f"({abuseipdb.get('total_reports', 0)} reports)"
                ),
                severity="medium",
                evidence_refs=["threat_feeds.abuseipdb.abuse_confidence_score"],
            ))

        phishtank = threat_feeds.get("phishtank", {}) or {}
        if phishtank.get("in_database") and phishtank.get("verified"):
            signals.append(Signal(
                id="sig_phishtank_match",
                category="reputation",
                description="PhishTank: URL confirmed as active phishing site (verified by community)",
                severity="critical",
                evidence_refs=["threat_feeds.phishtank.in_database", "threat_feeds.phishtank.verified"],
            ))
        elif phishtank.get("in_database"):
            signals.append(Signal(
                id="sig_phishtank_listed",
                category="reputation",
                description="PhishTank: URL found in phishing database (pending verification)",
                severity="high",
                evidence_refs=["threat_feeds.phishtank.in_database"],
            ))

        threatfox_matches = threat_feeds.get("threatfox_matches", []) or []
        if threatfox_matches:
            malware_names = list(set(
                m.get("malware", "unknown") for m in threatfox_matches if m.get("malware")
            ))
            signals.append(Signal(
                id="sig_threatfox_match",
                category="reputation",
                description=(
                    f"ThreatFox: {len(threatfox_matches)} IOC match(es) found"
                    f" — malware: {', '.join(malware_names[:3])}" if malware_names else
                    f"ThreatFox: {len(threatfox_matches)} IOC match(es) found"
                ),
                severity="critical",
                evidence_refs=["threat_feeds.threatfox_matches"],
            ))

        if threat_feeds.get("openphish_listed"):
            signals.append(Signal(
                id="sig_openphish_listed",
                category="reputation",
                description="OpenPhish: Domain found in active phishing feed",
                severity="high",
                evidence_refs=["threat_feeds.openphish_listed"],
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
