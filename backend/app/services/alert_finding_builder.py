"""
Turn raw collector evidence into findings.

An alert-body report should say what was *found*, not dump every field a
collector can return. Each collector contributes zero or more findings; a
collector that saw nothing contributes none (that it ran at all is already
recorded in the report's `collector_runs`).

Finding shape:

    {
      "source": "VirusTotal",        # human-readable provider
      "collector": "vt",             # collector key that produced it
      "type": "reputation",          # reputation | file_profile | sandbox_behaviour
                                     # | infrastructure | registration | web
                                     # | threat_intel | blocklist | certificate
      "severity": "high",            # high | medium | low | info
      "summary": "8 of 94 engines flag this as malicious",
      "data": { … only the values that were actually present … }
    }
"""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_indicator_findings(
    evidence: dict[str, Any],
    *,
    ip_lookup: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return the findings for one indicator, most severe first."""
    findings: list[dict[str, Any]] = []

    findings.extend(_virustotal_findings(_as_dict(evidence.get("vt"))))
    findings.extend(_threat_feed_findings(_as_dict(evidence.get("threat_feeds"))))
    findings.extend(_urlscan_findings(_as_dict(evidence.get("urlscan"))))
    findings.extend(_opencti_findings(_as_dict(evidence.get("opencti"))))
    findings.extend(_anyrun_findings(_as_dict(evidence.get("hybrid_analysis"))))
    findings.extend(_intel_findings(_as_dict(evidence.get("intel"))))
    findings.extend(_osint_findings(_as_dict(evidence.get("brave_osint"))))
    findings.extend(_dns_findings(_as_dict(evidence.get("dns"))))
    findings.extend(_whois_findings(_as_dict(evidence.get("whois"))))
    findings.extend(_asn_findings(_as_dict(evidence.get("asn"))))
    findings.extend(_http_findings(_as_dict(evidence.get("http"))))
    findings.extend(_tls_findings(_as_dict(evidence.get("tls"))))
    findings.extend(_ip_lookup_findings(_as_dict(ip_lookup)))

    findings.sort(key=lambda item: SEVERITY_ORDER.get(item.get("severity", "info"), 9))
    return findings


# ── VirusTotal ────────────────────────────────────────────────────────────────


def _virustotal_findings(vt: dict[str, Any]) -> list[dict[str, Any]]:
    if not vt:
        return []
    out: list[dict[str, Any]] = []
    malicious = int(vt.get("malicious_count") or 0)
    suspicious = int(vt.get("suspicious_count") or 0)
    total = int(vt.get("total_vendors") or 0)

    if vt.get("found") or total:
        # For a URL observable the stats may describe the URL's host instead —
        # say so in the summary rather than letting it read as a URL verdict.
        scope_value = str(vt.get("scope_value") or "")
        about = f" for the host {scope_value}" if vt.get("scope") == "domain" and scope_value else ""
        if malicious:
            severity, summary = (
                ("high" if malicious >= 5 else "medium"),
                f"{malicious} of {total} engines flag this as malicious{about}",
            )
        elif suspicious:
            severity, summary = "medium", f"{suspicious} of {total} engines flag this as suspicious{about}"
        elif total:
            severity, summary = "info", f"No detections across {total} engines{about}"
        else:
            severity, summary = "info", "Known to VirusTotal, no analysis results"
        out.append(
            _finding(
                "VirusTotal", "vt", "reputation", severity, summary,
                {
                    "scope": vt.get("scope") or None,
                    "scope_value": scope_value or None,
                    "malicious": malicious or None,
                    "suspicious": suspicious or None,
                    "total_engines": total or None,
                    "flagged_by": (vt.get("flagged_malicious_by") or [])[:10],
                    "detections": _vt_detection_names(vt),
                    "categories": vt.get("categories") or None,
                    "reputation_score": vt.get("reputation_score") or None,
                    "last_analysis": vt.get("last_analysis_date"),
                },
            )
        )

    out.extend(_vt_file_findings(_as_dict(vt.get("file_details"))))
    out.extend(_vt_behaviour_findings(_as_dict(vt.get("behaviour"))))
    return out


def _vt_detection_names(vt: dict[str, Any]) -> list[str]:
    """The distinct malware names engines returned — the useful half of the verdicts."""
    names: list[str] = []
    for row in vt.get("vendor_results") or []:
        if not isinstance(row, dict) or row.get("category") not in {"malicious", "suspicious"}:
            continue
        label = str(row.get("result") or "").strip()
        if label and label not in names:
            names.append(label)
    return names[:10]


def _vt_file_findings(details: dict[str, Any]) -> list[dict[str, Any]]:
    if not details:
        return []
    signature = _as_dict(details.get("signature"))
    name = details.get("meaningful_name")
    file_type = details.get("file_type")
    size = details.get("size_bytes")
    parts = [part for part in (name, file_type, _human_size(size)) if part]
    if signature:
        parts.append("signed" if signature.get("signed") else f"signature {signature.get('verified') or 'unverified'}")
    else:
        parts.append("unsigned")

    threat_label = details.get("threat_label")
    severity = "medium" if threat_label else "info"
    summary = " — ".join([str(parts[0]), ", ".join(str(p) for p in parts[1:])]) if parts else "File metadata"
    if threat_label:
        summary = f"{summary} · VT threat label {threat_label}"

    sandbox_verdicts = [
        {
            "sandbox": row.get("sandbox"),
            "verdict": row.get("category"),
            "malware_names": row.get("malware_names") or None,
        }
        for row in (details.get("sandbox_verdicts") or [])
        if isinstance(row, dict) and row.get("category") not in {None, "undetected"}
    ]
    if any(row.get("verdict") == "malicious" for row in sandbox_verdicts):
        severity = "high"

    out = [
        _finding(
            "VirusTotal", "vt", "file_profile", severity, summary,
            {
                "file_name": name,
                "other_names": [n for n in (details.get("names") or []) if n != name][:10],
                "file_type": file_type,
                "size_bytes": size,
                "magic": details.get("magic"),
                "sha256": details.get("sha256"),
                "md5": details.get("md5"),
                "imphash": details.get("imphash"),
                "signature": _clean(signature) or None,
                "threat_label": threat_label,
                "threat_categories": details.get("threat_categories") or None,
                "threat_names": details.get("threat_names") or None,
                "sandbox_verdicts": sandbox_verdicts or None,
                "capabilities": (details.get("capabilities_tags") or [])[:10] or None,
                "tags": (details.get("tags") or [])[:10] or None,
                "first_submission": details.get("first_submission_date"),
                "times_submitted": details.get("times_submitted"),
                "pe_sections": details.get("pe_sections") or None,
            },
        )
    ]

    rules = [
        {
            "kind": rule.get("kind"),
            "name": rule.get("name"),
            "severity": rule.get("severity"),
            "source": rule.get("source"),
        }
        for rule in (details.get("crowdsourced_rules") or [])
        if isinstance(rule, dict) and rule.get("name")
    ]
    if rules:
        out.append(
            _finding(
                "VirusTotal", "vt", "threat_intel", "medium",
                f"{len(rules)} crowdsourced rule(s) match this file",
                {"rules": rules},
            )
        )
    return out


def _vt_behaviour_findings(behaviour: dict[str, Any]) -> list[dict[str, Any]]:
    if not behaviour or not behaviour.get("checked"):
        return []
    data = _clean(
        {
            "processes_created": behaviour.get("processes_created"),
            "command_executions": behaviour.get("command_executions"),
            "files_written": behaviour.get("files_written"),
            "files_dropped": behaviour.get("files_dropped"),
            "registry_keys_set": behaviour.get("registry_keys_set"),
            "mutexes_created": behaviour.get("mutexes_created"),
            "services_created": behaviour.get("services_created"),
            "dns_lookups": behaviour.get("dns_lookups"),
            "ip_traffic": behaviour.get("ip_traffic"),
            "http_conversations": behaviour.get("http_conversations"),
            "attack_techniques": behaviour.get("attack_techniques"),
        }
    )
    if not data:
        return []
    highlights = [
        f"{len(values)} {key.replace('_', ' ')}"
        for key, values in data.items()
        if isinstance(values, list)
    ][:4]
    return [
        _finding(
            "VirusTotal", "vt", "sandbox_behaviour", "info",
            "Sandbox behaviour: " + ", ".join(highlights),
            data,
        )
    ]


# ── Threat feeds ──────────────────────────────────────────────────────────────


def _threat_feed_findings(feeds: dict[str, Any]) -> list[dict[str, Any]]:
    if not feeds:
        return []
    out: list[dict[str, Any]] = []

    phishtank = _as_dict(feeds.get("phishtank"))
    if phishtank.get("in_database"):
        verified = bool(phishtank.get("verified"))
        out.append(
            _finding(
                "PhishTank", "threat_feeds", "blocklist",
                "high" if verified else "low",
                "Verified phishing listing" if verified else "Unverified phishing listing (may be stale)",
                _clean({
                    "verified": verified,
                    "phish_id": phishtank.get("phish_id"),
                    "verified_at": phishtank.get("verified_at"),
                    "target_brand": phishtank.get("target_brand"),
                }),
            )
        )

    if feeds.get("openphish_listed"):
        out.append(_finding("OpenPhish", "threat_feeds", "blocklist", "high", "Listed as a phishing URL", {}))

    gsb = _as_dict(feeds.get("google_safe_browsing"))
    if gsb.get("listed"):
        out.append(
            _finding(
                "Google Safe Browsing", "threat_feeds", "blocklist", "high",
                "Listed: " + (", ".join(gsb.get("threat_types") or []) or "unsafe"),
                _clean({"threat_types": gsb.get("threat_types"), "matches": gsb.get("matches_count")}),
            )
        )

    matches = [row for row in (feeds.get("threatfox_matches") or []) if isinstance(row, dict)]
    if matches:
        malware = sorted({str(row.get("malware")) for row in matches if row.get("malware")})
        out.append(
            _finding(
                "ThreatFox", "threat_feeds", "threat_intel", "high",
                f"{len(matches)} IOC match(es)" + (f" — {', '.join(malware)}" if malware else ""),
                {
                    "matches": [
                        _clean({
                            "ioc": row.get("ioc_value"),
                            "type": row.get("ioc_type"),
                            "threat_type": row.get("threat_type"),
                            "malware": row.get("malware"),
                            "confidence": row.get("confidence_level"),
                            "first_seen": row.get("first_seen"),
                            "last_seen": row.get("last_seen"),
                        })
                        for row in matches[:10]
                    ]
                },
            )
        )

    abuse = _as_dict(feeds.get("abuseipdb"))
    finding = _abuse_finding(abuse, collector="threat_feeds")
    if finding:
        out.append(finding)

    otx = _as_dict(feeds.get("otx"))
    pulses = int(otx.get("pulse_count") or 0)
    if pulses:
        out.append(
            _finding(
                "AlienVault OTX", "threat_feeds", "threat_intel",
                "medium" if pulses >= 3 else "low",
                f"Referenced by {pulses} threat pulse(s)",
                {
                    "pulse_count": pulses,
                    "pulses": [
                        str(pulse.get("name"))
                        for pulse in (otx.get("pulses") or [])
                        if isinstance(pulse, dict) and pulse.get("name")
                    ][:8],
                },
            )
        )
    return out


def _abuse_finding(abuse: dict[str, Any], *, collector: str) -> dict[str, Any] | None:
    if not abuse or abuse.get("abuse_confidence_score") is None:
        return None
    score = int(abuse.get("abuse_confidence_score") or 0)
    reports = int(abuse.get("total_reports") or 0)
    if score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    elif score > 0 or reports:
        severity = "low"
    else:
        severity = "info"
    summary = (
        f"Abuse confidence {score}% from {reports} report(s)"
        if reports
        else "No abuse reports"
    )
    return _finding(
        "AbuseIPDB", collector, "reputation", severity, summary,
        _clean({
            "abuse_confidence_score": score,
            "total_reports": reports or None,
            "last_reported_at": abuse.get("last_reported_at"),
            "isp": abuse.get("isp"),
            "usage_type": abuse.get("usage_type"),
            "country_code": abuse.get("country_code"),
            "categories": abuse.get("category_labels") or None,
            "is_tor": abuse.get("is_tor") or None,
        }),
    )


# ── Other collectors ──────────────────────────────────────────────────────────


def _urlscan_findings(urlscan: dict[str, Any]) -> list[dict[str, Any]]:
    verdict = str(urlscan.get("verdict") or "").lower()
    if not urlscan or verdict in {"", "unknown"}:
        return []
    severity = {"malicious": "high", "suspicious": "medium"}.get(verdict, "info")
    return [
        _finding(
            "URLScan", "urlscan", "web", severity, f"Scan verdict: {verdict}",
            _clean({
                "score": urlscan.get("score"),
                "page_url": urlscan.get("page_url"),
                "page_ip": urlscan.get("page_ip"),
                "page_country": urlscan.get("page_country"),
                "page_server": urlscan.get("page_server"),
                "page_title": urlscan.get("page_title"),
                "tags": urlscan.get("tags") or None,
                "scan_id": urlscan.get("scan_id"),
            }),
        )
    ]


def _opencti_findings(opencti: dict[str, Any]) -> list[dict[str, Any]]:
    if not opencti or not opencti.get("found"):
        return []
    score = int(opencti.get("score") or 0)
    indicators = opencti.get("indicators") or []
    reports = opencti.get("reports") or []
    severity = "high" if score >= 70 else ("medium" if indicators or reports else "low")
    return [
        _finding(
            "OpenCTI", "opencti", "threat_intel", severity,
            f"Known observable (score {score})",
            _clean({
                "score": score,
                "entity_type": opencti.get("observable_entity_type"),
                "labels": opencti.get("labels") or None,
                "indicators": [
                    str(row.get("name")) for row in indicators if isinstance(row, dict) and row.get("name")
                ][:8] or None,
                "reports": [
                    str(row.get("name")) for row in reports if isinstance(row, dict) and row.get("name")
                ][:8] or None,
                "malware_families": [
                    str(row.get("name"))
                    for row in (opencti.get("malware_families") or [])
                    if isinstance(row, dict) and row.get("name")
                ] or None,
                "threat_actors": [
                    str(row.get("name"))
                    for row in (opencti.get("threat_actors") or [])
                    if isinstance(row, dict) and row.get("name")
                ] or None,
                "campaigns": opencti.get("campaigns") or None,
                "intrusion_sets": opencti.get("intrusion_sets") or None,
            }),
        )
    ]


def _anyrun_findings(anyrun: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in anyrun.get("items") or []:
        if not isinstance(item, dict) or not item.get("checked"):
            continue
        verdict = str(item.get("verdict") or "unknown").lower()
        if verdict in {"", "unknown"}:
            continue
        severity = {"malicious": "high", "suspicious": "medium"}.get(verdict, "info")
        out.append(
            _finding(
                "AnyRun", "hybrid_analysis", "sandbox_behaviour", severity,
                f"Sandbox verdict: {verdict}",
                _clean({
                    "threat_score": item.get("threat_score"),
                    "threat_names": item.get("threat_names") or None,
                    "tags": item.get("tags") or None,
                    "analysis_link": item.get("analysis_link"),
                }),
            )
        )
    return out


def _intel_findings(intel: dict[str, Any]) -> list[dict[str, Any]]:
    hits = [hit for hit in (intel.get("blocklist_hits") or []) if isinstance(hit, dict)]
    if not hits:
        return []
    sources = sorted({str(hit.get("source")) for hit in hits if hit.get("source")})
    return [
        _finding(
            "Blocklists", "intel", "blocklist", "medium",
            f"{len(hits)} blocklist hit(s)" + (f" — {', '.join(sources)}" if sources else ""),
            {
                "hits": [
                    _clean({
                        "source": hit.get("source"),
                        "category": hit.get("category"),
                        "severity": hit.get("severity"),
                        "details": hit.get("details"),
                    })
                    for hit in hits[:10]
                ]
            },
        )
    ]


def _osint_findings(osint: dict[str, Any]) -> list[dict[str, Any]]:
    hits = [hit for hit in (osint.get("top_hits") or []) if isinstance(hit, dict)]
    if not osint.get("checked") or not hits:
        return []
    risk = str(osint.get("risk_level") or "low").lower()
    return [
        _finding(
            "Brave OSINT", "brave_osint", "threat_intel",
            {"high": "medium", "medium": "low"}.get(risk, "info"),
            osint.get("summary") or f"{len(hits)} public OSINT mention(s)",
            {
                "risk_level": risk,
                "hits": [
                    _clean({"title": hit.get("title"), "url": hit.get("url"), "source": hit.get("source")})
                    for hit in hits[:6]
                ],
            },
        )
    ]


def _dns_findings(dns: dict[str, Any]) -> list[dict[str, Any]]:
    data = _clean({
        "a": dns.get("a"),
        "aaaa": dns.get("aaaa"),
        "cname": dns.get("cname"),
        "mx": dns.get("mx"),
        "ns": dns.get("ns"),
        "spf": dns.get("spf"),
        "dmarc": dns.get("dmarc"),
    })
    if not data:
        return []
    resolved = (data.get("a") or []) + (data.get("aaaa") or [])
    summary = f"Resolves to {', '.join(resolved[:3])}" if resolved else "DNS records present"
    return [_finding("DNS", "dns", "infrastructure", "info", summary, data)]


def _whois_findings(whois: dict[str, Any]) -> list[dict[str, Any]]:
    data = _clean({
        "registrar": whois.get("registrar"),
        "created_date": whois.get("created_date"),
        "expiry_date": whois.get("expiry_date"),
        "domain_age_days": whois.get("domain_age_days"),
        "registrant_org": whois.get("registrant_org"),
        "registrant_country": whois.get("registrant_country"),
        "name_servers": whois.get("name_servers"),
    })
    if not data:
        return []
    age = whois.get("domain_age_days")
    if isinstance(age, int) and 0 <= age <= 30:
        severity, summary = "medium", f"Domain registered {age} day(s) ago"
    else:
        severity = "info"
        summary = f"Registered via {data.get('registrar')}" if data.get("registrar") else "Registration details"
        if isinstance(age, int):
            summary += f", {age} days old"
    return [_finding("WHOIS", "whois", "registration", severity, summary, data)]


def _asn_findings(asn: dict[str, Any]) -> list[dict[str, Any]]:
    data = _clean({
        "ip": asn.get("ip"),
        "asn": asn.get("asn"),
        "asn_org": asn.get("asn_org"),
        "country": asn.get("country"),
        "city": asn.get("city"),
        "reverse_dns": asn.get("reverse_dns"),
        "is_cdn": asn.get("is_cdn") or None,
        "is_cloud": asn.get("is_cloud") or None,
        "is_hosting": asn.get("is_hosting") or None,
    })
    if not data:
        return []
    where = ", ".join(str(v) for v in (data.get("asn_org"), data.get("country")) if v)
    return [
        _finding("ASN", "asn", "infrastructure", "info", f"Hosted by {where}" if where else "Hosting details", data)
    ]


def _http_findings(http: dict[str, Any]) -> list[dict[str, Any]]:
    if not http or not http.get("reachable"):
        return []
    phishing = http.get("phishing_indicators") or []
    severity = "medium" if phishing else "info"
    summary = (
        f"{len(phishing)} phishing indicator(s) on the live page"
        if phishing
        else f"Reachable — HTTP {http.get('final_status_code')}"
    )
    return [
        _finding(
            "HTTP", "http", "web", severity, summary,
            _clean({
                "final_url": http.get("final_url"),
                "status_code": http.get("final_status_code"),
                "title": http.get("title"),
                "server": http.get("server"),
                "technologies": http.get("technologies_detected") or None,
                "has_login_form": http.get("has_login_form") or None,
                "phishing_indicators": phishing or None,
                "brand_indicators": http.get("brand_indicators") or None,
                "redirects": [
                    str(hop.get("url"))
                    for hop in (http.get("redirect_chain") or [])
                    if isinstance(hop, dict) and hop.get("url")
                ][:6] or None,
            }),
        )
    ]


def _tls_findings(tls: dict[str, Any]) -> list[dict[str, Any]]:
    if not tls or not tls.get("present"):
        return []
    self_signed = bool(tls.get("is_self_signed"))
    return [
        _finding(
            "TLS", "tls", "certificate", "medium" if self_signed else "info",
            "Self-signed certificate" if self_signed else f"Certificate issued by {tls.get('issuer_org') or tls.get('issuer') or 'unknown CA'}",
            _clean({
                "issuer": tls.get("issuer_org") or tls.get("issuer"),
                "subject": tls.get("subject"),
                "valid_from": tls.get("valid_from"),
                "valid_to": tls.get("valid_to"),
                "days_remaining": tls.get("valid_days_remaining"),
                "is_wildcard": tls.get("is_wildcard") or None,
                "is_self_signed": self_signed or None,
                "sans": (tls.get("sans") or [])[:10] or None,
            }),
        )
    ]


def _ip_lookup_findings(ip_lookup: dict[str, Any]) -> list[dict[str, Any]]:
    if not ip_lookup:
        return []
    out: list[dict[str, Any]] = []
    finding = _abuse_finding(_as_dict(ip_lookup.get("abuseipdb")), collector="ip_lookup")
    if finding:
        finding["source"] = "IP Lookup / AbuseIPDB"
        out.append(finding)

    matches = [row for row in (ip_lookup.get("threatfox") or []) if isinstance(row, dict)]
    if matches:
        malware = sorted({str(row.get("malware")) for row in matches if row.get("malware")})
        out.append(
            _finding(
                "IP Lookup / ThreatFox", "ip_lookup", "threat_intel", "high",
                f"{len(matches)} IOC match(es)" + (f" — {', '.join(malware)}" if malware else ""),
                {
                    "matches": [
                        _clean({
                            "ioc": row.get("ioc_value"),
                            "threat_type": row.get("threat_type"),
                            "malware": row.get("malware"),
                            "first_seen": row.get("first_seen"),
                            "last_seen": row.get("last_seen"),
                        })
                        for row in matches[:10]
                    ]
                },
            )
        )
    return out


# ── Helpers ───────────────────────────────────────────────────────────────────


def _finding(
    source: str,
    collector: str,
    finding_type: str,
    severity: str,
    summary: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source": source,
        "collector": collector,
        "type": finding_type,
        "severity": severity,
        "summary": summary,
        "data": _clean(data),
    }


def _clean(value: Any) -> Any:
    """Drop empty values so a finding only carries what was actually found."""
    if isinstance(value, dict):
        cleaned = {key: _clean(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if not _is_empty(item)}
    if isinstance(value, list):
        cleaned_list = [_clean(item) for item in value]
        return [item for item in cleaned_list if not _is_empty(item)]
    return value


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, list, dict, tuple, set)):
        return len(value) == 0
    return False


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _human_size(size: Any) -> str | None:
    try:
        size_bytes = int(size)
    except (TypeError, ValueError):
        return None
    if size_bytes <= 0:
        return None
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"
