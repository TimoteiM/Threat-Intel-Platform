from app.services.alert_finding_builder import build_indicator_findings


def _by_collector(findings: list[dict], collector: str, kind: str | None = None) -> dict | None:
    for finding in findings:
        if finding["collector"] == collector and (kind is None or finding["type"] == kind):
            return finding
    return None


def test_collectors_that_found_nothing_produce_no_findings():
    evidence = {
        "vt": {"found": False, "total_vendors": 0, "vendor_results": []},
        "whois": {"registrar": None, "name_servers": [], "statuses": []},
        "dns": {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []},
        "threat_feeds": {"threatfox_matches": [], "openphish_listed": False, "phishtank": None},
        "opencti": {"found": False, "score": 0},
        "http": {"reachable": False},
        "tls": {"present": False},
        "urlscan": {"verdict": "unknown"},
    }
    assert build_indicator_findings(evidence) == []


def test_virustotal_detection_finding_keeps_only_what_matters():
    evidence = {
        "vt": {
            "found": True,
            "malicious_count": 8,
            "suspicious_count": 0,
            "total_vendors": 94,
            "flagged_malicious_by": ["Kaspersky", "ESET"],
            "vendor_results": [
                {"vendor": "Kaspersky", "category": "malicious", "result": "Trojan.Win32.Emotet"},
                {"vendor": "Avast", "category": "undetected", "result": "undetected"},
            ],
            "reputation_score": -14,
        }
    }
    finding = _by_collector(build_indicator_findings(evidence), "vt", "reputation")
    assert finding["severity"] == "high"
    assert finding["summary"] == "8 of 94 engines flag this as malicious"
    assert finding["data"]["detections"] == ["Trojan.Win32.Emotet"]   # undetected rows dropped
    assert finding["data"]["flagged_by"] == ["Kaspersky", "ESET"]
    assert "suspicious" not in finding["data"]                        # zero values pruned


def test_clean_virustotal_result_is_reported_as_info():
    finding = _by_collector(
        build_indicator_findings({"vt": {"found": True, "malicious_count": 0, "total_vendors": 70}}),
        "vt",
        "reputation",
    )
    assert finding["severity"] == "info"
    assert finding["summary"] == "No detections across 70 engines"


def test_file_profile_finding_summarises_the_sample():
    evidence = {
        "vt": {
            "found": True,
            "total_vendors": 70,
            "malicious_count": 0,
            "file_details": {
                "meaningful_name": "sh.exe",
                "names": ["sh.exe", "bash.exe"],
                "file_type": "Win32 EXE",
                "size_bytes": 2456832,
                "signature": {"signed": False, "verified": "Invalid signature", "signers": ["Evil Corp"]},
                "threat_label": "trojan.emotet",
                "sandbox_verdicts": [
                    {"sandbox": "Zenbox", "category": "malicious", "malware_names": ["Emotet"]},
                    {"sandbox": "C2AE", "category": "undetected"},
                ],
                "crowdsourced_rules": [{"kind": "yara", "name": "detect_emotet", "source": "malpedia"}],
            },
        }
    }
    findings = build_indicator_findings(evidence)
    profile = _by_collector(findings, "vt", "file_profile")
    assert "sh.exe" in profile["summary"]
    assert "trojan.emotet" in profile["summary"]
    assert profile["severity"] == "high"                       # malicious sandbox verdict
    assert profile["data"]["other_names"] == ["bash.exe"]
    # Undetected sandboxes are not findings.
    assert [row["sandbox"] for row in profile["data"]["sandbox_verdicts"]] == ["Zenbox"]
    assert _by_collector(findings, "vt", "threat_intel")["data"]["rules"][0]["name"] == "detect_emotet"


def test_sandbox_behaviour_finding_lists_only_observed_activity():
    evidence = {
        "vt": {
            "found": True,
            "total_vendors": 1,
            "behaviour": {
                "checked": True,
                "processes_created": ["software.exe"],
                "dns_lookups": ["cdn.evil-corp.net"],
                "files_dropped": [],
                "registry_keys_set": [],
                "attack_techniques": ["T1027 — encode data using Base64"],
            },
        }
    }
    behaviour = _by_collector(build_indicator_findings(evidence), "vt", "sandbox_behaviour")
    assert set(behaviour["data"]) == {"processes_created", "dns_lookups", "attack_techniques"}
    assert "1 processes created" in behaviour["summary"]


def test_unverified_phishtank_is_low_and_verified_is_high():
    low = _by_collector(
        build_indicator_findings({"threat_feeds": {"phishtank": {"in_database": True, "verified": False}}}),
        "threat_feeds",
    )
    assert low["severity"] == "low"

    high = _by_collector(
        build_indicator_findings({"threat_feeds": {"phishtank": {"in_database": True, "verified": True}}}),
        "threat_feeds",
    )
    assert high["severity"] == "high"


def test_threatfox_matches_are_summarised_with_malware_names():
    evidence = {
        "threat_feeds": {
            "threatfox_matches": [
                {"ioc_value": "45.147.230.131", "malware": "Cobalt Strike", "threat_type": "botnet_cc"}
            ]
        }
    }
    finding = _by_collector(build_indicator_findings(evidence), "threat_feeds", "threat_intel")
    assert "Cobalt Strike" in finding["summary"]
    assert finding["severity"] == "high"
    assert finding["data"]["matches"][0]["ioc"] == "45.147.230.131"


def test_ip_lookup_findings_are_attributed_to_the_tool():
    ip_lookup = {
        "abuseipdb": {"abuse_confidence_score": 96, "total_reports": 44, "isp": "Bad Hosting", "country_code": "RU"},
        "threatfox": [{"ioc_value": "45.147.230.131", "malware": "Emotet"}],
    }
    findings = build_indicator_findings({}, ip_lookup=ip_lookup)
    abuse = _by_collector(findings, "ip_lookup", "reputation")
    assert abuse["source"] == "IP Lookup / AbuseIPDB"
    assert abuse["severity"] == "high"
    assert abuse["data"]["isp"] == "Bad Hosting"
    assert _by_collector(findings, "ip_lookup", "threat_intel")["severity"] == "high"


def test_newly_registered_domain_is_flagged_from_whois():
    finding = _by_collector(
        build_indicator_findings({"whois": {"registrar": "NameCheap", "domain_age_days": 4}}), "whois"
    )
    assert finding["severity"] == "medium"
    assert "4 day(s) ago" in finding["summary"]


def test_findings_are_ordered_most_severe_first():
    evidence = {
        "dns": {"a": ["1.2.3.4"]},
        "vt": {"found": True, "malicious_count": 9, "total_vendors": 90},
        "whois": {"registrar": "NameCheap", "domain_age_days": 900},
    }
    severities = [finding["severity"] for finding in build_indicator_findings(evidence)]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2, "info": 3}[s])
    assert severities[0] == "high"
