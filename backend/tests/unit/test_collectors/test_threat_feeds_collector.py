from __future__ import annotations

from app.collectors.threat_feeds_collector import ThreatFeedsCollector


def test_otx_indicator_type_mapping() -> None:
    collector = ThreatFeedsCollector("example.com", "case-1")

    assert collector._otx_indicator_type("example.com", "domain") == "domain"
    assert collector._otx_indicator_type("https://example.com/a?b=1", "url") == "URL"
    assert collector._otx_indicator_type("8.8.8.8", "ip") == "IPv4"
    assert collector._otx_indicator_type("2001:4860:4860::8888", "ip") == "IPv6"
    assert collector._otx_indicator_type("a" * 64, "hash") == "file"
    assert collector._otx_indicator_type("not-an-ip", "ip") is None


def test_parse_otx_general_extracts_pulse_summary() -> None:
    collector = ThreatFeedsCollector("bad.example", "case-1")

    out = collector._parse_otx_general(
        {
            "reputation": 5,
            "indicator": "bad.example",
            "sections": ["general", "malware"],
            "validation": ["hostname"],
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {
                        "id": "pulse-1",
                        "name": "Example phishing infrastructure",
                        "author": {"username": "analyst"},
                        "description": "Credential harvesting cluster",
                        "TLP": "white",
                        "subscriber_count": 42,
                        "indicator_count": 9,
                        "related_indicator_is_active": 0,
                        "modified": "2026-05-01T00:00:00",
                        "tags": ["phishing", "credential-theft"],
                        "malware_families": ["ExampleStealer"],
                        "adversary": "Example actor",
                        "references": ["https://example.test/report"],
                    },
                    {
                        "id": "pulse-2",
                        "name": "Follow-on activity",
                        "tags": ["phishing"],
                        "references": ["https://example.test/report"],
                    },
                ],
            },
        },
        "domain",
        {
            "geo": {"asn": "AS13335 cloudflare", "country_name": "Canada"},
            "passive_dns": {
                "count": 3,
                "passive_dns": [
                    {
                        "hostname": "bad.example",
                        "address": "1.2.3.4",
                        "record_type": "A",
                        "first": "2026-01-01T00:00:00",
                        "last": "2026-02-01T00:00:00",
                        "asn": "AS64500 example",
                        "flag_title": "Exampleland",
                    },
                    {
                        "hostname": "www.bad.example",
                        "address": "ns1.example.net",
                        "record_type": "NS",
                    },
                ],
            },
            "url_list": {"full_size": 1, "url_list": [{"url": "http://bad.example/login"}]},
            "malware": {"count": 1, "data": [{}]},
        },
    )

    assert out.checked is True
    assert out.found is True
    assert out.indicator_facts == [
        "Historical OTX telemetry",
        "1 subdomain",
        "1 observed URL",
        "1 malware sample",
        "ExampleStealer",
        "credential-theft",
        "phishing",
    ]
    assert out.indicator_type == "domain"
    assert out.pulse_count == 2
    assert [pulse.name for pulse in out.pulses] == [
        "Example phishing infrastructure",
        "Follow-on activity",
    ]
    assert out.pulses[0].author_name == "analyst"
    assert out.pulses[0].description == "Credential harvesting cluster"
    assert out.pulses[0].tlp == "white"
    assert out.pulses[0].subscriber_count == 42
    assert out.pulses[0].related_indicator_is_active is False
    assert out.geo == {"asn": "AS13335 cloudflare", "country_name": "Canada"}
    assert out.passive_dns_count == 3
    assert out.passive_dns[0].address == "1.2.3.4"
    assert out.ip_addresses == ["1.2.3.4"]
    assert out.nameservers == ["ns1.example.net"]
    assert out.subdomains == ["www.bad.example"]
    assert out.url_count == 1
    assert out.urls == ["http://bad.example/login"]
    assert out.malware_count == 1
    assert out.tags == ["credential-theft", "phishing"]
    assert out.malware_families == ["ExampleStealer"]
    assert out.adversaries == ["Example actor"]
    assert out.references == ["https://example.test/report"]
