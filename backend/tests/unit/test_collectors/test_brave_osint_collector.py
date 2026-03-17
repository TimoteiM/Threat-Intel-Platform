from app.collectors.brave_osint_collector import (
    BraveOSINTCollector,
    build_summary,
    filter_results,
    generate_queries,
    score_results,
)


def test_generate_queries_uses_domain_and_optional_context():
    queries = generate_queries(
        domain="evantage.eu",
        context={
            "brand": "revantage",
            "keywords": ["login", "secure"],
            "ip": "1.2.3.4",
            "asn": "AS12345",
        },
    )

    assert '"evantage.eu"' in queries
    assert '"evantage.eu" phishing' in queries
    assert 'revantage phishing' in queries
    assert 'revantage login scam' in queries
    assert '1.2.3.4 abuse' in queries
    assert 'AS12345 phishing' in queries
    assert 'login secure account scam' in queries
    assert 5 <= len(queries) <= 8
    assert len(queries) == len(set(queries))


def test_filter_results_keeps_security_relevant_hits_and_prioritizes_preferred_sources():
    raw_results = [
        {
            "title": "Revantage phishing campaign discussed",
            "url": "https://www.reddit.com/r/netsec/comments/abc/revantage_phishing_campaign/",
            "description": "Users report phishing and scam activity tied to the brand.",
        },
        {
            "title": "Evantage official business listing",
            "url": "https://directory.example.com/evantage-eu",
            "description": "A local company listing for Evantage.",
        },
        {
            "title": "IOC list for evantage.eu malware lure",
            "url": "https://github.com/example/iocs/blob/main/evantage.md",
            "description": "Malware and phishing indicators associated with the domain.",
        },
    ]

    filtered = filter_results(raw_results)

    assert [item["url"] for item in filtered] == [
        "https://www.reddit.com/r/netsec/comments/abc/revantage_phishing_campaign/",
        "https://github.com/example/iocs/blob/main/evantage.md",
    ]


def test_score_results_and_build_summary_favor_high_signal_sources():
    filtered = [
        {
            "title": "Revantage phishing campaign discussed",
            "url": "https://www.reddit.com/r/netsec/comments/abc/revantage_phishing_campaign/",
            "description": "Users report phishing and scam activity tied to the brand.",
        },
        {
            "title": "IOC list for evantage.eu malware lure",
            "url": "https://github.com/example/iocs/blob/main/evantage.md",
            "description": "Malware and phishing indicators associated with the domain.",
        },
    ]

    scored = score_results(filtered)
    summary = build_summary(domain="evantage.eu", queries=['"evantage.eu" phishing'], scored_results=scored)

    assert all("score" in item for item in scored)
    assert summary["score"] >= 60
    assert summary["risk_level"] in {"medium", "high"}
    assert "evantage.eu" in summary["summary"].lower()
    assert summary["top_hits"][0]["url"].startswith("https://")


def test_collector_run_builds_brave_osint_evidence(monkeypatch):
    class _Settings:
        brave_search_api_key = "brave-test"
        brave_search_base_url = "https://api.search.brave.com/res/v1/web/search"
        brave_search_count = 10

    monkeypatch.setattr("app.collectors.brave_osint_collector.get_settings", lambda: _Settings())
    monkeypatch.setattr(
        "app.collectors.brave_osint_collector.search_brave",
        lambda *args, **kwargs: [
            {
                "title": "Revantage phishing campaign discussed",
                "url": "https://www.reddit.com/r/netsec/comments/abc/revantage_phishing_campaign/",
                "description": "Users report phishing and scam activity tied to the brand.",
            }
        ],
    )

    collector = BraveOSINTCollector(
        domain="evantage.eu",
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=5,
        external_context={"brand": "revantage", "keywords": ["login", "secure"]},
    )

    evidence, meta, artifacts = collector.run()

    assert meta.status.value == "completed"
    assert evidence.checked is True
    assert evidence.score > 0
    assert evidence.top_hits[0].source == "reddit.com"
    assert any(name.startswith("brave_osint_") for name in artifacts)
