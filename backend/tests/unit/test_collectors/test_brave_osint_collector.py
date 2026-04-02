from app.collectors.brave_osint_collector import (
    BraveOSINTCollector,
    build_summary,
    filter_results,
    generate_queries,
    score_results,
)


def test_generate_queries_uses_single_exact_domain_query():
    queries = generate_queries(
        domain="evantage.eu",
        context={
            "brand": "revantage",
            "keywords": ["login", "secure"],
            "ip": "1.2.3.4",
            "asn": "AS12345",
        },
    )

    assert queries == ["evantage.eu"]


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
    summary = build_summary(domain="evantage.eu", queries=["evantage.eu"], scored_results=scored)

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


def test_collector_keeps_observed_results_when_no_hits_match_security_filter(monkeypatch):
    class _Settings:
        brave_search_api_key = "brave-test"
        brave_search_base_url = "https://api.search.brave.com/res/v1/web/search"
        brave_search_count = 10

    monkeypatch.setattr("app.collectors.brave_osint_collector.get_settings", lambda: _Settings())
    monkeypatch.setattr(
        "app.collectors.brave_osint_collector.search_brave",
        lambda *args, **kwargs: [
            {
                "title": "Revantage official website",
                "url": "https://revantage.eu/",
                "description": "Corporate real estate services and investment platform.",
            },
            {
                "title": "Revantage careers",
                "url": "https://jobs.revantage.eu/",
                "description": "Open roles and company profile.",
            },
        ],
    )

    collector = BraveOSINTCollector(
        domain="revantage.eu",
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=5,
    )

    evidence, meta, _ = collector.run()

    assert meta.status.value == "completed"
    assert evidence.checked is True
    assert evidence.score == 0
    assert evidence.top_hits == []
    assert len(evidence.observed_results) == 2
    assert len(evidence.all_results) == 2
    assert evidence.observed_results[0].source == "revantage.eu"
    assert any("No high-signal Brave search results" in note for note in evidence.notes)


def test_build_summary_keeps_all_results_separate_from_filtered_hits():
    raw_results = [
        {
            "title": "Example official page",
            "url": "https://example.com/",
            "description": "Corporate landing page.",
        },
        {
            "title": "Example phishing discussion",
            "url": "https://reddit.com/r/netsec/example-phishing",
            "description": "Phishing and scam indicators tied to example.com.",
        },
    ]
    filtered = [
        {
            "title": "Example phishing discussion",
            "url": "https://reddit.com/r/netsec/example-phishing",
            "description": "Phishing and scam indicators tied to example.com.",
        },
    ]

    scored = score_results(filtered)
    summary = build_summary(
        domain="example.com",
        queries=["example.com"],
        raw_results=raw_results,
        scored_results=scored,
    )

    assert len(summary["top_hits"]) == 1
    assert len(summary["all_results"]) == 2
    assert summary["all_results"][0]["url"] == "https://example.com/"
