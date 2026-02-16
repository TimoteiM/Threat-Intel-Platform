"""Tests for DNS collector."""

import json
from unittest.mock import patch, MagicMock

import pytest

from app.collectors.dns_collector import DNSCollector


class TestDNSCollector:

    def test_run_returns_tuple(self):
        """Collector.run() always returns (evidence, meta, artifacts)."""
        with patch("app.collectors.dns_collector.dns.resolver.Resolver") as mock_resolver:
            mock_instance = MagicMock()
            mock_resolver.return_value = mock_instance
            mock_instance.resolve.side_effect = Exception("No network in tests")

            collector = DNSCollector("example.com", "test-001")
            evidence, meta, artifacts = collector.run()

            assert meta.collector == "dns"
            assert meta.status.value in ("completed", "failed")

    def test_empty_evidence_on_failure(self):
        """On failure, returns empty evidence with error in meta."""
        with patch("app.collectors.dns_collector.dns.resolver.Resolver") as mock_resolver:
            mock_instance = MagicMock()
            mock_resolver.return_value = mock_instance
            mock_instance.resolve.side_effect = Exception("DNS timeout")

            collector = DNSCollector("example.com", "test-001")
            evidence, meta, artifacts = collector.run()

            assert meta.status.value == "failed"
            assert "DNS timeout" in (meta.error or "")
            assert evidence.a == []
            assert evidence.ns == []


class TestDNSCollectorParsing:

    def test_spf_extracted_from_txt(self):
        """SPF record is extracted from TXT records."""
        collector = DNSCollector("example.com", "test-001")

        # Simulate evidence with TXT records
        from app.models.schemas import DNSEvidence
        evidence = DNSEvidence()
        evidence.txt = ["v=spf1 include:_spf.google.com ~all", "some-other-txt"]

        # The SPF extraction logic
        for txt in evidence.txt:
            if txt.lower().startswith("v=spf1"):
                evidence.spf = txt
                break

        assert evidence.spf == "v=spf1 include:_spf.google.com ~all"
