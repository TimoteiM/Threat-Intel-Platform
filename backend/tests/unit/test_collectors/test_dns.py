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


class TestDNSCollectorFailureIsNotAnAnswer:
    """A DNS outage is not "this domain has no records".

    The collector caught every lookup exception, logged it at DEBUG and moved
    on, so an outage returned a COMPLETED run with empty evidence — the
    strongest possible statement about a domain, made from having learned
    nothing. Measured over 2,603 stored runs: **1** had ever been recorded as
    failed, and 290 of 2,602 completed runs carry no records at all, which is
    the upper bound on how many were lying.

    Every test here is in the dangerous direction: the failure mode is a clean
    "no records found", never an error.
    """

    @staticmethod
    def _resolver(side_effect):
        from unittest.mock import MagicMock, patch
        ctx = patch("app.collectors.dns_collector.dns.resolver.Resolver")
        mock_resolver = ctx.__enter__()
        inst = MagicMock()
        mock_resolver.return_value = inst
        inst.resolve.side_effect = side_effect
        return ctx, inst

    def test_a_domain_that_does_not_exist_still_COMPLETES(self):
        """The control, and the one the fix must not break.

        NXDOMAIN is an ANSWER: the name does not exist, so it genuinely has no
        records. Turning that into a failed run would be the fix overshooting,
        and it is the common case in phishing work where a domain is taken
        down.
        """
        import dns.resolver
        ctx, _ = self._resolver(dns.resolver.NXDOMAIN())
        try:
            evidence, meta, _ = DNSCollector("nonexistent.invalid", "t-1").run()
        finally:
            ctx.__exit__(None, None, None)

        assert meta.status.value == "completed", (
            "a non-existent domain was reported as a failed lookup; NXDOMAIN "
            "is an answer, not an outage"
        )
        assert evidence.a == [] and evidence.ns == []
        assert evidence.notes == [], "an answer must not be recorded as a failure"

    def test_no_answer_on_every_type_still_COMPLETES(self):
        """The second control: a domain that exists with no records of these
        types has answered us."""
        import dns.resolver
        ctx, _ = self._resolver(dns.resolver.NoAnswer())
        try:
            _, meta, _ = DNSCollector("example.com", "t-2").run()
        finally:
            ctx.__exit__(None, None, None)
        assert meta.status.value == "completed"

    def test_every_nameserver_erroring_is_a_FAILURE_not_an_empty_answer(self):
        """`NoNameservers` was grouped with NXDOMAIN and NoAnswer as though it
        were an answer. dnspython raises it when EVERY nameserver errored —
        socket errors during a local outage included — so it is a statement
        about our reachability, not about the domain."""
        import dns.resolver
        ctx, _ = self._resolver(dns.resolver.NoNameservers())
        try:
            evidence, meta, _ = DNSCollector("example.com", "t-3").run()
        finally:
            ctx.__exit__(None, None, None)

        assert meta.status.value == "failed", (
            "every nameserver errored and the run reported 'no records'"
        )
        assert "NoNameservers" in (meta.error or "")
        assert evidence.a == []

    def test_the_error_names_every_lookup_that_failed(self):
        ctx, _ = self._resolver(Exception("DNS timeout"))
        try:
            _, meta, _ = DNSCollector("example.com", "t-4").run()
        finally:
            ctx.__exit__(None, None, None)
        err = meta.error or ""
        assert "all 7 DNS lookups failed" in err
        for label in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "DMARC"):
            assert label in err, f"{label} missing from the failure summary"

    def test_a_PARTIAL_failure_completes_and_names_what_could_not_be_checked(self):
        """The distinction the whole fix rests on: an empty `mx` because MX
        answered with nothing is not an empty `mx` because MX could not be
        asked. The lookups that answered are kept; the ones that did not are
        named."""
        from unittest.mock import MagicMock, patch
        import dns.resolver

        def side_effect(name, rtype):
            if rtype == "A":
                rr = MagicMock()
                rr.rrset.ttl = 300
                rr.__iter__ = lambda self: iter(["93.184.216.34"])
                return rr
            raise Exception("SERVFAIL")

        with patch("app.collectors.dns_collector.dns.resolver.Resolver") as mr:
            inst = MagicMock()
            mr.return_value = inst
            inst.resolve.side_effect = side_effect
            evidence, meta, _ = DNSCollector("example.com", "t-5").run()

        assert meta.status.value == "completed", (
            "one lookup answered, so the run is partial and not failed"
        )
        assert evidence.a == ["93.184.216.34"], "the answer we DID get was lost"
        assert len(evidence.notes) == 6, (
            f"expected a note per unchecked lookup, got {evidence.notes}"
        )
        assert any("MX" in n for n in evidence.notes)
        assert all("SERVFAIL" in n for n in evidence.notes)

    def test_notes_are_per_instance_not_shared(self):
        """`notes: list[str] = []` is a mutable default on a Pydantic model.
        Pydantic deep-copies it, but the assertion is cheap and the failure
        would be every investigation inheriting the last one's notes."""
        from app.models.schemas import DNSEvidence
        a, b = DNSEvidence(), DNSEvidence()
        a.notes.append("x")
        assert b.notes == []
