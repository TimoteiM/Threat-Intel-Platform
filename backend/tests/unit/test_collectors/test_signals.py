"""Tests for signal generation and gap detection."""

import pytest

from app.collectors.signals import generate_signals, detect_data_gaps


class TestGenerateSignals:

    def test_young_domain_signal(self):
        evidence = {"whois": {"domain_age_days": 5}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_very_young_domain" in ids

    def test_30_day_domain_signal(self):
        evidence = {"whois": {"domain_age_days": 14}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_young_domain" in ids

    def test_old_domain_no_age_signal(self):
        evidence = {"whois": {"domain_age_days": 3650}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_very_young_domain" not in ids
        assert "sig_young_domain" not in ids

    def test_privacy_whois_signal(self):
        evidence = {"whois": {"privacy_protected": True}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_whois_privacy" in ids

    def test_self_signed_cert(self):
        evidence = {"tls": {"is_self_signed": True}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_self_signed" in ids

    def test_login_form_signal(self):
        evidence = {"http": {"has_login_form": True, "reachable": True, "security_headers": {}}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_login_form" in ids

    def test_no_dmarc_signal(self):
        evidence = {"dns": {"dmarc": None}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_no_dmarc" in ids

    def test_blocklist_signal(self):
        evidence = {"intel": {"blocklist_hits": [
            {"source": "Spamhaus DBL", "indicator": "evil.com"}
        ]}}
        signals = generate_signals(evidence)
        ids = [s.id for s in signals]
        assert "sig_blocklisted" in ids

    def test_empty_evidence_no_crash(self):
        """Should not crash on completely empty evidence."""
        signals = generate_signals({})
        assert isinstance(signals, list)


class TestDetectDataGaps:

    def test_failed_collector_creates_gap(self):
        evidence = {
            "whois": {"meta": {"status": "failed", "error": "timeout"}},
        }
        gaps = detect_data_gaps(evidence)
        gap_ids = [g.id for g in gaps]
        assert "gap_whois_failed" in gap_ids

    def test_completed_whois_missing_date(self):
        evidence = {
            "whois": {"meta": {"status": "completed"}, "created_date": None},
        }
        gaps = detect_data_gaps(evidence)
        gap_ids = [g.id for g in gaps]
        assert "gap_whois_age" in gap_ids

    def test_no_gaps_on_good_evidence(self):
        evidence = {
            "dns": {"meta": {"status": "completed"}},
            "http": {"meta": {"status": "completed"}, "reachable": True},
            "tls": {"meta": {"status": "completed"}},
            "whois": {"meta": {"status": "completed"}, "created_date": "2020-01-01"},
            "asn": {"meta": {"status": "completed"}},
        }
        gaps = detect_data_gaps(evidence)
        assert len(gaps) == 0

    def test_empty_evidence_no_crash(self):
        gaps = detect_data_gaps({})
        assert isinstance(gaps, list)
