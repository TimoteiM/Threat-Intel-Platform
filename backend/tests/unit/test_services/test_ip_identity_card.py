"""
The identity card needs data, not just an instruction.

The prompt asks for a public IP to be introduced as "(ISP: ..., Usage Type: ...)"
and for that to outrank abuse statistics. AbuseIPDB carries those fields in the
finding's data, but only the summary line reached the model — and that line is
"Abuse confidence 100% from 584 report(s)", exactly the statistic the report is
meant to lead away from. Without this the rule is unenforceable.
"""

from __future__ import annotations

from app.services.alert_indicator_summary_service import _describe


def _report(**abuse):
    return {
        "indicator": {"value": "185.220.101.34", "type": "ip"},
        "verdict": {"classification": "suspicious", "risk_score": 60},
        "findings": [{
            "source": "AbuseIPDB", "collector": "threat_feeds", "type": "reputation",
            "summary": "Abuse confidence 100% from 584 report(s)",
            "data": {"abuse_confidence_score": 100, "total_reports": 584, **abuse},
        }],
    }


def test_identity_card_leads_the_line():
    entry = _describe(_report(isp="Foo Telecom", usage_type="Data Center/Web Hosting/Transit",
                              country_code="DE"))
    line = entry["line"]
    assert "ISP: Foo Telecom" in line
    assert "Usage Type: Data Center/Web Hosting/Transit" in line
    assert "Country: DE" in line
    # Ahead of the abuse statistics, so the address is introduced by what it is.
    assert line.index("ISP: Foo Telecom") < line.index("Abuse confidence")


def test_a_tor_exit_is_named_as_one():
    entry = _describe(_report(isp="Foo Telecom", usage_type="Data Center/Web Hosting/Transit",
                              is_tor=True))
    assert "known Tor exit" in entry["line"]
    assert entry["is_tor"] is True


def test_enrichment_fields_are_available_as_facts():
    entry = _describe(_report(isp="Akamai", usage_type="Content Delivery Network"))
    assert entry["isp"] == "Akamai"
    assert entry["usage_type"] == "Content Delivery Network"


def test_no_card_when_there_is_no_enrichment():
    """No invented ISP: absent enrichment must leave the line as it was."""
    entry = _describe(_report())
    assert "ISP:" not in entry["line"]
    assert "Abuse confidence" in entry["line"]


def test_non_ip_indicators_are_untouched():
    report = {
        "indicator": {"value": "evil.test", "type": "domain"},
        "verdict": {"classification": "suspicious", "risk_score": 60},
        "findings": [{
            "source": "AbuseIPDB", "collector": "threat_feeds", "type": "reputation",
            "summary": "Abuse confidence 100% from 584 report(s)",
            "data": {"isp": "Foo", "usage_type": "Data Center"},
        }],
    }
    assert "ISP:" not in _describe(report)["line"]
