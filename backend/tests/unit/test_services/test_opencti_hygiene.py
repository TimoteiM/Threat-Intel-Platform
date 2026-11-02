from __future__ import annotations

from app.services import risk_aggregator
from app.services.alert_finding_builder import _opencti_findings
from app.services.opencti_hygiene import is_hygiene_match


# Shapes taken from records this deployment actually stored.
GOOGLE_DNS = {
    "found": True, "score": 90, "observable_entity_type": "IPv4-Addr",
    # Real threat labels sit next to the hygiene label: malware genuinely does
    # resolve against 8.8.8.8. Overriding them is the point of the label.
    "labels": ["apt27", "darkcomet", "hygiene", "njrat", "tlp:amber"],
    "indicators": [{"name": "[ipv4-addr:value = '8.8.8.8']"}],
    "malware_families": [{"name": "njrat"}],
}
EXAMPLE_COM = {
    "found": True, "score": 80, "observable_entity_type": "Domain-Name",
    "labels": ["hygiene"],
    "indicators": [{"name": "[domain-name:value = 'example.com']"}],
}
REAL_THREAT = {
    "found": True, "score": 80, "observable_entity_type": "Domain-Name",
    "labels": ["cobalt strike", "tlp:white"],
    "indicators": [{"name": "[domain-name:value = 'evil.test']"}],
    "malware_families": [{"name": "cobalt strike"}],
}


def test_hygiene_label_is_recognised():
    assert is_hygiene_match(EXAMPLE_COM) is True
    assert is_hygiene_match(GOOGLE_DNS) is True
    assert is_hygiene_match(REAL_THREAT) is False
    assert is_hygiene_match({"found": True, "score": 90}) is False
    assert is_hygiene_match(None) is False


def test_hygiene_parent_counts_too():
    assert is_hygiene_match({"labels": ["hygiene_parent"]}) is True


def test_threat_labels_do_not_cancel_the_hygiene_label():
    """
    The tempting rule — "hygiene only counts when nothing else is flagged" —
    gets it backwards. Threat labels beside a hygiene label are the normal case
    for shared infrastructure, and overriding them is what the label is for.
    """
    assert is_hygiene_match(GOOGLE_DNS) is True


def test_hygiene_finding_is_reported_as_context_not_severity():
    finding = _opencti_findings(EXAMPLE_COM)[0]
    assert finding["severity"] == "info"
    assert "hygiene" in finding["summary"].lower()


def test_a_real_opencti_hit_is_still_high():
    """The fix must not blind the platform to genuine OpenCTI intelligence."""
    finding = _opencti_findings(REAL_THREAT)[0]
    assert finding["severity"] == "high"


def test_hygiene_contributes_no_aggregate_score():
    assert risk_aggregator._opencti_score({"opencti": GOOGLE_DNS}) == 0.0
    assert risk_aggregator._opencti_score({"opencti": REAL_THREAT}) > 0.0


def test_hygiene_gets_no_risk_floor():
    """
    The floor is the harshest path: 70 forces suspicious no matter what every
    other collector found.
    """
    assert risk_aggregator._opencti_risk_floor({"opencti": GOOGLE_DNS}) == 0

    # A real hit still gets its floor. 35 rather than 70 here is correct: the
    # top floor wants score >= 85, or >= 75 with two kinds of context, and this
    # fixture has one (malware_families) at score 80.
    assert risk_aggregator._opencti_risk_floor({"opencti": REAL_THREAT}) == 35

    strong = {**REAL_THREAT, "score": 90, "threat_actors": [{"name": "apt29"}]}
    assert risk_aggregator._opencti_risk_floor({"opencti": strong}) == 70
    # ...and the same strong hit is still discarded once it is hygiene-labelled.
    assert risk_aggregator._opencti_risk_floor(
        {"opencti": {**strong, "labels": [*strong["labels"], "hygiene"]}}
    ) == 0
