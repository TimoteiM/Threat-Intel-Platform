"""Who named the technique: the rule, the evidence, or both.

Corroboration was a boolean and collapsed two independent statements into one.
Measured on `alert_body_investigation_runs.result_attack_assessment`,
2026-10-12: 16,531 assessments, 768 with any supporting evidence (684
production, 84 rig), of which **41 confirmed a technique the rule had claimed
and 727 found evidence for one the rule had not**. So the scarcity is the
intersection, not the evidence and not the test rig.
"""

from __future__ import annotations

from app.services.technique_attribution_service import (
    BOTH,
    MODEL_ONLY,
    RULE_ONLY,
    Attribution,
    attribute,
    corroborated_ids,
)


def _assessment(claimed=(), additional=()):
    return {
        "techniques": [
            {"id": tid, "status": status} for tid, status in claimed
        ],
        "additional_techniques": [
            {"id": tid, "status": status} for tid, status in additional
        ],
    }


class TestTheFourStates:
    def test_both_is_the_only_corroboration(self):
        found = attribute(
            _assessment(claimed=[("T1055", "confirmed")]), rule_ids=["T1055"]
        )
        assert found.of("T1055") == BOTH
        assert found.corroborated() == ["T1055"]

    def test_a_rule_claim_with_nothing_behind_it(self):
        found = attribute(
            _assessment(claimed=[("T1129", "not_corroborated")]), rule_ids=["T1129"]
        )
        assert found.of("T1129") == RULE_ONLY
        assert found.corroborated() == []

    def test_evidence_with_no_rule_is_drawn_and_is_not_corroboration(self):
        """727 of the 768 alerts with evidence are this, and the graph could
        not see one of them."""
        found = attribute(_assessment(additional=[("T1036", "additional")]))
        assert found.of("T1036") == MODEL_ONLY
        assert found.model_only() == ["T1036"]
        assert found.corroborated() == [], "model-only must never count as corroborated"

    def test_an_ai_proposal_is_not_the_telemetry_speaking(self):
        """`assess_attack` keeps AI proposals out of `confirmed_count`; they
        ride in the same list with a different status and must not become a
        model-only finding."""
        found = attribute(_assessment(additional=[("T1486", "ai_suggested")]))
        assert found.of("T1486") is None
        assert found.model_only() == []


class TestTheDisagreement:
    def test_both_sides_are_named(self):
        found = attribute(
            _assessment(
                claimed=[("T1129", "not_corroborated")],
                additional=[("T1036", "additional")],
            ),
            rule_ids=["T1129"],
        )
        assert found.disagreement == (("T1129",), ("T1036",))
        assert found.of("T1129") == RULE_ONLY
        assert found.of("T1036") == MODEL_ONLY

    def test_it_is_one_per_alert_not_a_cross_product(self):
        """Rule 81640 asserts five techniques against one piece of evidence.
        Pairing each with each turned one alert into five disagreements, and
        the tell was the same count repeated five times in the output."""
        found = attribute(
            _assessment(
                claimed=[(t, "not_corroborated") for t in
                         ("T1046", "T1071", "T1082", "T1218", "T1218.011")],
                additional=[("T1059", "additional")],
            ),
            rule_ids=["T1046", "T1071", "T1082", "T1218", "T1218.011"],
        )
        claimed, supported = found.disagreement
        assert len(claimed) == 5 and len(supported) == 1
        assert found.as_json()["disagreement"]["evidence_supports"] == ["T1059"]

    def test_agreement_is_not_a_disagreement(self):
        found = attribute(
            _assessment(claimed=[("T1055", "confirmed")]), rule_ids=["T1055"]
        )
        assert found.disagreement is None

    def test_a_rule_with_no_evidence_at_all_is_not_a_disagreement(self):
        found = attribute(
            _assessment(claimed=[("T1129", "not_corroborated")]), rule_ids=["T1129"]
        )
        assert found.disagreement is None


class TestOneDefinitionForEveryConsumer:
    def test_corroborated_ids_is_both_only(self):
        a = _assessment(
            claimed=[("T1055", "confirmed"), ("T1129", "not_corroborated")],
            additional=[("T1036", "additional")],
        )
        assert corroborated_ids(a, rule_ids=["T1055", "T1129"]) == ["T1055"]

    def test_the_store_service_delegates_rather_than_computing(self):
        """`confirmed_ids` read `techniques[]` alone while
        `alert_correlation_service` also read `additional_techniques` — one
        column with two meanings depending on who asked."""
        from app.services.alert_graph_store_service import confirmed_ids, model_only_ids

        a = _assessment(
            claimed=[("T1055", "confirmed")],
            additional=[("T1036", "additional")],
        )
        assert confirmed_ids(a) == ["T1055"]
        assert model_only_ids(a) == ["T1036"]

    def test_a_json_string_assessment_is_read_the_same_way(self):
        import json

        a = _assessment(claimed=[("T1055", "confirmed")])
        assert corroborated_ids(json.dumps(a), rule_ids=["T1055"]) == ["T1055"]

    def test_malformed_input_yields_nothing_rather_than_raising(self):
        for bad in (None, "not json", {"techniques": "nope"}, 7):
            assert attribute(bad).corroborated() == []


class TestTheGraphDrawsAllFour:
    def test_a_model_only_technique_becomes_a_node_marked_as_such(self):
        from app.services.alert_graph_extraction_service import extract

        body = "\n".join([
            "Alert: EXP-FIN-034 - something fired",
            "Rule: 100210",
            "Rule level: 12",
            "Agent: EXP-FIN-034 | 1634",
            "Decoder: windows_eventchannel",
            "MITRE: {0=T1129}",
        ])
        found = extract(body, model_only_techniques=["T1036"])
        techniques = {
            e.attrs.get("id"): e.attrs.get("named_by")
            for e in found.entities if e.kind == "technique"
        }
        assert techniques.get("T1129") == RULE_ONLY
        assert techniques.get("T1036") == MODEL_ONLY

    def test_a_model_only_technique_is_never_observed(self):
        from app.services.alert_graph_extraction_service import INFERRED, extract

        found = extract(
            "Alert: x\nRule: 1\nAgent: HOST-1 | 1\nDecoder: windows_eventchannel",
            model_only_techniques=["T1036"],
        )
        node = next(e for e in found.entities if e.kind == "technique")
        assert node.basis == INFERRED
        assert node.status == "claimed"

    def test_a_confirmed_rule_technique_is_marked_both(self):
        from app.services.alert_graph_extraction_service import OBSERVED, extract

        body = "\n".join([
            "Alert: x", "Rule: 1", "Agent: HOST-1 | 1",
            "Decoder: windows_eventchannel", "MITRE: {0=T1055}",
        ])
        found = extract(body, confirmed_techniques=["T1055"])
        node = next(e for e in found.entities if e.kind == "technique")
        assert node.basis == OBSERVED
        assert node.attrs.get("named_by") == BOTH
