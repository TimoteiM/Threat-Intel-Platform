"""A pasted SIEM document must not lose its rule.

Correlation counts *distinct* detection rules and discards empty ones, so a run
with no rule id can never join a case however well it scores on every other
axis. Eight alerts of a simulated intrusion on EXP-FIN-034 — correct host,
correct event times, eight tactics in forward order — correlated with nothing
because the rule sat at `rule.id` in nested JSON and only the flat `Rule:`
header was being read.
"""

from __future__ import annotations

import json

from app.api.alert_investigations import rule_from_pasted_body

WAZUH_ALERT = {
    "timestamp": "2026-08-16T09:02:44.512+0000",
    "rule": {
        "id": "100210",
        "level": 12,
        "description": "Microsoft Office application spawned a command interpreter",
        "mitre": {"tactic": ["Initial Access"]},
    },
    "agent": {"id": "034", "name": "EXP-FIN-034", "ip": "10.20.14.34"},
    "manager": {"name": "wazuh-mgr-01"},
    "data": {"win": {"system": {"computer": "EXP-FIN-034.corp.local"}}},
}


def test_a_nested_wazuh_rule_is_recovered():
    found = rule_from_pasted_body(json.dumps(WAZUH_ALERT))
    assert found["detection_rule_id"] == "100210"
    assert "command interpreter" in (found["detection_rule_name"] or "")


def test_plain_text_yields_nothing_rather_than_guessing():
    assert rule_from_pasted_body("Alert: something happened\nRule: 110400") == {}


def test_malformed_json_is_not_an_error():
    assert rule_from_pasted_body('{"rule": {"id": ') == {}


def test_an_empty_body_is_not_an_error():
    assert rule_from_pasted_body("") == {}
    assert rule_from_pasted_body("   ") == {}


def test_a_json_document_that_is_not_an_alert_is_ignored():
    """Random JSON must not be mined for anything that looks like a rule."""
    assert rule_from_pasted_body('{"hello": "world", "n": 3}') == {}


def test_a_json_list_is_ignored():
    assert rule_from_pasted_body('[{"rule": {"id": "1"}}]') == {}
