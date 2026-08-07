"""
Accepting a SIEM alert document as the request body.

The sample mirrors what Wazuh/OpenSearch posts: flattened dotted keys, the raw
Sysmon text in `data.win.system.message`, and a `_source` field that repeats the
entire document.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import alert_payload_service as svc

MESSAGE = (
    '"Process Create:\r\nRuleName: -\r\nUtcTime: 2026-08-04 14:28:29.045\r\n'
    "ProcessId: 22636\r\nImage: C:\\Program Files\\Git\\usr\\bin\\bash.exe\r\n"
    "CommandLine: bash.exe -c \"powershell -NoProfile -Command whoami\"\r\n"
    "User: INT\\tradoi\r\nIntegrityLevel: Medium\r\n"
    "Hashes: SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B\r\n"
    'ParentImage: C:\\Program Files\\Git\\usr\\bin\\bash.exe"'
)

WAZUH_ALERT = {
    "_id": "fWMtzZ8BGK5kUh3TKZB2",
    "_index": "wazuh-alerts-4.x-2026.08.04",
    "title": "EXP-D0MY264 - Possible Remote Lateral Movement Activity",
    "severity": "2",
    "agent.name": "EXP-D0MY264",
    "agent.ip": "192.168.50.129",
    "data.win.system.computer": "EXP-D0MY264.int.expertware.net",
    "data.win.system.eventID": "1",
    "data.win.system.message": MESSAGE,
    "data.win.eventdata.image": "C:\\\\Program Files\\\\Git\\\\usr\\\\bin\\\\bash.exe",
    "manager.name": "Siembiot",
    "rule.description": "Remote execution command — possible lateral movement",
    "rule.id": "110145",
    "rule.level": "10",
    "rule.mitre.id": "{0=T1021.006}",
    "rule.mitre.tactic": "{0=Lateral Movement}",
    "timestamp": "2026-08-04T14:28:30.004+0000",
    "_source": "{the whole document repeated}",
}


def test_a_wazuh_document_is_recognised_as_someone_elses_alert():
    assert svc.looks_like_siem_alert(WAZUH_ALERT) is True
    # Our own request shape must be left alone.
    assert svc.looks_like_siem_alert({"alert_body": "text", "title": "x"}) is False
    assert svc.looks_like_siem_alert("plain text") is False


def test_the_alert_document_becomes_a_readable_body():
    result = svc.normalize_alert_payload(WAZUH_ALERT)
    body = result["alert_body"]

    assert result["title"] == "EXP-D0MY264 - Possible Remote Lateral Movement Activity"
    assert result["external_ref"] == "fWMtzZ8BGK5kUh3TKZB2"
    # Header: what fired, where, when.
    assert "Rule: 110145" in body
    assert "MITRE: {0=T1021.006} | {0=Lateral Movement}" in body
    assert "Agent IP: 192.168.50.129" in body
    assert "Computer: EXP-D0MY264.int.expertware.net" in body
    # The Sysmon message is passed through with real line breaks so the event
    # parser sees an event, not two literal characters.
    assert "\nProcess Create:" in body
    assert "\\r\\n" not in body
    assert "ProcessId: 22636" in body


def test_the_source_duplicate_is_left_out():
    """`_source` repeats the whole document — including it doubles everything."""
    body = svc.normalize_alert_payload(WAZUH_ALERT)["alert_body"]
    assert "the whole document repeated" not in body
    assert "_index" not in body


def test_nested_documents_flatten_the_same_way():
    nested = {
        "title": "Nested shipper",
        "rule": {"id": "110145", "description": "Remote execution command"},
        "agent": {"name": "EXP-D0MY264", "ip": "192.168.50.129"},
        "data": {"win": {"system": {"message": MESSAGE, "computer": "host.expertware.net"}}},
    }
    body = svc.normalize_alert_payload(nested)["alert_body"]

    assert "Rule: 110145" in body
    assert "Agent IP: 192.168.50.129" in body
    assert "Computer: host.expertware.net" in body
    assert "Process Create:" in body


def test_a_document_without_any_message_still_yields_its_fields():
    body = svc.normalize_alert_payload(
        {"title": "Odd alert", "some.field": "value", "src_ip": "8.8.8.8"}
    )["alert_body"]
    assert "Alert: Odd alert" in body
    assert "src_ip: 8.8.8.8" in body


def test_a_plain_string_is_already_an_alert_body():
    result = svc.normalize_alert_payload("User clicked https://evil.com")
    assert result["alert_body"] == "User clicked https://evil.com"
    assert result["title"] is None
