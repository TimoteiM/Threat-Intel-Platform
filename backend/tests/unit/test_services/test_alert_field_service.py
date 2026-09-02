"""
Field extraction, tested against the shapes this deployment actually receives.

Every case here is a body format taken from stored alerts, and three of them are
bugs the first implementation had — found by running it over the real corpus
rather than over examples written to match the parser.
"""

from __future__ import annotations

from app.services.alert_field_service import entity_of, extract_alert_fields

WAZUH_HEADER = """Groups: {0=syslog, 1=errors}
Agent: exprevpxy002 | 1445
Agent IP: 172.20.20.5
Event ID: SystemStatus
Manager: Siembiot

Aug 16 07:29:12 exprevpxy002 docker/appsec-agent[1198]: {"eventTime": "2026-08-16T07:29:11.995","eventName": "Web Request","eventSeverity": "Info","eventPriority": "Low"}
"""

FORWARDED_BY_MANAGER = """Agent: Siembiot | 000
Manager: Siembiot
Event ID: FileActivity
CEF:0|Fortinet|Fortigate|url=http://example.test service=HTTP
"""

CEF_INSIDE_ESCAPED_JSON = (
    '"{\\"approxLogTime\\":1786538630000000,\\"rawLogs\\":'
    '[\\"destinationServiceName=Office 365 dproc=management-general suser=jdoe@corp.com\\"]}"'
)


def test_wazuh_header_block():
    fields = extract_alert_fields(WAZUH_HEADER, rule_id="1002", rule_name="Unknown problem")
    assert fields["agent"] == "exprevpxy002"
    assert fields["agent_ip"] == "172.20.20.5"
    assert fields["manager"] == "Siembiot"
    assert fields["event_name"] == "Web Request"
    assert fields["event_priority"] == "Low"
    assert fields["event_severity"] == "Info"
    assert entity_of(fields) == ("exprevpxy002", None)


def test_the_agent_id_is_kept_not_swallowed_by_the_name():
    """
    The header pattern originally stopped at the pipe, so the id was never seen
    and every forwarded log looked like an endpoint observation.
    """
    fields = extract_alert_fields(WAZUH_HEADER)
    assert fields["agent"] == "exprevpxy002"
    assert fields["agent_id"] == "1445"


def test_a_manager_forwarded_alert_has_no_host_entity():
    """
    Agent 000 is the Wazuh manager. Correlating on it would file every
    forwarded firewall log in the estate under one machine that never saw any
    of them, and a chain built from that is fiction.
    """
    fields = extract_alert_fields(FORWARDED_BY_MANAGER, rule_id="81640")
    assert fields["agent"] == "Siembiot"
    assert fields["agent_id"] == "000"
    host, _user = entity_of(fields)
    assert host is None


def test_key_values_inside_escaped_json_are_found():
    """
    CEF arrives wrapped in escaped JSON here, so the key is preceded by a
    backslash-quote. A whitespace-only boundary matched none of it.
    """
    fields = extract_alert_fields(CEF_INSIDE_ESCAPED_JSON)
    assert fields["service"] == "Office 365"
    assert fields["user"] == "jdoe@corp.com"


def test_rule_columns_win_over_reparsing_the_text():
    """Ingest already resolved these; re-deriving them is a second answer."""
    fields = extract_alert_fields(WAZUH_HEADER, rule_id="9999", rule_name="From the column")
    assert fields["rule_id"] == "9999"
    assert fields["rule_name"] == "From the column"


def test_absent_fields_are_absent_never_guessed():
    """A suppression built on a guessed value silences alerts nobody chose to."""
    fields = extract_alert_fields("a line with nothing identifying in it at all")
    assert "agent" not in fields
    assert "event_priority" not in fields
    assert entity_of(fields) == (None, None)


def test_user_is_carried_as_an_entity():
    """Lateral movement is only visible if a chain can span hosts under a user."""
    fields = extract_alert_fields("Agent: WKS-01 | 12\nsuser=jdoe")
    assert entity_of(fields) == ("WKS-01", "jdoe")


# ── Client and payload kind ──────────────────────────────────────────────────

from app.services.alert_field_service import UNKNOWN_CLIENT, client_of, is_pre_correlated

TRACECAT_INCIDENT = """Alert: mvapsupm01: Notable AA Session
Rule level: medium

client: LIN
entity_id: mvapsupm01
entity_type: asset
event_count: 50
"""

OKTA_JSON = (
    '"displayName":"Someone","detailEntry":null},"client":{"userAgent":'
    '{"rawUserAgent":"Mozilla/5.0"}}'
)


def test_an_incident_names_its_client_and_its_subject():
    fields = extract_alert_fields(TRACECAT_INCIDENT)
    assert client_of(fields) == "LIN"
    assert entity_of(fields)[0] == "mvapsupm01"


def test_an_incident_is_recognised_as_already_a_session():
    """
    It arrives carrying fifty events and their triggered rules. It is a case,
    not a member of one, and grouping it beside single alerts would compare a
    case to its own parts.
    """
    assert is_pre_correlated(extract_alert_fields(TRACECAT_INCIDENT)) is True
    assert is_pre_correlated(extract_alert_fields(WAZUH_HEADER)) is False


def test_a_json_object_is_not_a_client_name():
    """
    Okta payloads carry "client":{"userAgent":...}. Capturing the brace filed 87
    alerts under an organisation called "{" — and correlation partitions on the
    client, so a bogus one is worse than none.
    """
    assert client_of(extract_alert_fields(OKTA_JSON)) == UNKNOWN_CLIENT


def test_wazuh_alerts_carry_no_client_so_the_sender_must_declare_one():
    """
    Nothing in a Wazuh alert says whose estate it is. Left underived, every
    customer would share one partition — so the declaration is the only answer,
    and its absence is explicit rather than guessed.
    """
    fields = extract_alert_fields(WAZUH_HEADER)
    assert client_of(fields) == UNKNOWN_CLIENT
    assert client_of(fields, declared="ACME") == "ACME"
