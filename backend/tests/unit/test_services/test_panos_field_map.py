"""The PAN-OS positional map, tested on the real shapes in the store.

Every line in these tests is a record taken from
`alert_body_investigation_runs`, with the customer's addresses left as they
are — they are RFC1918 and internal, and the point of the tests is the shape.
"""

from __future__ import annotations

from app.services import panos_field_map as pm
from app.services.alert_graph_extraction_service import PANOS_SOURCE, extract
from app.services.source_severity_service import _loudest_of

# A real spyware record: the DNS sinkhole that case #1106 is made of. Note the
# quoted domain and the quoted comma-separated characteristics near the end —
# the two reasons this cannot be split on commas.
SPYWARE = (
    "<12>Sep 17 13:34:24 172.16.23.1 1,2026/09/17 13:34:23,013101014199,THREAT,"
    "spyware,2818,2026/09/17 13:34:20,10.64.4.53,10.14.0.10,0.0.0.0,0.0.0.0,"
    "LEO - DNS NTP DHCP,povgrp\\f0316,,dns-base,vsys1,user-wired,SERVER,ae2.1218,"
    "ae2.1,LogForw,2026/09/17 13:34:21,1096106,1,51448,53,0,0,0x3000,udp,sinkhole,"
    '"www.darmika.be",generic:www.darmika.be(757811880),any,medium,client-to-server,'
    "7679384792193621683,0x8000000000000000,10.0.0.0-10.255.255.255,"
    "10.0.0.0-10.255.255.255,,,0,,,0,,,,,,,,0,437,0,0,0,Ursa-Major_POV_core-FW,"
    "Alpha-UMa,,,,,0,,0,,N/A,dns-malware,AppThreat-9148-10245,0x0,0,4294967295,,,"
    "37970e12-7530-4fd1-9121-02dc15017e1f,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,"
    "2026-09-17T13:34:21.343+02:00,,,,infrastructure,networking,network-protocol,3,"
    '"used-by-malware,has-known-vulnerability,pervasive-use",dns,dns-base,no,no,,,'
    "NonProxyTraffic,,false,0,0,,,,0"
)

# A real vulnerability record. Single-digit day, so the BSD timestamp has two
# spaces and `split(" ", 4)` puts the relay address inside field 1.
VULNERABILITY = (
    "<12>Sep  8 11:50:59 172.16.23.1 1,2026/09/08 11:50:59,013101014199,THREAT,"
    "vulnerability,2818,2026/09/08 11:50:51,10.64.1.99,10.14.0.90,0.0.0.0,0.0.0.0,"
    "LEO DATA to SERVER Catch,povgrp\\i0316,,web-browsing,vsys1,user-wired,SERVER,"
    "ae2.1215,ae2.1,LogForw,2026/09/08 11:50:51,1283283,1,62111,80,0,0,0x0,tcp,"
    "alert,showPresenceWSW.cfm,HTTP Unauthorized Brute Force Attack(40031),"
    "URLCAT-CTP-WHITELIST,high,client-to-server,"
    + ",".join([""] * 22)
    + ",Ursa-Major_POV_core-FW,Alpha-UMa"
    + ",".join([""] * 72)
)


def _threat(record_text: str) -> pm.PanosRecord:
    found = pm.records_of(record_text)
    assert len(found) == 1, found
    return found[0]


class TestFindingTheRecord:
    def test_a_single_digit_day_does_not_shift_the_positions(self):
        """`Sep  8` has two spaces. The header is stripped by pattern because
        counting spaces puts the relay address into a data field."""
        record = _threat(VULNERABILITY)
        assert record.get("receive_time") == "2026/09/08 11:50:59"
        assert record.get("src_ip") == "10.64.1.99"
        assert record.get("severity") == "high"

    def test_a_quoted_comma_does_not_split_a_field(self):
        """197 of 199 sampled records carry one of these. `split(",")` reads
        `used-by-malware` as a field of its own and every later position
        shifts."""
        record = _threat(SPYWARE)
        assert record.get("misc") == "www.darmika.be"
        assert record.get("threat_name") == "generic:www.darmika.be(757811880)"
        assert record.get("severity") == "medium"

    def test_several_records_in_one_body_are_all_found(self):
        """A run holds 1 to 14 records; 149 of 224 hold more than one."""
        found = pm.records_of(SPYWARE + "\n" + VULNERABILITY)
        assert [r.get("subtype") for r in found] == ["spyware", "vulnerability"]

    def test_a_record_inside_a_json_envelope_is_unescaped(self):
        """One run wraps its record in `{"rawLogs": [...]}`, serialised into a
        JSON string, so the record is escaped twice. One pass left
        `povgrp\\\\f0316`, which the account guard correctly called a path."""
        envelope = (
            '— 13:47:18 | "{\\"rawLogs\\":[\\"'
            + SPYWARE.replace("\\", "\\\\\\\\").replace('"', '\\\\\\"')
            + '\\"],\\"subject\\":\\"vpn\\"}"'
        )
        found = pm.records_of(envelope)
        assert found and found[0].readable, [r.problem for r in found]
        assert found[0].get("src_user") == "povgrp\\f0316"
        assert found[0].get("misc") == "www.darmika.be"


class TestQuarantineNeverDrop:
    def test_globalprotect_is_named_not_guessed_at(self):
        """51 positions, a different layout. Reading field 35 as a severity
        there invents one, so the record is kept and labelled instead."""
        line = (
            "<14>Sep 25 10:28:01 172.16.23.1 1,2026/09/25 10:28:00,013101014199,"
            "GLOBALPROTECT,0,2818,2026/09/25 10:27:54,vsys1,portal-auth,login,saml,,"
            "someone@example.be,BE,NBI0607,193.190.147.2" + ",".join([""] * 35)
        )
        record = _threat(line)
        assert not record.readable
        assert "GLOBALPROTECT" in (record.problem or "")
        assert record.raw, "the record is kept, not dropped"

    def test_an_unexpected_width_is_not_read_at_the_threat_positions(self):
        truncated = SPYWARE[: SPYWARE.index("client-to-server")]
        record = _threat(truncated)
        assert not record.readable
        assert "131 fields" in (record.problem or "")


class TestSeverity:
    def test_the_named_grade_is_read(self):
        signals = pm.severity_signals([_threat(VULNERABILITY)])
        assert signals == [(86, "panos.severity=high")]

    def test_loudest_wins_across_the_records_in_one_body(self):
        """A body holds up to 14 records and they disagree. Taking the first
        would make severity depend on syslog ordering."""
        found = pm.records_of(VULNERABILITY + "\n" + SPYWARE)
        score, raw = _loudest_of(pm.severity_signals(found))
        assert score == 86
        assert raw == "panos.severity=high (also panos.severity=medium)"

    def test_repeated_gradings_are_stated_once(self):
        """Ten records saying `medium` is one grading. Undeduplicated this
        reached 252 characters against a column of 96."""
        found = pm.records_of("\n".join([SPYWARE] * 10))
        _score, raw = _loudest_of(pm.severity_signals(found))
        assert raw == "panos.severity=medium"

    def test_globalprotect_only_is_unrated_rather_than_low(self):
        line = (
            "<14>Sep 25 10:28:01 172.16.23.1 1,2026/09/25 10:28:00,013101014199,"
            "GLOBALPROTECT,0,2818,2026/09/25 10:27:54,vsys1" + ",".join([""] * 42)
        )
        assert pm.severity_signals(pm.records_of(line)) == []


class TestMiscIsThreeDifferentThings:
    def test_spyware_names_a_domain(self):
        assert pm.misc_kind(_threat(SPYWARE)) == "domain"

    def test_vulnerability_names_a_resource_not_a_file_on_disk(self):
        """`showPresenceWSW.cfm` is a page on the server. Sniffing the suffix
        reads it as a file and puts a web page on an endpoint's disk."""
        assert pm.misc_kind(_threat(VULNERABILITY)) == "url"

    def test_an_unmapped_subtype_yields_nothing_rather_than_a_guess(self):
        record = pm.PanosRecord(kind="THREAT", fields={"subtype": "tunnel", "misc": "x"})
        assert pm.misc_kind(record) is None


class TestThroughTheExtractor:
    def test_the_source_is_named_as_a_field_map_not_a_transport(self):
        found = extract(SPYWARE)
        assert found.source_type == PANOS_SOURCE
        assert found.mapped is True

    def test_the_sinkholed_domain_the_true_positive_turns_on(self):
        found = extract(SPYWARE)
        kinds = {e.kind for e in found.entities}
        assert {"ip", "account", "domain"} <= kinds
        domain = next(e for e in found.entities if e.kind == "domain")
        assert domain.merge_key == "domain:www.darmika.be"
        assert found.source_severity == 57

    def test_the_user_id_binding_is_an_edge_not_a_relabelled_address(self):
        found = extract(VULNERABILITY)
        edge = next(e for e in found.edges if e.kind == "attributed_to")
        assert edge.source == "ip:10.64.1.99"
        assert edge.target == "account:povgrp\\i0316"
        assert edge.status == "corroborated"

    def test_the_resource_is_keyed_with_the_server_that_served_it(self):
        """The same page name on two servers is two resources, and 249 of 580
        records name `showPresenceWSW.cfm`."""
        found = extract(VULNERABILITY)
        url = next(e for e in found.entities if e.kind == "url")
        assert url.merge_key == "url:10.14.0.90/showpresencewsw.cfm"

    def test_the_firewall_does_not_become_a_hub_node(self):
        """It reported 718 of the 734 records in the store, so a node for it
        joins every node in every PAN-OS case to one centre."""
        found = extract(SPYWARE + "\n" + VULNERABILITY)
        labels = {e.label for e in found.entities}
        assert "Alpha-UMa" not in labels
        edge = next(e for e in found.edges if e.kind == "connected_to")
        assert edge.attrs.get("reported_by") == "Alpha-UMa"

    def test_the_two_records_share_their_destination_rather_than_duplicating(self):
        found = extract(SPYWARE + "\n" + VULNERABILITY)
        addresses = [e.merge_key for e in found.entities if e.kind == "ip"]
        assert len(addresses) == len(set(addresses))

    def test_an_unreadable_record_is_drawn_as_unparsed(self):
        line = (
            "<14>Sep 25 10:28:01 172.16.23.1 1,2026/09/25 10:28:00,013101014199,"
            "GLOBALPROTECT,0,2818,2026/09/25 10:27:54,vsys1" + ",".join([""] * 42)
        )
        found = extract(line)
        assert [e.kind for e in found.entities] == ["unparsed"]
        assert found.quarantined and "GLOBALPROTECT" in found.quarantined[0]["why"]


# A real CEF record from the same firewall. 91 of the 95 CEF records in the
# store are this URL-filtering shape.
CEF_URL = (
    "<14>Sep 17 13:36:22 172.16.23.1 CEF:0|Palo Alto Networks|PAN-OS|11.2.10-h7|"
    "url|THREAT|1|rt=Sep 17 2026 11:36:21 GMT deviceExternalId=013101014199 "
    "src=10.64.4.53 dst=18.235.223.241 cs1Label=Rule cs1=LEO to UNTRUST - WEB "
    "suser=povgrp\\f0316 duser= app=ssl cs4Label=Source Zone cs4=user-wired "
    "cs5Label=Destination Zone cs5=TRANSIT-CP spt=50861 dpt=443 proto=tcp "
    'act=alert request="qvdt3feo.com/" cs2Label=URL Category '
    "cs2=content-delivery-networks cat=9999(9999) dvchost=Alpha-UMa"
)


class TestCefIsReadByKeyNotByPosition:
    def test_a_value_containing_spaces_runs_to_the_next_key(self):
        """`cs1=LEO to UNTRUST - WEB` is one value. Splitting on whitespace
        reads `to`, `UNTRUST` and `WEB` as keys that do not exist."""
        record = pm.records_of(CEF_URL)[0]
        assert record.get("rule") == "LEO to UNTRUST - WEB"
        assert record.get("application") == "ssl"

    def test_a_url_category_is_not_presented_as_a_detection(self):
        """`cat` is `9999(9999)` on all 91 of these — the URL-filtering
        placeholder, with `PanOSThreatCategory=N/A` beside it. So the record
        states no signature, and the first version of this map put
        `content-delivery-networks` in `threat`, which an analyst reads as the
        name of what was caught."""
        record = pm.records_of(CEF_URL)[0]
        assert record.get("threat_name") == ""
        assert record.get("category") == "content-delivery-networks"
        name, signature = pm.threat_id(record)
        assert (name, signature) == ("", None)

        found = extract(CEF_URL)
        edge = next(e for e in found.edges if e.kind == "connected_to")
        assert "threat" not in edge.attrs
        assert edge.attrs["url_category"] == "content-delivery-networks"

    def test_the_quoted_request_loses_its_quoting(self):
        record = pm.records_of(CEF_URL)[0]
        assert pm.misc_value(record) == "qvdt3feo.com/"
        assert pm.misc_kind(record) == "domain"

    def test_cef_severity_is_read_from_the_header(self):
        assert pm.severity_signals(pm.records_of(CEF_URL)) == [(10, "cef.severity=1/10")]
