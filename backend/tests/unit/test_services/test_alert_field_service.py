"""
Field extraction, tested against the shapes this deployment actually receives.

Every case here is a body format taken from stored alerts, and three of them are
bugs the first implementation had — found by running it over the real corpus
rather than over examples written to match the parser.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services import alert_field_service as afs
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


# ── A device category is not a hostname ──────────────────────────────────────

from app.services.alert_field_service import looks_like_host

OKTA_CEF = (
    "deviceNtDomain=Windows 11 dhost=Antwerp dproc=logs dvchost=Personal computer "
    "duser=tonny@corp.test end=1787643684201"
)


def test_a_device_category_is_not_an_entity():
    """
    This feed puts "dvchost=Personal computer" and "dvchost=Smartphone" in the
    CEF field reserved for a device hostname. Correlation groups on the host, so
    accepting those filed 52 alerts under one entity called "Smartphone" —
    exactly the fabricated grouping the partitions exist to prevent.
    """
    host, _user = entity_of(extract_alert_fields(OKTA_CEF))
    assert host is None


def test_a_hostname_cannot_contain_whitespace():
    """DNS and NetBIOS names cannot, so a space means it is a description."""
    assert looks_like_host("Personal computer") is False
    assert looks_like_host("EXP-D0MY264") is True
    assert looks_like_host("wm-c00.siembiot.int") is True


def test_bare_category_words_are_rejected():
    for category in ("Unknown", "Smartphone", "smartphone", "Tablet", "iPhone", "server"):
        assert looks_like_host(category) is False, category


def test_real_names_that_resemble_words_are_kept():
    """Alpha-UMa is a machine on this estate, not a category."""
    for name in ("Alpha-UMa", "ExpDC001", "exprevpxy002", "EXPSQL402"):
        assert looks_like_host(name) is True, name


def test_the_user_is_unaffected_by_the_host_rule():
    """A person's name legitimately contains a space; a machine's does not."""
    fields = extract_alert_fields(OKTA_CEF)
    assert entity_of(fields)[1] == "tonny@corp.test"


# --- the account that ran the command ----------------------------------------
#
# Reported as "case #1058 did not mention which user executed the cmd but the
# alert says that". It said so twice, in two forms the extractor never tried.
# Three separate defects, each pinned below.

def test_the_account_is_read_from_the_header_form():
    """A Sysmon process-creation alert writes `User:` on its own line.

    Every other identity field in `extract_alert_fields` passes a header label
    — "Agent IP", "Manager", "Rule" — and the account passed None, so only
    `user=` and `"user":` were ever tried. Measured over 14,906 stored runs,
    3,511 carried an account the extractor could not see, against 344 that
    had one.
    """
    fields = afs.extract_alert_fields("Agent: EXP-BSFX014\nUser: INT\\echelarasu\n")
    assert afs.entity_of(fields)[1] == "INT\\echelarasu"


def test_the_account_is_read_from_the_flattened_form():
    """Wazuh's flattened block: a dotted path, unquoted, colon-separated.

    `_KV` needs an `=` and `_JSON` needs the key quoted, so neither can see
    `data.win.eventdata.user: ...`.
    """
    fields = afs.extract_alert_fields("data.win.eventdata.user: INT\\\\echelarasu\n")
    assert afs.entity_of(fields)[1] == "INT\\echelarasu"


def test_a_lone_backslash_does_not_end_the_account():
    """The defect that fabricated links between different people.

    `suser=CORP\\jdoe` yielded `CORP` — the domain — because the value's
    terminator treated any backslash as the end. On one host that collapsed
    30 distinct people into a single account called `povgrp`, and correlation
    links on this value, so a case there asserted that one person did all of
    it.

    The `\\"` that closes CEF embedded in escaped JSON must still terminate,
    which is what the terminator was there for.
    """
    assert afs.entity_of(afs.extract_alert_fields('suser=CORP\\jdoe dproc=x'))[1] == "CORP\\jdoe"
    assert afs.entity_of(afs.extract_alert_fields('duser=INT\\echelarasu act=block'))[1] == "INT\\echelarasu"
    # The escaped-quote terminator still works: CEF inside escaped JSON.
    assert afs.entity_of(
        afs.extract_alert_fields('\\"suser=CORP\\jdoe\\" next=1')
    )[1] == "CORP\\jdoe"


def test_the_parent_process_account_is_not_mistaken_for_the_account():
    """A Sysmon alert carries both. The parent's account is not who ran the
    command, and the header is anchored at line start so `ParentUser:` cannot
    satisfy it."""
    fields = afs.extract_alert_fields("ParentUser: INT\\someone_else\n")
    assert afs.entity_of(fields)[1] is None


def test_one_account_has_one_spelling():
    """The flattened block is JSON printed rather than parsed, so it doubles
    the separator. Stored as-is, one person is several accounts — and
    correlation links on this value, so their activity splits."""
    assert afs._clean_user("INT\\\\echelarasu") == "INT\\echelarasu"
    assert afs._clean_user("INT\\echelarasu") == "INT\\echelarasu"
    assert afs._clean_user('  "jdoe"  ') == "jdoe"
    assert afs._clean_user("USER,") == "USER"


def test_a_domain_with_no_account_names_nobody():
    """`CORP\\` and a lone separator would group every alert in the domain
    under one subject. So would the literal strings senders use for absence."""
    for nobody in ("CORP\\", "\\", "", "   ", "-", "N/A", "unknown", None):
        assert afs._clean_user(nobody) is None, nobody


def test_the_dotted_form_is_opt_in_per_field():
    """Measured blast radius, pinned.

    Switched on for every key at once, the flattened form gave 3,511 alerts
    their account and also gave 11,374 of them an `event_name` of "Account
    Manipulation, Valid Accounts" — a MITRE technique list, read as an event
    name because some dotted path ends in `.name`. `event_name` is offered as
    a suppression criterion, so analysts would have built exclusions on it.
    """
    import inspect

    assert "dotted" in inspect.signature(afs._field).parameters
    assert inspect.signature(afs._field).parameters["dotted"].default is False
    # The account asks for it; nothing else does yet. It is asked for in
    # `_account_of`, which is the only place that reads the flattened block.
    assert "dotted=True" not in inspect.getsource(afs.extract_alert_fields)
    account_source = inspect.getsource(afs._account_of)
    assert account_source.count("dotted=True") == 3, "the three account fields, and nothing else"


# --- a host whose clock is ahead of the manager that reports it --------------

def test_a_host_clock_ahead_of_the_alert_is_refused():
    """Reported as "how is the displayed activity in the future?".

    The far-future guard is two days, so a host ten hours fast sailed through
    it — and the alert says plainly that it is fast:

        Time: 2026-10-08T09:15:26.531+0000
        data.win.system.systemTime: 2026-10-08T13:07:39.294706900Z

    Both explicitly UTC, so nothing is mis-parsed. The Windows host is simply
    3h52m ahead of the Wazuh manager. Taken at face value that put a case in
    the future, where a window measured from it could never elapse.
    """
    body = (
        "Time: 2026-10-08T09:15:26.531+0000\n"
        "Agent: SERVER01\n"
        "data.win.system.systemTime: 2026-10-08T13:07:39.294706900Z\n"
    )
    chosen = afs.event_time_of(body)
    assert chosen is not None
    # The manager's own stamp, not the host's.
    assert chosen.hour == 9
    assert chosen < datetime(2026, 10, 8, 9, 16, tzinfo=timezone.utc)


def test_a_host_clock_behind_the_manager_is_believed():
    """Which is the normal case: an event happens, and some time later an
    alert about it is written. Only the other direction is impossible."""
    body = (
        "Time: 2026-10-08T09:15:26.531+0000\n"
        "data.win.system.systemTime: 2026-10-08T09:10:00.000Z\n"
    )
    chosen = afs.event_time_of(body)
    assert chosen == datetime(2026, 10, 8, 9, 10, tzinfo=timezone.utc)


def test_a_few_seconds_of_skew_is_tolerated():
    """Propagation and rounding are seconds. The guard must not fire on them,
    or every alert would be restamped and the host's own clock — which is the
    more precise source — would never be used."""
    body = (
        "Time: 2026-10-08T09:15:00.000+0000\n"
        "data.win.system.systemTime: 2026-10-08T09:15:30.000Z\n"
    )
    assert afs.event_time_of(body) == datetime(2026, 10, 8, 9, 15, 30, tzinfo=timezone.utc)


def test_the_substitution_is_counted():
    """So a fleet-wide clock problem announces itself rather than being
    absorbed. Three hosts do this today over eight alerts, two of them exactly
    ten hours out."""
    afs.reset_stamp_heuristic_stats()
    afs.event_time_of(
        "Time: 2026-10-08T09:15:26.531+0000\n"
        "data.win.system.systemTime: 2026-10-08T19:15:00.000Z\n"
    )
    assert afs.stamp_heuristic_stats()["host_clock_ahead"] == 1


def test_an_alert_with_no_stamp_of_its_own_still_falls_back():
    """Without a manager stamp there is no ceiling to apply, so the host is
    believed — there is nothing better — and the caller's fallback still
    covers a body with no time at all."""
    fallback = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    assert afs.event_time_of("nothing parseable here", fallback=fallback) == fallback


# --- the account a Windows security event is about ---------------------------

def test_the_locked_out_account_is_the_one_reported():
    """Reported as: the alert names the locked account, the case shows none.

    Event 4740 names two principals and we matched neither:

        subjectUserName: EXPDC402$   the domain controller, which performed it
        targetUserName:  gmaciuc     the person it happened to
    """
    body = (
        "Agent: EXPDC402\n"
        "Event ID: 4740 | UserAccountChange\n"
        "data.win.eventdata.subjectUserName: EXPDC402$\n"
        "data.win.eventdata.targetUserName: gmaciuc\n"
    )
    assert afs.entity_of(afs.extract_alert_fields(body))[1] == "gmaciuc"


def test_whichever_field_names_a_person_is_preferred():
    """Taking the target always would be wrong. Across the 513 affected alerts
    the target is a machine account 204 times and the subject 300 times, so
    neither field is reliably the person."""
    target_is_machine = (
        "data.win.eventdata.targetUserName: EXP-4JHPZY2$\n"
        "data.win.eventdata.subjectUserName: jdoe\n"
    )
    assert afs.entity_of(afs.extract_alert_fields(target_is_machine))[1] == "jdoe"


def test_a_machine_account_is_still_recorded_when_it_is_all_there_is():
    """"The domain controller did this" is worth knowing. It is barred from
    linking cases together, which is a separate decision from whether to
    store it."""
    body = (
        "data.win.eventdata.targetUserName: EXPDC001$\n"
        "data.win.eventdata.subjectUserName: EXPDC402$\n"
    )
    assert afs.entity_of(afs.extract_alert_fields(body))[1] == "EXPDC001$"


def test_an_alert_that_states_its_user_outright_still_wins():
    """A Sysmon alert names the account that ran the command, and that is a
    better answer than either half of a security event's subject/target
    pair."""
    body = (
        "User: INT\\echelarasu\n"
        "data.win.eventdata.targetUserName: someone_else\n"
    )
    assert afs.entity_of(afs.extract_alert_fields(body))[1] == "INT\\echelarasu"


def test_a_kerberos_machine_principal_is_recognised():
    """Windows writes a computer account `HOST$`, and Kerberos writes it
    `HOST$@REALM` — 48 alerts in this estate carry the second form."""
    assert afs.is_machine_account("EXPDC001$@INT.EXPERTWARE.NET")
    assert afs.is_machine_account("EXP-4JHPZY2$")
    assert afs.is_machine_account("NT AUTHORITY\\SYSTEM")
    assert not afs.is_machine_account("gmaciuc")
    assert not afs.is_machine_account("INT\\echelarasu")


def test_the_linkage_service_uses_the_same_definition():
    """Two copies of "what is a machine account" would drift, and the answer
    has to be the same where it is stored and where it decides linking."""
    from app.services import alert_case_linkage_service as linkage

    assert linkage._is_machine_account is afs.is_machine_account
