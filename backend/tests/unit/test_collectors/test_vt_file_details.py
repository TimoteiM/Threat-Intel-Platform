from app.collectors.vt_collector import _parse_behaviour_summary, _parse_file_details
from app.models.schemas import VTBehaviourSummary

SAMPLE_ATTRS = {
    "sha256": "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b",
    "md5": "4f96b0f8b5337360d11bb59bd103d061",
    "size": 2456832,
    "type_description": "Win32 EXE",
    "type_tag": "peexe",
    "type_extension": "exe",
    "magic": "PE32+ executable (console) x86-64",
    "meaningful_name": "sh.exe",
    "names": ["sh.exe", "bash.exe", ""],
    "times_submitted": 22,
    "unique_sources": 9,
    "reputation": -12,
    "first_submission_date": 1750255443,
    "last_analysis_date": 1754360061,
    "total_votes": {"harmless": 1, "malicious": 7},
    "tags": ["peexe", "signed"],
    "capabilities_tags": ["long_sleeps", "checks_debugger"],
    "popular_threat_classification": {
        "suggested_threat_label": "trojan.emotet/zbot",
        "popular_threat_category": [{"value": "trojan", "count": 12}],
        "popular_threat_name": [{"value": "emotet", "count": 8}],
    },
    "signature_info": {
        "verified": "Signed",
        "signers": "Evil Corp Ltd; Sectigo RSA CA; USERTrust",
        "counter signers": "Sectigo Timestamp Signer",
        "product": "Updater",
        "description": "Update helper",
        "copyright": "(c) Evil Corp",
        "original name": "updater.exe",
        "internal name": "updater",
        "file version": "1.2.3.4",
        "signing date": "10:31 AM 06/18/2026",
    },
    "sandbox_verdicts": {
        "Zenbox": {
            "category": "malicious",
            "sandbox_name": "Zenbox",
            "confidence": 98,
            "malware_names": ["Emotet"],
            "malware_classification": ["TROJAN"],
        }
    },
    "crowdsourced_yara_results": [
        {"rule_name": "detect_emotet", "author": "researcher", "ruleset_name": "malpedia"}
    ],
    "crowdsourced_ids_results": [
        {"rule_msg": "ET MALWARE Emotet CnC Checkin", "alert_severity": "high", "rule_source": "Emerging Threats"}
    ],
    "pe_info": {
        "imphash": "8e6df21baebf68cc126345d8edca4189",
        "sections": [{"name": ".text"}, {"name": ".rsrc"}],
        "import_list": [{"library_name": "KERNEL32.dll"}],
    },
}


def test_parse_file_details_extracts_identity_and_naming():
    details = _parse_file_details(SAMPLE_ATTRS)
    assert details.meaningful_name == "sh.exe"
    assert details.names == ["sh.exe", "bash.exe"]        # empty names dropped
    assert details.file_type == "Win32 EXE"
    assert details.size_bytes == 2456832
    assert details.imphash == "8e6df21baebf68cc126345d8edca4189"
    assert details.times_submitted == 22
    assert details.first_submission_date.startswith("2025-06-18")  # epoch 1750255443
    assert details.harmless_votes == 1 and details.malicious_votes == 7


def test_parse_file_details_extracts_signature():
    signature = _parse_file_details(SAMPLE_ATTRS).signature
    assert signature is not None
    assert signature.signed is True
    assert signature.verified == "Signed"
    assert signature.signers == ["Evil Corp Ltd", "Sectigo RSA CA", "USERTrust"]
    assert signature.counter_signers == ["Sectigo Timestamp Signer"]
    assert signature.original_name == "updater.exe"
    assert signature.file_version == "1.2.3.4"


def test_unverified_signature_is_flagged_not_trusted():
    attrs = {**SAMPLE_ATTRS, "signature_info": {**SAMPLE_ATTRS["signature_info"], "verified": "Invalid signature"}}
    details = _parse_file_details(attrs)
    assert details.signature.signed is False
    assert any("could not verify" in note for note in details.notes)


def test_parse_file_details_extracts_threat_context_and_rules():
    details = _parse_file_details(SAMPLE_ATTRS)
    assert details.threat_label == "trojan.emotet/zbot"
    assert details.threat_categories == ["trojan"]
    assert details.threat_names == ["emotet"]
    assert [verdict.sandbox for verdict in details.sandbox_verdicts] == ["Zenbox"]
    assert details.sandbox_verdicts[0].category == "malicious"
    kinds = {rule.kind for rule in details.crowdsourced_rules}
    assert kinds == {"yara", "ids"}
    assert details.pe_sections == [".text", ".rsrc"]


def test_parse_file_details_tolerates_a_sparse_response():
    details = _parse_file_details({})
    assert details.signature is None
    assert details.names == []
    assert details.sandbox_verdicts == []
    assert details.first_submission_date is None


def test_parse_behaviour_summary_flattens_sandbox_activity():
    payload = {
        "processes_created": ["C:\\\\Users\\\\user\\\\software.exe"],
        "files_written": ["C:\\\\Temp\\\\a.bin"],
        "dns_lookups": [{"hostname": "cdn.evil-corp.net"}],
        "ip_traffic": [{"destination_ip": "45.147.230.131", "destination_port": 443}],
        "mitre_attack_techniques": [
            {"id": "T1027", "signature_description": "encrypt data using RC4 PRGA"}
        ],
    }
    summary = _parse_behaviour_summary(payload, VTBehaviourSummary(checked=True))
    assert summary.processes_created == ["C:\\\\Users\\\\user\\\\software.exe"]
    assert summary.dns_lookups == ["cdn.evil-corp.net"]
    assert summary.ip_traffic == ["45.147.230.131 (443)"]
    assert summary.attack_techniques == ["T1027 — encrypt data using RC4 PRGA"]
    assert summary.checked is True
