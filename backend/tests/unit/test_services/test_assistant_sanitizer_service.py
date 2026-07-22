import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.services import assistant_sanitizer_service as sanitizer


def test_sanitize_entry_replaces_email_sid_and_account_values() -> None:
    text = (
        "user=admin logged in from 10.20.30.40 with SID "
        "S-1-5-21-1234567890-123456789-123456789-1001 and email admin@example.com"
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "10.20.30.40" not in result.sanitized_text
    assert "[IP_1]" in result.sanitized_text
    assert "[EMAIL_1]" in result.sanitized_text
    assert "[SID_1]" in result.sanitized_text
    assert "[ACCOUNT_1]" in result.sanitized_text
    assert result.token_map["[ACCOUNT_1]"] == "admin"
    assert result.summary["ips"] == 1
    assert result.summary["emails"] == 1
    assert result.summary["sids"] == 1


def test_sanitize_session_entries_reuses_same_token_for_same_indicator() -> None:
    entries = [
        "Source IP 10.20.30.40 contacted admin@example.com",
        "Destination IP 10.20.30.40 triggered for admin@example.com",
    ]

    results = sanitizer.sanitize_entries(entries)

    assert len(results.entries) == 2
    assert "10.20.30.40" not in results.entries[0].sanitized_text
    assert "[IP_1]" in results.entries[0].sanitized_text
    # IPs and emails are deduplicated across entries
    assert results.summary["ips"] == 1
    assert results.summary["emails"] == 1


def test_sanitize_entry_replaces_host_fields() -> None:
    text = (
        "hostname=wm-c06.siembiot.int computer=FeliciaPopa.Metrorex.local "
        "Suspicious login from host srv-01"
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "wm-c06.siembiot.int" not in result.sanitized_text
    assert "FeliciaPopa.Metrorex.local" not in result.sanitized_text
    assert "srv-01" not in result.sanitized_text
    assert "[HOST_1]" in result.sanitized_text
    assert "[HOST_2]" in result.sanitized_text
    assert "[HOST_3]" in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "wm-c06.siembiot.int"
    assert result.summary["hosts"] == 3


def test_sanitize_entry_ignores_generic_release_word_after_server_prefix() -> None:
    text = 'agentOsRevision":"Oracle Server release 8.10 5.15.0-317.197.5.1.el8uek.x86_64"'

    result = sanitizer.sanitize_entry(text, {})

    assert "release" in result.sanitized_text
    assert "[HOST_" not in result.sanitized_text
    assert result.summary.get("hosts", 0) == 0


def test_sanitize_entry_replaces_json_style_agent_computer_name() -> None:
    text = 'agentComputerName":"onvmbp01.onenet.be"'

    result = sanitizer.sanitize_entry(text, {})

    assert "onvmbp01.onenet.be" not in result.sanitized_text
    assert '[HOST_1]"' in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "onvmbp01.onenet.be"
    assert result.summary["hosts"] == 1


def test_sanitize_entries_fail_closed_on_internal_error() -> None:
    class BadStr(str):
        def replace(self, old: str, new: str, count: int = -1):  # type: ignore[override]
            raise RuntimeError("boom")

    results = sanitizer.sanitize_entries([BadStr("admin@example.com")])

    assert results.entries[0].sanitized_text == "[SANITIZATION_ERROR]"
    assert results.entries[0].token_map == {}
    assert results.summary["errors"] == 1


def test_sanitize_entry_replaces_domain_backslash_account() -> None:
    text = "user=povgrp\\pom29 action=allowed"

    result = sanitizer.sanitize_entry(text, {})

    assert "povgrp\\pom29" not in result.sanitized_text
    assert "[ACCOUNT_1]" in result.sanitized_text
    assert result.token_map["[ACCOUNT_1]"] == "povgrp\\pom29"
    assert result.summary["accounts"] == 1


def test_sanitize_entry_replaces_syslog_source_hostname() -> None:
    text = "<134>Apr 30 10:12:21 host1 DNS-LOG: src=10.16.17.17 user=admin action=allowed"

    result = sanitizer.sanitize_entry(text, {})

    assert "host1" not in result.sanitized_text
    assert "[HOST_1]" in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "host1"
    assert result.summary["hosts"] >= 1


def test_sanitize_entry_replaces_windows_path_username() -> None:
    text = r'Image="C:\Users\jdoe\AppData\Local\Temp\payload.exe" User=domain\jdoe'

    result = sanitizer.sanitize_entry(text, {})

    assert "jdoe" not in result.sanitized_text
    # domain\jdoe from the User= field
    assert result.token_map.get("[ACCOUNT_1]") == "domain\\jdoe"
    # jdoe extracted from the Windows path gets its own token
    assert any(v == "jdoe" for v in result.token_map.values())


def test_sanitize_entries_full_syslog_attack_chain() -> None:
    logs = [
        "<134>Apr 30 10:12:21 host1 DNS-LOG: src=10.16.17.17 user=povgrp\\pom29 action=allowed",
        r'<134>Apr 30 10:12:45 host1 Sysmon: Image="C:\Users\pom29\AppData\Temp\inv.exe" User=povgrp\pom29',
        "<134>Apr 30 10:13:30 fw1 TRAFFIC: src=10.16.17.17 dst=185.225.69.45 user=povgrp\\pom29",
    ]

    results = sanitizer.sanitize_entries(logs)

    token_map = results.entries[-1].token_map
    # All occurrences of the domain account resolve to the same token
    assert any(v == "povgrp\\pom29" for v in token_map.values())
    account_token = next(k for k, v in token_map.items() if v == "povgrp\\pom29")
    for entry in results.entries:
        assert "povgrp\\pom29" not in entry.sanitized_text
    # Both syslog hostnames are tokenised
    assert "host1" not in results.entries[0].sanitized_text
    assert "fw1" not in results.entries[2].sanitized_text
    # host1 and fw1 share the same batch token map but are different tokens
    host_tokens = {k for k in token_map if k.startswith("[HOST_")}
    assert len(host_tokens) >= 2
    assert "10.16.17.17" not in results.entries[0].sanitized_text
    assert "[IP_1]" in results.entries[0].sanitized_text
    _ = account_token  # suppress unused-variable warning


def test_sanitize_entry_does_not_treat_compliance_controls_as_hostnames() -> None:
    text = "hipaa=[164.312.a.2.I, 164.312.a.2.II, 164.312.b]"

    result = sanitizer.sanitize_entry(text, {})

    assert "164.312.a.2.II" in result.sanitized_text
    assert "[HOST_" not in result.sanitized_text
    assert result.summary.get("hosts", 0) == 0


def test_sanitize_entry_replaces_windows_event_account_fields() -> None:
    text = (
        "targetUserName=CodexSandboxUsers samAccountName=CodexSandboxUsers "
        "subjectUserName=epentilescu message=\"Account Name: epentilescu "
        "SAM Account Name: CodexSandboxUsers\""
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "targetUserName=[ACCOUNT_1]" in result.sanitized_text
    assert "samAccountName=[ACCOUNT_1]" in result.sanitized_text
    assert "subjectUserName=[ACCOUNT_2]" in result.sanitized_text
    assert "Account Name: [ACCOUNT_2]" in result.sanitized_text
    assert "SAM Account Name: [ACCOUNT_1]" in result.sanitized_text
    assert result.token_map["[ACCOUNT_1]"] == "CodexSandboxUsers"
    assert result.token_map["[ACCOUNT_2]"] == "epentilescu"


def test_sanitize_entry_replaces_escaped_json_agent_computer_name() -> None:
    text = r'\"agentComputerName\":\"5CG5452NBD\",\"agentIpV4\":\"172.16.0.2,192.168.129.2\"'

    result = sanitizer.sanitize_entry(text, {})

    assert r'\"agentComputerName\":\"[HOST_1]\"' in result.sanitized_text
    assert "172.16.0.2" not in result.sanitized_text
    assert "[IP_1]" in result.sanitized_text
    assert result.token_map["[HOST_1]"] == "5CG5452NBD"


def test_sanitize_entry_does_not_tokenize_browser_version_as_ip() -> None:
    text = (
        "{agent={ip=192.168.5.12}, @src_ip=45.148.10.62, "
        'full_log=\"GET /.env.tmp HTTP/1.1\" 403 \"Mozilla/5.0 '
        'Chrome/131.0.0.0 Safari/537.36\"}'
    )

    result = sanitizer.sanitize_entry(text, {})

    assert "131.0.0.0" in result.sanitized_text
    assert "131.0.0.0" not in result.token_map.values()
    assert set(value for value in result.token_map.values() if value.count(".") == 3) == {
        "192.168.5.12",
        "45.148.10.62",
    }


def test_sanitize_entry_distinguishes_json_version_from_explicit_ip_field() -> None:
    result = sanitizer.sanitize_entry(
        '{"browser_version":"120.1.2.3","source_ip":"198.51.100.7"}',
        {},
    )

    assert '"browser_version":"120.1.2.3"' in result.sanitized_text
    assert result.token_map == {"[IP_1]": "198.51.100.7"}
