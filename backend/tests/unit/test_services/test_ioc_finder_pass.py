"""
The ioc-finder pass and the flat `by_type` view.

ioc-finder supplies recall (CVEs, scheme-less URLs, defanging spellings we never
wrote a rule for); our validation supplies precision. The fixtures below are the
two shapes that actually reach us: analyst-written prose, and machine telemetry
where a context-free matcher produces nothing but false positives.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services.alert_ioc_extraction_service import extract_alert_indicators, find_iocs_in

PHISHING_ALERT = """[ALERT] Credential phishing — user clicked
User: jdoe@expertware.net clicked hxxps://secure-login[.]myspotifypremium[.]info/login_up.php
Source 10.10.30.19 -> 102.135.105.190:443, proxy log ref 8.8.8.8
Attachment invoice_2026.pdf SHA256 ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B
Exploit attempt for CVE-2026-1234 seen on wm-c00.siembiot.int
Sender: billing@mail.evil-corp.com  Reply-To: no-reply(at)evil-corp(dot)com
"""

MALWARE_ALERT = """[ALERT] Malware detected on WKS-4471
Defender removed C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe
Hashes: MD5=4F96B0F8B5337360D11BB59BD103D061,SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B,IMPHASH=8E6DF21BAEBF68CC126345D8EDCA4189
The sample beaconed to 45.147.230.131 and www.evil-drop.net/gate.php
Related advisory: CVE-2026-9999, see also cve-2025-0001
"""

SIEM_DOCUMENT = """Alert: EXP-D0MY264 - Possible Remote Lateral Movement Activity
Rule: 110145
Agent IP: 192.168.50.129
Computer: EXP-D0MY264.int.expertware.net

Process Create:
Image: C:\\Program Files\\Git\\usr\\bin\\bash.exe
CommandLine: bash.exe -c "ls /c/EFI/BOOT/BOOTX64.EFI"
Hashes: MD5=4F96B0F8B5337360D11BB59BD103D061,SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B

alert.category: System
decoder.name: windows_eventchannel
data.win.eventdata.image: C:\\Program Files\\Git\\usr\\bin\\bash.exe
data.win.system.providerName: Microsoft-Windows-Sysmon
rule.id: 110145
"""


def _values(result: dict, kind: str) -> list[str]:
    return [item["value"] for item in result["indicators"] if item["type"] == kind]


def _by_value(result: dict, value: str) -> dict:
    return next(item for item in result["indicators"] if item["value"] == value)


# ── The library itself ────────────────────────────────────────────────────────


def test_the_library_is_installed_and_returns_the_types_we_rely_on():
    iocs = find_iocs_in("8.8.8.8 evil.com https://evil.com/a CVE-2026-1234 a@b.com")
    assert iocs["ipv4s"] == ["8.8.8.8"]
    assert iocs["cves"] == ["CVE-2026-1234"]
    assert iocs["urls"] == ["https://evil.com/a"]
    # The URL's host is not repeated as a domain — that would investigate one
    # site twice.
    assert "evil.com" in iocs["domains"]
    assert iocs["email_addresses"] == ["a@b.com"]


# ── Prose alerts: recall ──────────────────────────────────────────────────────


def test_a_phishing_alert_yields_every_type():
    result = extract_alert_indicators(PHISHING_ALERT)

    assert _values(result, "url") == ["https://secure-login.myspotifypremium.info/login_up.php"]
    assert sorted(_values(result, "domain")) == ["evil-corp.com", "expertware.net", "siembiot.int"]
    assert sorted(_values(result, "ip")) == ["10.10.30.19", "102.135.105.190", "8.8.8.8"]
    assert _values(result, "cve") == ["CVE-2026-1234"]
    assert len(_values(result, "email")) == 3
    assert _values(result, "hash") == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]


def test_defanged_indicators_are_normalised():
    result = extract_alert_indicators(PHISHING_ALERT)
    url = _by_value(result, "https://secure-login.myspotifypremium.info/login_up.php")
    assert url["defanged_in_source"] is True
    # `no-reply(at)evil-corp(dot)com` refangs to a real address.
    assert "no-reply@evil-corp.com" in _values(result, "email")


def test_cves_are_reported_but_not_investigated():
    """Report-only for now: no collector resolves a CVE."""
    cve = _by_value(extract_alert_indicators(PHISHING_ALERT), "CVE-2026-1234")
    assert cve["investigable"] is False
    assert cve["skip_reason"] == "cve_reported_as_context"


def test_a_malware_alert_keeps_one_file_and_finds_its_cves():
    result = extract_alert_indicators(MALWARE_ALERT)

    # One file, not three digests — and never the imphash.
    assert _values(result, "hash") == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]
    assert sorted(_values(result, "cve")) == ["CVE-2025-0001", "CVE-2026-9999"]
    # A scheme-less URL is still a URL, with a scheme collectors can use.
    assert "http://www.evil-drop.net/gate.php" in _values(result, "url")
    assert "45.147.230.131" in _values(result, "ip")
    # The dropper's path is not an indicator.
    assert "dropper.exe" not in " ".join(_values(result, "domain"))


# ── Machine telemetry: precision ──────────────────────────────────────────────


def test_a_siem_document_yields_only_real_indicators():
    """
    The second pass must not undo the first pass's judgement.

    ioc-finder alone returns `data.win`, `decoder.name` and `alert.category`
    here — all valid TLDs, all field names.
    """
    result = extract_alert_indicators(SIEM_DOCUMENT)

    assert _values(result, "domain") == ["expertware.net"]
    assert _by_value(result, "expertware.net")["hostnames"] == ["exp-d0my264.int.expertware.net"]
    assert _values(result, "ip") == ["192.168.50.129"]
    assert _by_value(result, "192.168.50.129")["investigable"] is False
    assert _values(result, "hash") == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]
    # BOOTX64.EFI is a file, not a host.
    assert not any("bootx64" in value.lower() for value in _values(result, "domain"))


def test_the_raw_library_would_have_produced_those_false_positives():
    """Documents why the validation layer exists, and fails if it stops being needed."""
    raw = find_iocs_in(SIEM_DOCUMENT)
    assert "data.win" in raw["domains"] or "decoder.name" in raw["domains"]


# ── Shape and edges ───────────────────────────────────────────────────────────


def test_the_flat_view_mirrors_the_rich_list():
    result = extract_alert_indicators(PHISHING_ALERT)
    flat = result["by_type"]

    assert flat["urls"] == _values(result, "url")
    assert sorted(flat["domains"]) == sorted(_values(result, "domain"))
    assert sorted(flat["ips"]) == sorted(_values(result, "ip"))
    assert flat["cves"] == ["CVE-2026-1234"]
    assert flat["hashes"]["sha256"] == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]
    assert flat["hashes"]["md5"] == []


def test_the_flat_view_lists_sibling_digests_of_one_file():
    flat = extract_alert_indicators(MALWARE_ALERT)["by_type"]
    assert flat["hashes"]["sha256"] == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]
    # The MD5 of the same file is reachable without becoming a second lookup.
    assert flat["hashes"]["md5"] == ["4f96b0f8b5337360d11bb59bd103d061"]


def test_duplicates_are_counted_once_across_both_passes():
    result = extract_alert_indicators("evil.com seen, evil.com again, and evil.com once more")
    assert _values(result, "domain") == ["evil.com"]
    assert _by_value(result, "evil.com")["occurrences"] == 3


def test_input_without_indicators_returns_an_empty_bundle():
    for text in ("", "   ", "The user reported a suspicious email but gave no details."):
        result = extract_alert_indicators(text)
        assert result["indicators"] == []
        assert result["investigable_total"] == 0
        assert result["by_type"]["domains"] == []
        assert result["by_type"]["hashes"] == {"md5": [], "sha1": [], "sha256": []}
