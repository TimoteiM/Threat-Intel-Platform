from app.services.alert_ioc_extraction_service import extract_alert_indicators, refang


def _values(result: dict, kind: str) -> list[str]:
    return [item["value"] for item in result["indicators"] if item["type"] == kind]


def _by_value(result: dict, value: str) -> dict:
    return next(item for item in result["indicators"] if item["value"] == value)


def test_refang_handles_common_defanging():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("user[at]evil(.)com") == "user@evil.com"


def test_extracts_urls_domains_ips_and_hashes():
    alert = (
        "Suspicious login from 45.147.230.131 to hxxps://secure-login[.]evil-corp[.]com/session\n"
        "Bare domain: malware-drop.net\n"
        "SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
        "MD5 d41d8cd98f00b204e9800998ecf8427e\n"
    )
    result = extract_alert_indicators(alert)

    assert _values(result, "url") == ["https://secure-login.evil-corp.com/session"]
    assert _values(result, "domain") == ["malware-drop.net"]
    assert _values(result, "ip") == ["45.147.230.131"]
    assert sorted(_values(result, "hash")) == [
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]
    assert _by_value(result, "d41d8cd98f00b204e9800998ecf8427e")["hash_type"] == "md5"
    assert result["counts"]["url"] == 1
    assert result["investigable_total"] == 5


def test_url_host_is_not_duplicated_as_a_domain_indicator():
    result = extract_alert_indicators("Visit https://phish.example.org/login now")
    assert _values(result, "url") == ["https://phish.example.org/login"]
    assert _values(result, "domain") == []


def test_private_ips_are_extracted_but_not_investigable():
    result = extract_alert_indicators("Source host 10.12.4.55 contacted 8.8.8.8")
    private = _by_value(result, "10.12.4.55")
    assert private["investigable"] is False
    assert private["skip_reason"] == "private_or_reserved_address"
    assert _by_value(result, "8.8.8.8")["investigable"] is True


def test_email_is_context_only_but_its_domain_is_investigated():
    result = extract_alert_indicators("Sender: billing@evil-corp.com")
    email = _by_value(result, "billing@evil-corp.com")
    assert email["type"] == "email"
    assert email["investigable"] is False
    domain = _by_value(result, "evil-corp.com")
    assert domain["type"] == "domain"
    assert domain["derived_from"] == "email"
    assert domain["investigable"] is True


def test_filenames_are_not_mistaken_for_domains():
    result = extract_alert_indicators("Dropped invoice_2024.pdf and setup.exe on the host")
    assert _values(result, "domain") == []


def test_repeated_indicators_are_deduplicated_with_occurrence_counts():
    result = extract_alert_indicators("evil.com seen; evil.com again; EVIL.com third time")
    assert _values(result, "domain") == ["evil.com"]
    assert _by_value(result, "evil.com")["occurrences"] == 3


def test_defanged_values_are_flagged():
    result = extract_alert_indicators("Contact evil-corp[.]com over 1[.]2[.]3[.]4")
    assert _by_value(result, "evil-corp.com")["defanged_in_source"] is True
    assert _by_value(result, "1.2.3.4")["defanged_in_source"] is True


def test_hostnames_collapse_to_their_registered_domain():
    alert = (
        "computer=exprdsh002.int.expertware.net, manager={name=wm-c00.siembiot.int}, "
        "relay=mail.corp.example.co.uk"
    )
    result = extract_alert_indicators(alert)

    assert sorted(_values(result, "domain")) == ["example.co.uk", "expertware.net", "siembiot.int"]
    assert _by_value(result, "expertware.net")["hostnames"] == ["exprdsh002.int.expertware.net"]
    assert _by_value(result, "example.co.uk")["hostnames"] == ["mail.corp.example.co.uk"]


def test_sibling_hosts_become_one_domain_indicator():
    result = extract_alert_indicators("a.evil.com and b.evil.com and evil.com")
    domain = _by_value(result, "evil.com")
    assert _values(result, "domain") == ["evil.com"]
    assert domain["occurrences"] == 3
    assert domain["hostnames"] == ["a.evil.com", "b.evil.com"]


def test_registered_domain_of_a_url_host_is_not_investigated_twice():
    result = extract_alert_indicators("https://login.evil-corp.com/session then evil-corp.com")
    assert _values(result, "url") == ["https://login.evil-corp.com/session"]
    assert _values(result, "domain") == []


def test_email_subdomain_is_collapsed_to_the_registered_domain():
    result = extract_alert_indicators("Sender: billing@mail.evil-corp.com")
    domain = _by_value(result, "evil-corp.com")
    assert domain["derived_from"] == "email"
    assert domain["hostnames"] == ["mail.evil-corp.com"]


def test_max_indicators_truncates_investigable_indicators():
    alert = " ".join(f"host{i}.example{i}.com" for i in range(10))
    result = extract_alert_indicators(alert, max_indicators=4)
    assert result["investigable_total"] == 4
    assert result["truncated"] is True
    assert result["dropped"] == 6


def test_empty_alert_body_returns_empty_bundle():
    result = extract_alert_indicators("")
    assert result["indicators"] == []
    assert result["total"] == 0
    assert result["investigable_total"] == 0


def test_sysmon_hash_field_yields_one_file_not_three_indicators():
    """MD5 + SHA256 + IMPHASH of one file are one file, and imphash is not one."""
    alert = (
        "Process Create: Image: C:\\Windows\\System32\\cmd.exe "
        "Hashes: MD5=4F96B0F8B5337360D11BB59BD103D061,"
        "SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B,"
        "IMPHASH=8E6DF21BAEBF68CC126345D8EDCA4189 User: INT\\tmoscaliuc"
    )
    result = extract_alert_indicators(alert)

    assert _values(result, "hash") == [
        "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"
    ]
    indicator = _by_value(result, "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b")
    assert indicator["hash_type"] == "sha256"
    # The other digests travel with the file instead of becoming lookups.
    assert indicator["other_digests"] == {
        "md5": "4f96b0f8b5337360d11bb59bd103d061",
        "imphash": "8e6df21baebf68cc126345d8edca4189",
    }


def test_a_hash_field_without_sha256_falls_back_to_md5():
    result = extract_alert_indicators(
        "Hashes: MD5=4F96B0F8B5337360D11BB59BD103D061,IMPHASH=8E6DF21BAEBF68CC126345D8EDCA4189"
    )
    assert _values(result, "hash") == ["4f96b0f8b5337360d11bb59bd103d061"]
    assert _by_value(result, "4f96b0f8b5337360d11bb59bd103d061")["hash_type"] == "md5"


def test_an_imphash_only_field_produces_no_hash_indicator():
    """Nothing can resolve an import hash as a file — do not spend a lookup on it."""
    result = extract_alert_indicators("Hashes: IMPHASH=8E6DF21BAEBF68CC126345D8EDCA4189")
    assert _values(result, "hash") == []


def test_loose_hashes_outside_a_hash_field_still_extract():
    result = extract_alert_indicators("Sample SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 seen")
    assert _values(result, "hash") == ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]


def test_flattened_siem_field_names_are_not_domains():
    """A posted alert document flattens to dotted keys — several look like hosts."""
    alert = (
        "alert.category: System\n"
        "rule.id: 110145\n"                       # .id is a real ccTLD
        "decoder.name: windows_eventchannel\n"
        "data.win.eventdata.image: C:\\Program Files\\Git\\usr\\bin\\bash.exe\n"
        "Computer: EXP-D0MY264.int.expertware.net\n"
    )
    result = extract_alert_indicators(alert)
    # Only the value is a domain; none of the keys are.
    assert _values(result, "domain") == ["expertware.net"]


def test_filenames_with_alphabetic_extensions_are_not_domains():
    result = extract_alert_indicators(
        "Files: BOOTX64.EFI grubx64.efi options.csv snapshot-bash-123.sh report.docx"
    )
    assert _values(result, "domain") == []


def test_a_real_domain_after_a_label_is_still_extracted():
    """The key guard must not swallow values that follow a label."""
    result = extract_alert_indicators("Computer: host.evil-corp.com\nsender: a@evil-corp.com")
    assert _values(result, "domain") == ["evil-corp.com"]


def test_a_host_with_a_port_at_line_start_is_not_a_field_name():
    """`evil.com:8080/path` starts a line and is followed by a colon — but it is a value."""
    result = extract_alert_indicators("evil8[.]com:8080/path\nrule.id: 110145")
    assert _values(result, "domain") == ["evil8.com"]


def test_a_browser_version_is_not_an_ip_address():
    """`Chrome/131.0.0.0` in a user agent used to become an investigable IP."""
    alert = (
        'full_log=195.178.110.31 - - [07/Aug/2026:07:38:09 +0000] "GET /.env.php.bak HTTP/1.1" '
        '404 1260 "-" "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"'
    )
    assert _values(extract_alert_indicators(alert), "ip") == ["195.178.110.31"]


def test_explicit_network_fields_win_over_the_version_guard():
    result = extract_alert_indicators("agent.ip=172.16.0.11, @src_ip=195.178.110.31, dst_ip: 8.8.8.8")
    assert sorted(_values(result, "ip")) == ["172.16.0.11", "195.178.110.31", "8.8.8.8"]
    assert _by_value(result, "172.16.0.11")["investigable"] is False   # RFC1918, context only
