from app.services.email_ioc_service import (
    _extract_header_value_from_raw,
    _extract_sender_ip,
    _extract_sender_ip_from_sources,
    _extract_sender_email_from_header_blob,
    _extract_urls_from_text,
)


def test_extract_urls_from_wrapped_quoted_printable_text() -> None:
    text = (
        "Click here: https://casewareinternationalinc.cdn.salesforce-exper=\r\n"
        "ience.com/cms/delivery/media/MC46ZIFG6BS5HDNEIIV5DR7BU5VU?fileName=IDC+banner+NL.png"
    )
    urls = _extract_urls_from_text(text)
    assert any("salesforce-experience.com/cms/delivery/media" in u for u in urls)


def test_extract_urls_from_html_href() -> None:
    html_text = '<a href="https://www.caseware.com/resources/industry-reports/idc-report">Report</a>'
    urls = _extract_urls_from_text(html_text)
    assert "https://www.caseware.com/resources/industry-reports/idc-report" in urls


def test_extract_sender_email_from_header_blob_with_return_path_fallback() -> None:
    headers = (
        "Subject: test\r\n"
        "Return-Path: <marketing.nl@em.caseware.com>\r\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\r\n"
    )
    sender = _extract_sender_email_from_header_blob(headers)
    assert sender == "marketing.nl@em.caseware.com"


def test_extract_header_value_from_raw_decodes_encoded_subject() -> None:
    raw = (
        b"Subject: =?UTF-8?Q?Essenti=C3=ABle_inzichten:_IDC=E2=80=99s_onderz?=\r\n"
        b"From: Marketing <marketing.nl@em.caseware.com>\r\n\r\nBody"
    )
    subject = _extract_header_value_from_raw(raw, "Subject")
    assert "Essenti" in subject
    assert "IDC" in subject


def test_extract_sender_ip_fallback_to_private_hop_when_no_public() -> None:
    received = [
        "from mx.internal (mx.internal [10.12.4.8]) by relay.local with ESMTP",
        "from app.local ([192.168.1.20]) by mx.internal with ESMTP",
    ]
    ip = _extract_sender_ip(received)
    assert ip in {"10.12.4.8", "192.168.1.20"}


def test_extract_sender_ip_from_explicit_header_tokens_when_received_missing() -> None:
    ip = _extract_sender_ip_from_sources(
        received_headers=[],
        direct_header_values=[
            "Authentication-Results: mx.example; spf=pass smtp.remote-ip=155.226.0.6;",
            "X-Originating-IP: [155.226.0.6]",
        ],
    )
    assert ip == "155.226.0.6"
