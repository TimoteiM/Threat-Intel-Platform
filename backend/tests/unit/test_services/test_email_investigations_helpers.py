from app.api.email_investigations import (
    _build_url_destination_context,
    _compact_checks_for_ai,
    _prepare_history_payload,
    _render_email_template_resolution,
)


def test_compact_checks_keeps_lexical_ml_section() -> None:
    checks = {
        "sender_domain": {},
        "sender_ip": {},
        "attachments": {"present": False, "items": [], "message": ""},
        "urls": [
            {
                "url": "https://example.com",
                "vt": {"verdict": "clean"},
                "lexical_ml": {"score": 0.12, "label": "low", "model_source": "built_in"},
                "screenshot": {"captured": False, "final_url": None, "error": "Not requested"},
            }
        ],
    }
    compact = _compact_checks_for_ai(checks)
    assert len(compact["urls"]) == 1
    assert compact["urls"][0]["lexical_ml"]["label"] == "low"


def test_prepare_history_payload_keeps_lexical_ml_without_image_blob() -> None:
    payload = {
        "filename": "a.eml",
        "urls_count": 1,
        "attachments_count": 0,
        "indicator_checks": {
            "urls": [
                {
                    "url": "https://example.com",
                    "vt": {"verdict": "clean"},
                    "lexical_ml": {"score": 0.12, "label": "low"},
                    "screenshot": {"image_base64": "abc", "captured": False},
                }
            ]
        },
    }
    stored = _prepare_history_payload(payload)
    url_item = stored["indicator_checks"]["urls"][0]
    assert "image_base64" not in url_item["screenshot"]
    assert url_item["lexical_ml"]["label"] == "low"


def test_build_url_destination_context_is_specific_not_generic() -> None:
    checks = {
        "urls": [
            {
                "url": "https://58ktaz.1.tracking.e360.salesforce.com/click?jwt=x",
                "lexical_ml": {"label": "medium"},
                "screenshot": {
                    "final_url": "https://www.caseware.com/resources/industry-reports/idc-report",
                },
            },
            {
                "url": "https://example.top/verify/account/login",
                "lexical_ml": {"label": "high"},
                "screenshot": {"final_url": None},
            },
        ]
    }
    text = _build_url_destination_context(checks)
    assert "Caseware corporate website/resources" in text
    assert "high-risk URL lexical pattern destination" in text
    assert "Destinations observed:" in text
    assert "caseware.com (Caseware corporate website and resources)" in text
    assert "other web destinations" not in text


def test_render_email_template_resolution_enforces_expected_layout() -> None:
    extracted = {
        "email_subject": "Quarterly Update",
        "sender_email": "noreply@example.com",
        "sender_domain": "example.com",
        "sender_ip": "1.2.3.4",
        "urls": ["https://a.example.com"],
        "attachments": [],
    }
    checks = {
        "sender_domain": {"whois": {"registrar": "Namecheap"}},
        "sender_ip": {
            "abuseipdb": {"isp": "Example ISP", "usage_type": "Data Center"},
            "vt": {"verdict": "clean", "malicious_count": 0, "suspicious_count": 0, "total_vendors": 94},
        },
        "attachments": {"items": []},
        "urls": [{"url": "https://a.example.com"}],
    }
    resolution = {
        "sender_domain_analysis": {"primary_reasoning": "example.com is a known corporate domain."}
    }
    text = _render_email_template_resolution(
        extracted=extracted,
        checks=checks,
        url_destination_context="web destination with low-risk lexical pattern [example.com]",
        resolution=resolution,
    )
    assert text.startswith('Email subject: "Quarterly Update"')
    assert "After our investigation, we found:" in text
    assert "All URLs found in the email body were checked and URLs checked: 1/1." in text
    assert "Suspicious URL assessment" not in text
