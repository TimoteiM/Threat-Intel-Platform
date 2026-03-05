from app.api.email_investigations import _compact_checks_for_ai, _prepare_history_payload


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
