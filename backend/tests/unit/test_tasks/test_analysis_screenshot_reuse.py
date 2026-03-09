from app.tasks.analysis_task import (
    _build_reused_screenshot_payload,
    _should_reuse_urlscan_screenshot,
)


def test_should_reuse_urlscan_screenshot_when_artifact_exists():
    evidence = {"urlscan": {"screenshot_artifact_id": "abc-123"}}
    assert _should_reuse_urlscan_screenshot(evidence, "domain") is True


def test_should_not_reuse_urlscan_screenshot_without_artifact():
    evidence = {"urlscan": {"screenshot_artifact_id": None}}
    assert _should_reuse_urlscan_screenshot(evidence, "domain") is False


def test_build_reused_screenshot_payload_prefers_urlscan_page_url():
    evidence = {
        "urlscan": {
            "screenshot_artifact_id": "abc-123",
            "page_url": "https://final.example.com/",
        }
    }
    payload = _build_reused_screenshot_payload(evidence, investigated_url=None, domain="example.com")
    assert payload["artifact_id"] == "abc-123"
    assert payload["final_url"] == "https://final.example.com/"
