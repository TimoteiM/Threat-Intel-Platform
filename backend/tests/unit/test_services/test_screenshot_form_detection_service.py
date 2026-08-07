from types import SimpleNamespace

from PIL import Image

from app.services import screenshot_form_detection_service as service


def test_screenshot_form_detection_returns_unavailable_without_key():
    result = service.detect_sensitive_forms_in_screenshots(
        [b"not-needed"],
        settings=SimpleNamespace(openai_api_key=""),
    )

    assert result["checked"] is False
    assert result["detected"] is False
    assert result["sources"] == []


def test_compact_image_data_url_accepts_png():
    import io

    buffer = io.BytesIO()
    Image.new("RGB", (20, 10), "white").save(buffer, format="PNG")

    result = service._compact_image_data_url(buffer.getvalue())

    assert result.startswith("data:image/jpeg;base64,")
