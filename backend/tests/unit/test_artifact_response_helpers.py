from app.api.artifacts import _ensure_filename_extension, _resolve_artifact_content_type


def test_resolve_artifact_content_type_from_name_when_generic():
    assert _resolve_artifact_content_type("application/octet-stream", "urlscan_screenshot_png") == "image/png"


def test_ensure_filename_extension_adds_png_for_inline_name():
    assert _ensure_filename_extension("urlscan_screenshot_png", "image/png").endswith(".png")
