from app.tasks.analysis_task import _guess_content_type


def test_guess_content_type_handles_extensionless_png_name():
    assert _guess_content_type("urlscan_screenshot_png") == "image/png"


def test_guess_content_type_handles_standard_png_name():
    assert _guess_content_type("screenshot.png") == "image/png"
