from app.tasks.analysis_task import _attach_artifact_ids, _guess_content_type


def test_guess_content_type_handles_extensionless_png_name():
    assert _guess_content_type("urlscan_screenshot_png") == "image/png"


def test_guess_content_type_handles_standard_png_name():
    assert _guess_content_type("screenshot.png") == "image/png"


def test_attach_artifact_ids_resolves_nested_anyrun_screenshot():
    evidence = {
        "items": [
            {
                "sandbox_intelligence": {
                    "screenshot_thumbnails": [{"artifact_name": "hybrid_analysis_anyrun_screenshot_01_01.jpeg"}]
                }
            }
        ]
    }

    _attach_artifact_ids(
        evidence,
        {"hybrid_analysis_anyrun_screenshot_01_01.jpeg": "artifact-uuid"},
    )

    assert evidence["items"][0]["sandbox_intelligence"]["screenshot_thumbnails"][0]["artifact_id"] == "artifact-uuid"
