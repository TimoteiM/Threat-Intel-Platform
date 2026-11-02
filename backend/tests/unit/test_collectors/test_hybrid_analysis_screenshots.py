from __future__ import annotations

import requests
from anyrun.connectors import SandboxConnector

from app.collectors.hybrid_analysis_collector import HybridAnalysisCollector


class _Response:
    status_code = 200
    headers = {"Content-Type": "image/jpeg"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def iter_content(self, chunk_size: int):
        assert chunk_size > 0
        yield b"\xff\xd8\xfforiginal-image"


def test_fetch_anyrun_screenshot_uses_api_authorization(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _Response()

    monkeypatch.setattr(requests, "get", fake_get)

    payload, extension = HybridAnalysisCollector._fetch_anyrun_screenshot(
        "https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg",
        ["secret-key"],
    )

    assert payload == b"\xff\xd8\xfforiginal-image"
    assert extension == "jpeg"
    assert captured["headers"]["Authorization"] == "API-KEY secret-key"
    assert captured["stream"] is True


def test_refresh_cached_anyrun_result_recovers_original_screenshot_urls(monkeypatch):
    class _Connector:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def get_analysis_report(self, analysis_id, report_format):
            assert analysis_id == "task-1"
            assert report_format == "json"
            return {
                "data": {
                    "analysis": {
                        "content": {
                            "screenshots": [
                                {
                                    "time": 3193,
                                    "permanentUrl": "https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg",
                                    "thumbnailUrl": "https://content.any.run/tasks/task-1/download/thumbnails/shot-1/image.jpeg",
                                }
                            ]
                        }
                    }
                }
            }

    monkeypatch.setattr(SandboxConnector, "windows", lambda api_key: _Connector())
    monkeypatch.setattr(HybridAnalysisCollector, "_configured_anyrun_keys", staticmethod(lambda: ["secret-key"]))
    result = {
        "analysis_id": "task-1",
        "cache_hit": True,
        "raw_summary": {
            "source": "anyrun",
            "screenshots": [{"url": "data:image/jpeg;base64,old-preview"}],
        },
    }

    collector = object.__new__(HybridAnalysisCollector)
    collector._refresh_anyrun_screenshot_metadata(result)

    shot = result["raw_summary"]["screenshots"][0]
    assert shot["url"].endswith("/download/screens/shot-1/image.jpeg")
    assert shot["thumbnail_url"].endswith("/download/thumbnails/shot-1/image.jpeg")
