"""The sandbox recording cache: what it will fetch, and what it will not.

The endpoint in front of this builds a vendor URL from a caller-supplied id, so
the validation here is the thing standing between "play our own sandbox
recording" and "fetch anything, at our bandwidth, from a path we were handed".
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.services import anyrun_video_cache as cache

TASK = "6ab38a57-bb61-4790-a74c-031a83a293ad"


# —— what counts as a task id ——————————————————————————————————————————————

def test_a_uuid_is_a_task_id():
    assert cache.is_task_id(TASK)
    assert cache.is_task_id(TASK.upper())


@pytest.mark.parametrize("value", [
    "", "   ", "not-a-uuid", "../../etc/passwd", "6ab38a57", None,
    f"{TASK}/../../../etc/passwd", f"{TASK} ", "%2e%2e%2f",
])
def test_anything_else_is_refused(value):
    assert cache.is_task_id(value) is False


def test_the_url_is_built_from_a_fixed_host():
    """The caller supplies an id, never an address."""
    url = cache.video_url(TASK)
    assert url == f"https://content.any.run/tasks/{TASK}/download/mp4"
    assert url.startswith("https://content.any.run/")


def test_a_refused_id_never_reaches_the_network(monkeypatch):
    def explode(*_a, **_k):
        raise AssertionError("validation should have stopped this before any request")
    monkeypatch.setattr(cache.requests, "get", explode)
    assert cache.fetch("../../etc/passwd") is None


# —— expiry ————————————————————————————————————————————————————————————————

def test_a_fresh_file_is_served_from_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    path = tmp_path / f"{TASK}.mp4"
    path.write_bytes(b"video")
    assert cache.cached_if_fresh(TASK) == path


def test_a_file_past_its_day_is_not_fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    path = tmp_path / f"{TASK}.mp4"
    path.write_bytes(b"video")
    stale = time.time() - (cache.VIDEO_TTL_HOURS + 1) * 3600
    import os
    os.utime(path, (stale, stale))
    assert cache.cached_if_fresh(TASK) is None


def test_a_missing_file_is_not_fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    assert cache.cached_if_fresh(TASK) is None


def test_purge_removes_only_what_expired(tmp_path, monkeypatch):
    import os
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    fresh = tmp_path / "fresh.mp4"
    old = tmp_path / "old.mp4"
    fresh.write_bytes(b"a" * 10)
    old.write_bytes(b"b" * 20)
    stale = time.time() - (cache.VIDEO_TTL_HOURS + 2) * 3600
    os.utime(old, (stale, stale))

    result = cache.purge_expired()
    assert result["removed"] == 1
    assert result["bytes_freed"] == 20
    assert fresh.exists() and not old.exists()


def test_a_dead_partial_download_is_swept(tmp_path, monkeypatch):
    """A request that died mid-download must not leave a file that looks cached."""
    import os
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    partial = tmp_path / f"{TASK}.mp4.part"
    partial.write_bytes(b"truncated")
    dead = time.time() - cache.DOWNLOAD_TIMEOUT_SECONDS * 3
    os.utime(partial, (dead, dead))
    assert cache.purge_expired()["removed"] == 1
    assert not partial.exists()


def test_purge_on_a_directory_that_does_not_exist_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path / "nope")
    assert cache.purge_expired() == {"removed": 0, "bytes_freed": 0}


# —— finding the video wherever the report happens to nest it ——————————————

def test_the_real_nesting_is_found():
    """Where the one recording in this deployment actually sits.

    items[].domain_intelligence.raw_summary.report_excerpt.analysis.content.video
    — six levels below anything a fixed path was checking, which is why the
    player never appeared for the investigation that had one.
    """
    payload = {"items": [{"domain_intelligence": {"raw_summary": {"report_excerpt": {
        "analysis": {"content": {"video": {
            "present": True,
            "permanentUrl": f"https://content.any.run/tasks/{TASK}/download/mp4",
        }}}}}}}]}
    assert cache.find_video_reference(payload) == {
        "task_id": TASK,
        "url": f"https://content.any.run/tasks/{TASK}/download/mp4",
    }


def test_a_shallow_nesting_is_found_too():
    payload = {"video": {"present": True,
                         "permanentUrl": f"https://content.any.run/tasks/{TASK}/download/mp4"}}
    assert cache.find_video_reference(payload)["task_id"] == TASK


def test_absent_means_none():
    assert cache.find_video_reference({"video": {"present": False}}) is None
    assert cache.find_video_reference({}) is None
    assert cache.find_video_reference(None) is None


def test_a_video_url_on_another_host_is_refused():
    """A `video` key elsewhere in the document must not become a fetch target."""
    assert cache.find_video_reference(
        {"video": {"present": True, "permanentUrl": "https://evil.example/x.mp4"}}
    ) is None


def test_a_content_url_without_a_valid_task_id_is_refused():
    assert cache.find_video_reference(
        {"video": {"present": True, "permanentUrl": "https://content.any.run/tasks/../download/mp4"}}
    ) is None


def test_the_search_is_bounded():
    """Vendor JSON has no contract about its own depth."""
    deep: dict = {"video": {"present": True,
                            "permanentUrl": f"https://content.any.run/tasks/{TASK}/download/mp4"}}
    for _ in range(cache.MAX_SEARCH_DEPTH + 5):
        deep = {"nest": deep}
    assert cache.find_video_reference(deep) is None


# —— private tasks need the key that owns them ——————————————————————————————

def test_every_key_is_tried_before_giving_up(monkeypatch):
    """A private task is visible only to the account that submitted it.

    Measured on a real task: key_2 answers 200 while key_1 and key_3 answer
    403. We do not record which key ran which submission — the rotation picks
    by remaining allowance — so each is tried until one owns it.
    """
    monkeypatch.setattr(cache, "_candidate_auth_headers",
                        lambda: [{"Authorization": "API-Key a"},
                                 {"Authorization": "API-Key b"}, {}])
    seen: list = []

    class _Resp:
        def __init__(self, code):
            self.status_code = code
            self.headers = {"content-type": "video/mp4" if code == 200 else "text/plain"}
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_get(url, headers=None, timeout=None, stream=None):
        seen.append((headers or {}).get("Authorization"))
        return _Resp(200 if (headers or {}).get("Authorization") == "API-Key b" else 403)

    monkeypatch.setattr(cache.requests, "get", fake_get)
    assert cache.recording_exists(TASK) is True
    assert seen == ["API-Key a", "API-Key b"], "stops at the key that owns it"


def test_an_unauthenticated_attempt_is_kept_last():
    """Public community tasks need no key at all."""
    assert _candidate_last_is_anonymous()


def _candidate_last_is_anonymous() -> bool:
    return cache._candidate_auth_headers()[-1] == {}


def test_a_task_id_alone_is_a_candidate():
    """Our own submissions are stored as a summary with no vendor video block.

    The task id is enough to ask about; whether a recording exists is then
    confirmed by probing rather than assumed.
    """
    found = cache.find_video_reference({"items": [{"analysis_id": TASK}]})
    assert found == {"task_id": TASK, "url": cache.video_url(TASK)}


def test_a_non_uuid_analysis_id_is_not_a_candidate():
    assert cache.find_video_reference({"items": [{"analysis_id": "not-a-task"}]}) is None
