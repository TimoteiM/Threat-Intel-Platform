from app.tasks.investigation_task import _build_timeout_result


def test_build_timeout_result_marks_failed_with_error_meta():
    result = _build_timeout_result("urlscan")
    assert result["collector"] == "urlscan"
    assert result["status"] == "failed"
    assert result["meta"]["status"] == "failed"
    assert "timed out" in str(result["meta"]["error"]).lower()
    assert result["evidence"]["meta"]["collector"] == "urlscan"
