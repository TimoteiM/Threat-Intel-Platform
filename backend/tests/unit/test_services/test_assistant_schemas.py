from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import schemas


def test_assistant_session_create_schema_accepts_expected_payload() -> None:
    payload = schemas.AssistantSessionCreate(
        title="Login alert review",
        mode="alert_analysis",
        linked_investigation_id=uuid4(),
    )

    assert payload.title == "Login alert review"
    assert payload.mode == "alert_analysis"
    assert payload.source_type == "manual"


def test_assistant_entry_create_schema_requires_text() -> None:
    with pytest.raises(ValidationError):
        schemas.AssistantEntryCreate(text="")


def test_assistant_run_schema_uses_configured_provider_order_by_default() -> None:
    payload = schemas.AssistantSessionRunRequest()

    assert payload.model is None


def test_assistant_session_detail_schema_captures_entries_and_result() -> None:
    entry = schemas.AssistantEntryRead(
        id=uuid4(),
        session_id=uuid4(),
        entry_index=0,
        entry_label="alert-1",
        raw_text="raw",
        sanitized_text="sanitized",
        token_map_json={"[IP_1]": "10.0.0.1"},
        created_at=datetime.now(timezone.utc),
    )
    detail = schemas.AssistantSessionDetailResponse(
        id=uuid4(),
        title="Test session",
        mode="incident_correlation",
        status="completed",
        source_type="manual",
        linked_investigation_id=None,
        sanitization_summary_json={"emails": 1},
        result_json={"summary": "ok"},
        report_markdown="# Report",
        error=None,
        created_at=datetime.now(timezone.utc),
        updated_at=None,
        completed_at=None,
        entries=[entry],
    )

    assert detail.entries[0].entry_label == "alert-1"
    assert detail.result_json["summary"] == "ok"
