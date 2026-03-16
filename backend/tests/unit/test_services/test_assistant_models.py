from __future__ import annotations

from app.models import database as db


def test_assistant_models_are_registered_with_expected_relationships():
    assert hasattr(db, "AssistantSession")
    assert hasattr(db, "AssistantEntry")

    assert "assistant_sessions" in db.Base.metadata.tables
    assert "assistant_entries" in db.Base.metadata.tables

    session_table = db.Base.metadata.tables["assistant_sessions"]
    entry_table = db.Base.metadata.tables["assistant_entries"]

    assert "linked_investigation_id" in session_table.c
    assert "result_json" in session_table.c
    assert "report_markdown" in session_table.c

    assert "session_id" in entry_table.c
    assert "raw_text" in entry_table.c
    assert "sanitized_text" in entry_table.c
    assert "token_map_json" in entry_table.c

    assert db.Investigation.assistant_sessions.property.mapper.class_ is db.AssistantSession
    assert db.AssistantSession.entries.property.mapper.class_ is db.AssistantEntry
