from __future__ import annotations

from app.models import database as db


def test_assistant_models_are_registered_with_expected_relationships():
    assert hasattr(db, "AssistantSession")
    assert hasattr(db, "AssistantEntry")
    assert hasattr(db, "SOCIndicator")

    assert "assistant_sessions" in db.Base.metadata.tables
    assert "assistant_entries" in db.Base.metadata.tables
    assert "soc_indicators" in db.Base.metadata.tables

    session_table = db.Base.metadata.tables["assistant_sessions"]
    entry_table = db.Base.metadata.tables["assistant_entries"]
    indicator_table = db.Base.metadata.tables["soc_indicators"]

    assert "linked_investigation_id" in session_table.c
    assert "result_json" in session_table.c
    assert "report_markdown" in session_table.c

    assert "session_id" in entry_table.c
    assert "raw_text" in entry_table.c
    assert "sanitized_text" in entry_table.c
    assert "token_map_json" in entry_table.c
    assert "indicator_type" in indicator_table.c
    assert "normalized_value" in indicator_table.c
    assert "assistant_session_id" in indicator_table.c
    assert "assistant_entry_id" in indicator_table.c

    assert db.Investigation.assistant_sessions.property.mapper.class_ is db.AssistantSession
    assert db.AssistantSession.entries.property.mapper.class_ is db.AssistantEntry
    assert db.AssistantSession.soc_indicators.property.mapper.class_ is db.SOCIndicator
    assert db.AssistantEntry.soc_indicators.property.mapper.class_ is db.SOCIndicator
