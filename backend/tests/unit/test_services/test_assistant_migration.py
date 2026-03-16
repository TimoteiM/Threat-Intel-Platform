from pathlib import Path


def test_assistant_migration_exists_with_expected_tables() -> None:
    migration_path = (
        Path(__file__).resolve().parents[3]
        / "alembic"
        / "versions"
        / "009_add_ai_assistant_sessions.py"
    )

    assert migration_path.exists()

    content = migration_path.read_text(encoding="utf-8")

    assert 'revision: str = "009"' in content
    assert 'down_revision: Union[str, None] = "008"' in content
    assert "CREATE TABLE IF NOT EXISTS assistant_sessions" in content
    assert "CREATE TABLE IF NOT EXISTS assistant_entries" in content
    assert "linked_investigation_id UUID" in content
    assert "REFERENCES investigations(id) ON DELETE SET NULL" in content
    assert "REFERENCES assistant_sessions(id) ON DELETE CASCADE" in content
    assert "CREATE INDEX IF NOT EXISTS idx_assistant_sessions_created" in content
    assert "CREATE INDEX IF NOT EXISTS idx_assistant_entries_session_order" in content
