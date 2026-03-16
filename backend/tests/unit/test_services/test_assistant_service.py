from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.database import AssistantEntry, AssistantSession
from app.services.assistant_service import AssistantService


def _build_session(mode: str = "alert_analysis") -> AssistantSession:
    session = AssistantSession(
        id=uuid4(),
        title="Test session",
        mode=mode,
        status="draft",
        source_type="manual",
    )
    session.entries = [
        AssistantEntry(
            id=uuid4(),
            session_id=session.id,
            entry_index=0,
            entry_label="entry-1",
            raw_text="User admin@example.com from 10.0.0.1",
            sanitized_text="",
            token_map_json={},
        )
    ]
    return session


def _build_settings() -> SimpleNamespace:
    return SimpleNamespace(openai_model="gpt-5-mini", openai_api_key="test-key")


@pytest.mark.asyncio
async def test_run_session_persists_alert_result_without_sending_raw_text(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(return_value=session_obj)  # type: ignore[attr-defined]

    seen_prompt = {}

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        seen_prompt["user_text"] = user_text
        return "# Executive Summary\nAlert is suspicious."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    assert result.report_markdown.startswith("# Executive Summary")
    assert result.status == "completed"
    assert "admin@example.com" not in seen_prompt["user_text"]
    assert "10.0.0.1" not in seen_prompt["user_text"]
    assert "[EMAIL_1]" in seen_prompt["user_text"]
    assert "[IP_1]" in seen_prompt["user_text"]
    assert result.entries[0].sanitized_text
    fake_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_run_session_restores_sanitized_tokens_in_final_output(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = "hostname=wm-c06.siembiot.int admin@example.com from 10.0.0.1"
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Event Interpretation\n[HOST_1] observed [EMAIL_1] from [IP_1]."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    assert "wm-c06.siembiot.int" in (result.report_markdown or "")
    assert "admin@example.com" in (result.report_markdown or "")
    assert "10.0.0.1" in (result.report_markdown or "")
    assert "[HOST_1]" not in (result.report_markdown or "")


@pytest.mark.asyncio
async def test_run_session_persists_incident_result(monkeypatch) -> None:
    session_obj = _build_session("incident_correlation")
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(return_value=session_obj)  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Executive Summary\nCorrelated incident."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    assert result.status == "completed"
    assert result.result_json["mode"] == "incident_correlation"


@pytest.mark.asyncio
async def test_run_session_returns_reloaded_session_after_commit(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    reloaded = _build_session("alert_analysis")
    reloaded.id = session_obj.id
    reloaded.status = "completed"
    reloaded.report_markdown = "# Executive Summary\nReloaded."
    reloaded.updated_at = datetime.now(timezone.utc)
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, reloaded])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Executive Summary\nReloaded."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    assert result is reloaded
    assert service._get_session.await_count == 2  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_run_session_marks_failed_when_openai_errors(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(return_value=session_obj)  # type: ignore[attr-defined]

    async def broken_openai(*, model: str, system: str, user_text: str) -> str:
        raise RuntimeError("provider down")

    monkeypatch.setattr(service, "_call_openai", broken_openai)

    with pytest.raises(RuntimeError):
        await service.run_session(session_obj.id)

    assert session_obj.status == "failed"
    assert "provider down" in (session_obj.error or "")
    fake_db.commit.assert_awaited()
