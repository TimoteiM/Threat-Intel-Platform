import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.sql import Select

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.models.database import AssistantEntry, AssistantSession
from app.services.assistant_service import AssistantService


def _report_body(markdown: str | None) -> str:
    return (markdown or "").split("\n\n---\n\n## Resolved Identifiers", 1)[0]


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
    return SimpleNamespace(
        anthropic_api_key=None,
        openai_model="gpt-5-mini",
        openai_api_key="test-key",
    )


class _ScalarResult:
    def __init__(self, items):
        self._items = items

    def all(self):
        return list(self._items)


class _ExecuteResult:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _ScalarResult(self._items)


class _CountResult:
    def __init__(self, value: int):
        self._value = value

    def scalar_one(self):
        return self._value


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
    assert "[IP_1]" in seen_prompt["user_text"]
    assert "[EMAIL_1]" in seen_prompt["user_text"]
    assert result.entries[0].sanitized_text
    fake_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_create_session_defaults_title_when_missing() -> None:
    added = []

    class FakeSession:
        def add(self, obj):
            added.append(obj)

        flush = AsyncMock()
        commit = AsyncMock()

    service = AssistantService(FakeSession(), settings=_build_settings())

    created = await service.create_session(title="", mode="alert_analysis")

    assert created.title == "Alert Analysis"
    assert added[0].title == "Alert Analysis"


@pytest.mark.asyncio
async def test_run_session_restores_sanitized_tokens_in_final_output(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = "hostname=wm-c06.siembiot.int admin@example.com from 10.0.0.1"
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Event Interpretation\n[HOST_1] observed [EMAIL_1] from 10.0.0.1."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    report_body = _report_body(result.report_markdown)
    assert "wm-c06.siembiot.int" in report_body
    assert "admin@example.com" in report_body
    assert "10.0.0.1" in report_body
    assert "[HOST_1]" not in report_body


@pytest.mark.asyncio
async def test_run_session_adds_omitted_endpoint_key_observables(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = json.dumps({
        "endpoint": {"name": "NBM0582"},
        "filters": [{
            "level": "medium",
            "name": "Uncommon File Path of Executable File",
            "tactics": ["TA0005"],
            "techniques": ["T1036"],
            "highlightedObjects": [
                {"field": "objectFileHashSha1", "value": "b74961868a4af731a7c352968413634bfb6ee9a0"},
                {"field": "objectFilePath", "value": r"C:\Users\M0534\AppData\Local\Temp\.net\BingWallpaperInstaller\11a4\Microsoft.CSharp.dll"},
                {"field": "processFilePath", "value": r"C:\Users\M0534\Downloads\BingWallpaperInstaller.exe"},
                {"field": "processCmd", "value": r'"C:\Users\M0534\Downloads\BingWallpaperInstaller.exe"'},
            ],
        }],
    })
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "## Event Interpretation\n\nInstaller-like activity was observed."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)
    report_body = _report_body(result.report_markdown)

    assert "**Key observables:**" not in report_body
    assert "BingWallpaperInstaller.exe" in report_body
    assert "Microsoft.CSharp.dll" in report_body
    assert "b74961868a4af731a7c352968413634bfb6ee9a0" in report_body
    assert "SHA-1" in report_body
    assert r"C:\Users\M0534\Downloads" not in report_body
    assert "TA0005" not in report_body


@pytest.mark.asyncio
async def test_run_session_restores_markdown_escaped_host_tokens(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = "hostname=HOST1 srcip=10.0.0.1"
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Event Interpretation\nMalicious activity on \\[HOST_1\\] from 10.0.0.1."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    report_body = _report_body(result.report_markdown)
    assert "HOST1" in report_body
    assert "[HOST_1]" not in report_body
    assert "\\[HOST_1\\]" not in report_body


@pytest.mark.asyncio
async def test_run_session_restores_windows_account_tokens(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = (
        "subjectUserName=epentilescu targetUserName=CodexSandboxUsers "
        "computer=EXP-D07DY24.int.expertware.net"
    )
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Event Interpretation\nAccount [ACCOUNT_1] created group on [HOST_1]."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    report_body = _report_body(result.report_markdown)
    assert "epentilescu" in report_body
    assert "EXP-D07DY24.int.expertware.net" in report_body
    assert "[ACCOUNT_1]" not in report_body
    assert "[HOST_1]" not in report_body


@pytest.mark.asyncio
async def test_run_session_replaces_unresolved_hallucinated_tokens(monkeypatch) -> None:
    session_obj = _build_session("alert_analysis")
    session_obj.entries[0].raw_text = "classification=Ransomware originatorProcess=svchost.exe"
    fake_db = SimpleNamespace(commit=AsyncMock())
    service = AssistantService(fake_db, settings=_build_settings())
    service._get_session = AsyncMock(side_effect=[session_obj, session_obj])  # type: ignore[attr-defined]

    async def fake_openai(*, model: str, system: str, user_text: str) -> str:
        return "# Event Interpretation\nRansomware was detected on [HOST_1]."

    monkeypatch.setattr(service, "_call_openai", fake_openai)

    result = await service.run_session(session_obj.id)

    report_body = _report_body(result.report_markdown)
    assert "the affected host" in report_body
    assert "[HOST_1]" not in report_body
    assert "Resolved Identifiers" not in (result.report_markdown or "")


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

    with pytest.raises(ValueError, match="fallback.*unavailable"):
        await service.run_session(session_obj.id)

    assert session_obj.status == "failed"
    assert "fallback" in (session_obj.error or "")
    fake_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_assistant_falls_back_to_haiku_when_openai_fails(monkeypatch) -> None:
    settings = _build_settings()
    settings.anthropic_api_key = "anthropic-test-key"
    settings.anthropic_model = "claude-haiku-4-5-20251001"
    settings.openai_model = "gpt-5.6-luna"
    service = AssistantService(SimpleNamespace(), settings=settings)
    seen = {}

    async def broken_openai(*, model: str, system: str, user_text: str) -> str:
        seen["primary"] = model
        raise RuntimeError("provider down")

    async def fake_claude(*, model: str, system: str, user_text: str) -> str:
        seen["fallback"] = model
        return "fallback report"

    monkeypatch.setattr(service, "_call_openai", broken_openai)
    monkeypatch.setattr(service, "_call_claude", fake_claude)

    result = await service._call_with_fallback(model=None, system="system", user_text="evidence")

    assert result == "fallback report"
    assert seen == {
        "primary": "gpt-5.6-luna",
        "fallback": "claude-haiku-4-5-20251001",
    }


@pytest.mark.asyncio
async def test_list_sessions_returns_paginated_matches_for_search() -> None:
    matching = _build_session("alert_analysis")
    matching.title = "Invoice phishing alert"
    fake_db = SimpleNamespace(
        execute=AsyncMock(side_effect=[_ExecuteResult([matching]), _CountResult(3)]),
    )
    service = AssistantService(fake_db, settings=_build_settings())

    result = await service.list_sessions(search="invoice", limit=10, offset=20)

    assert result["items"] == [matching]
    assert result["total"] == 3
    assert result["limit"] == 10
    assert result["offset"] == 20


@pytest.mark.asyncio
async def test_list_sessions_searches_titles_and_entry_content() -> None:
    fake_db = SimpleNamespace(execute=AsyncMock(side_effect=[_ExecuteResult([]), _CountResult(0)]))
    service = AssistantService(fake_db, settings=_build_settings())

    await service.list_sessions(search="admin@example.com", limit=25, offset=0)

    executed_query = fake_db.execute.await_args_list[0].args[0]
    assert isinstance(executed_query, Select)
    query_text = str(executed_query.compile(compile_kwargs={"literal_binds": False}))
    assert "assistant_sessions.title" in query_text
    assert "assistant_entries.raw_text" in query_text
