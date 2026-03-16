from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.database import Investigation
from app.services.assistant_service import AssistantService


@pytest.mark.asyncio
async def test_create_from_investigation_creates_linked_session_and_preload(monkeypatch) -> None:
    investigation_id = uuid4()
    investigation = Investigation(
        id=investigation_id,
        domain="example.com",
        observable_type="domain",
        state="concluded",
        risk_score=42,
    )
    fake_result = SimpleNamespace(scalar_one_or_none=lambda: investigation)
    fake_db = SimpleNamespace(execute=AsyncMock(return_value=fake_result), commit=AsyncMock())

    service = AssistantService(
        fake_db,
        settings=SimpleNamespace(openai_model="gpt-5-mini", openai_api_key="test-key"),
    )

    created_session = SimpleNamespace(id=uuid4())
    reloaded_session = SimpleNamespace(id=created_session.id, linked_investigation_id=investigation_id)
    service.create_session = AsyncMock(return_value=created_session)  # type: ignore[method-assign]
    service.add_entry = AsyncMock()  # type: ignore[method-assign]
    service._get_session = AsyncMock(return_value=reloaded_session)  # type: ignore[attr-defined]

    result = await service.create_from_investigation(investigation_id)

    assert result.linked_investigation_id == investigation_id
    service.create_session.assert_awaited()
    service.add_entry.assert_awaited()
    preload_text = service.add_entry.await_args.kwargs["text"]
    assert "Investigation domain: example.com" in preload_text
    assert "Risk score: 42" in preload_text
