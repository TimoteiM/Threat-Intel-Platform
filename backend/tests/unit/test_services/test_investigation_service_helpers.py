import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[3]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
APP_PACKAGE_DIR = BACKEND_ROOT / "app"
app_spec = importlib.util.spec_from_file_location(
    "app",
    APP_PACKAGE_DIR / "__init__.py",
    submodule_search_locations=[str(APP_PACKAGE_DIR)],
)
assert app_spec and app_spec.loader
app_module = importlib.util.module_from_spec(app_spec)
sys.modules["app"] = app_module
app_spec.loader.exec_module(app_module)

from app.services.investigation_service import (
    InvestigationService,
    _dedupe_investigations,
    _ensure_baseline_collectors,
)


def test_baseline_collectors_are_added_when_not_explicit():
    collectors = ["dns", "http", "vt"]
    supported = {"dns", "http", "vt", "threat_feeds", "urlscan"}
    out = _ensure_baseline_collectors(
        collectors,
        supported_for_type=supported,
        explicit_request=False,
    )
    assert out == ["dns", "http", "vt", "threat_feeds", "urlscan"]


def test_explicit_collector_request_is_respected():
    collectors = ["dns", "vt"]
    supported = {"dns", "vt", "threat_feeds", "urlscan"}
    out = _ensure_baseline_collectors(
        collectors,
        supported_for_type=supported,
        explicit_request=True,
    )
    assert out == ["dns", "vt"]


def _inv(
    value: str,
    *,
    classification: str | None = None,
    created_at: datetime | None = None,
    suffix: str = "",
):
    return SimpleNamespace(
        id=f"{value}-{suffix or uuid4()}",
        domain=value,
        classification=classification,
        created_at=created_at or datetime.now(timezone.utc),
    )


def test_dedupe_investigations_keeps_newest_item_per_value():
    older = _inv(
        "findmaps-loca.com",
        classification="malicious",
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
        suffix="older",
    )
    newer = _inv(
        "findmaps-loca.com",
        classification="suspicious",
        created_at=datetime.now(timezone.utc),
        suffix="newer",
    )
    other = _inv(
        "appleid-login-check.com",
        classification="malicious",
        created_at=datetime.now(timezone.utc) - timedelta(hours=12),
        suffix="other",
    )

    out = _dedupe_investigations([older, newer, other])

    assert out == [newer, other]


@pytest.mark.asyncio
async def test_list_all_with_dedupe_keeps_newest_and_applies_pagination():
    rows = [
        _inv(
            "findmaps-loca.com",
            classification="malicious",
            created_at=datetime.now(timezone.utc) - timedelta(days=2),
            suffix="old",
        ),
        _inv(
            "findmaps-loca.com",
            classification="suspicious",
            created_at=datetime.now(timezone.utc),
            suffix="new",
        ),
        _inv(
            "icloud-secure-login.com",
            classification="malicious",
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
            suffix="other",
        ),
    ]

    service = InvestigationService(session=SimpleNamespace())
    service.repo = SimpleNamespace(list_all=AsyncMock(return_value=rows), count=AsyncMock())  # type: ignore[assignment]

    result = await service.list_all(limit=1, offset=0, dedupe=True)

    assert result == [rows[1]]
    service.repo.list_all.assert_awaited_once_with(  # type: ignore[attr-defined]
        limit=None,
        offset=0,
        state=None,
        search=None,
        observable_type=None,
        classification=None,
    )


@pytest.mark.asyncio
async def test_count_with_dedupe_returns_deduped_total_after_classification_filter():
    rows = [
        _inv(
            "findmaps-loca.com",
            classification="malicious",
            created_at=datetime.now(timezone.utc) - timedelta(days=2),
            suffix="old-mal",
        ),
        _inv(
            "findmaps-loca.com",
            classification="malicious",
            created_at=datetime.now(timezone.utc),
            suffix="new-mal",
        ),
        _inv(
            "outlook-security-reset.net",
            classification="suspicious",
            created_at=datetime.now(timezone.utc) - timedelta(hours=3),
            suffix="susp",
        ),
    ]

    service = InvestigationService(session=SimpleNamespace())
    service.repo = SimpleNamespace(list_all=AsyncMock(return_value=rows), count=AsyncMock(return_value=999))  # type: ignore[assignment]

    total = await service.count(classification="malicious", dedupe=True)

    assert total == 1
    service.repo.list_all.assert_awaited_once_with(  # type: ignore[attr-defined]
        limit=None,
        offset=0,
        state=None,
        search=None,
        observable_type=None,
        classification="malicious",
    )
