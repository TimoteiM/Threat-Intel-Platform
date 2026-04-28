import asyncio
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

os.environ.setdefault("OPENAI_API_KEY", "test-key")

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

from app.api import admin as admin_api
from app.api.admin import get_api_health, router
from app.models import schemas


def test_api_health_response_schema_serializes_normalized_provider_list() -> None:
    generated_at = datetime.now(timezone.utc)
    last_checked_at = datetime.now(timezone.utc)
    reset_at = datetime.now(timezone.utc)

    payload = schemas.APIHealthResponse(
        generated_at=generated_at,
        providers=[
            schemas.APIProviderHealth(
                provider="virustotal",
                display_name="VirusTotal",
                configured=True,
                status="healthy",
                remaining=420,
                limit=500,
                unit="requests_day",
                reset_at=reset_at,
                low_quota_threshold=50,
                last_checked_at=last_checked_at,
                source="header_quota",
                error=None,
            ),
            schemas.APIProviderHealth(
                provider="abuseipdb",
                display_name="AbuseIPDB",
                configured=False,
                status="not_configured",
                remaining=None,
                limit=None,
                unit="requests_day",
                reset_at=None,
                low_quota_threshold=25,
                last_checked_at=last_checked_at,
                source="config",
                error="Missing API key",
            ),
        ],
    )

    dumped = payload.model_dump(mode="json")

    assert datetime.fromisoformat(dumped["generated_at"].replace("Z", "+00:00")) == generated_at
    assert dumped["providers"][0]["provider"] == "virustotal"
    assert dumped["providers"][0]["display_name"] == "VirusTotal"
    assert dumped["providers"][0]["configured"] is True
    assert dumped["providers"][0]["status"] == "healthy"
    assert dumped["providers"][0]["remaining"] == 420
    assert dumped["providers"][0]["limit"] == 500
    assert dumped["providers"][0]["unit"] == "requests_day"
    assert (
        datetime.fromisoformat(dumped["providers"][0]["reset_at"].replace("Z", "+00:00"))
        == reset_at
    )
    assert dumped["providers"][0]["low_quota_threshold"] == 50
    assert (
        datetime.fromisoformat(
            dumped["providers"][0]["last_checked_at"].replace("Z", "+00:00")
        )
        == last_checked_at
    )
    assert dumped["providers"][0]["source"] == "header_quota"
    assert dumped["providers"][0]["error"] is None
    assert dumped["providers"][1]["status"] == "not_configured"
    assert dumped["providers"][1]["configured"] is False


def test_api_health_response_schema_requires_provider_identifier() -> None:
    with pytest.raises(ValidationError):
        schemas.APIProviderHealth(
            provider="",
            display_name="VirusTotal",
            configured=True,
            status="healthy",
        )


def test_admin_router_exposes_api_health_path() -> None:
    routes = {(route.path, tuple(sorted(route.methods or []))) for route in router.routes}

    assert ("/api/admin/api-health", ("GET",)) in routes


def test_get_api_health_returns_normalized_response(monkeypatch):
    expected = schemas.APIHealthResponse(
        providers=[
            schemas.APIProviderHealth(
                provider="virustotal",
                display_name="VirusTotal",
                configured=True,
                status="healthy",
                remaining=400,
                limit=500,
                unit="requests/day",
                source="response_headers",
            ),
            schemas.APIProviderHealth(
                provider="urlscan",
                display_name="URLScan",
                configured=False,
                status="not_configured",
                source="configuration",
            ),
        ],
        generated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(admin_api, "get_api_health_snapshot", lambda: expected)

    result = asyncio.run(get_api_health())

    assert result == expected
