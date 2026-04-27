import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4


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

from app.api.dashboard import _build_recent_malicious


def _row(
    domain: str,
    *,
    created_at: datetime,
    risk_score: int = 80,
    classification: str = "malicious",
):
    return SimpleNamespace(
        id=uuid4(),
        domain=domain,
        risk_score=risk_score,
        classification=classification,
        created_at=created_at,
    )


def test_build_recent_malicious_keeps_newest_unique_domains_and_limits_to_ten():
    now = datetime.now(timezone.utc)
    rows = [
        _row("repeat.example", created_at=now - timedelta(minutes=1), risk_score=91),
        _row("repeat.example", created_at=now - timedelta(minutes=5), risk_score=40),
        _row("alpha.example", created_at=now - timedelta(minutes=2)),
        _row("bravo.example", created_at=now - timedelta(minutes=3)),
        _row("charlie.example", created_at=now - timedelta(minutes=4)),
        _row("delta.example", created_at=now - timedelta(minutes=6)),
        _row("echo.example", created_at=now - timedelta(minutes=7)),
        _row("foxtrot.example", created_at=now - timedelta(minutes=8)),
        _row("golf.example", created_at=now - timedelta(minutes=9)),
        _row("hotel.example", created_at=now - timedelta(minutes=10)),
        _row("india.example", created_at=now - timedelta(minutes=11)),
        _row("juliet.example", created_at=now - timedelta(minutes=12)),
        _row("kilo.example", created_at=now - timedelta(minutes=13)),
    ]

    result = _build_recent_malicious(rows)

    assert [item["domain"] for item in result] == [
        "repeat.example",
        "alpha.example",
        "bravo.example",
        "charlie.example",
        "delta.example",
        "echo.example",
        "foxtrot.example",
        "golf.example",
        "hotel.example",
        "india.example",
    ]
    assert len(result) == 10
    assert result[0]["risk_score"] == 91
