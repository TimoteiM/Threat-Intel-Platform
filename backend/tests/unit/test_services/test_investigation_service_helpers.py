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
        has_video=None,
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


# --- observable length: the 500 that should have been a 400 (2026-10-26) ----

#: The URL that was reported. A Hornetsecurity ATP-scan wrapper carrying a
#: Barracuda linkprotect URL, which carries the real destination
#: double-percent-encoded. 819 characters. Shortened here to its shape — the
#: length is what the test is about, and the live destination is phishing
#: infrastructure that does not belong in a fixture.
_ATP_WRAPPER = (
    "https://atpscan.global.hornetsecurity.com/?d=" + "d" * 60
    + "&f=" + "f" * 64 + "&i=&k=KEn4&m=" + "m" * 120 + "&n=" + "n" * 88
    + "&r=" + "r" * 64 + "&s=" + "s" * 64
    + "&u=https%3A%2F%2Flinkprotect.cudasvc.com%2Furl%3Fa%3Dhttps%253a%252f%252f"
    + "e" * 60 + ".example%26amp%3Bc%3D" + "c" * 100 + "%26amp%3Btypo%3D1"
)


def test_the_service_limit_matches_the_column_it_writes_to():
    """**The drift between these two IS the defect.**

    `investigations.domain` was varchar(512) and the service checked nothing,
    so an 819-character URL reached the insert, Postgres raised
    StringDataRightTruncation, SQLAlchemy surfaced it as DataError — and
    DataError is not ValueError, which is all the endpoint catches. An input
    error became a 500 with no indication that a shorter URL would work.

    Asserting them equal is what stops the next widening or narrowing from
    re-opening it silently.
    """
    from app.models.database import Investigation
    from app.services.investigation_service import MAX_OBSERVABLE_CHARS

    column_width = Investigation.__table__.c.domain.type.length
    assert MAX_OBSERVABLE_CHARS == column_width, (
        f"the service accepts {MAX_OBSERVABLE_CHARS} characters and the column "
        f"holds {column_width}; whichever is larger produces a 500"
    )


def test_a_mail_rewrapped_url_fits():
    """The reported case. ATP-scan and linkprotect wrappers routinely produce
    URLs of this length, and a SOC is sent them constantly — the wrapper is
    exactly what arrives in a phishing report."""
    from app.services.investigation_service import MAX_OBSERVABLE_CHARS

    assert 512 < len(_ATP_WRAPPER) <= MAX_OBSERVABLE_CHARS, (
        f"fixture is {len(_ATP_WRAPPER)} chars; it must be longer than the old "
        f"512 limit and within the new one, or it tests nothing"
    )


def test_an_over_long_observable_raises_ValueError_not_something_else():
    """The dangerous direction: whatever the limit is, exceeding it must be
    the exception type the endpoint converts to a 400. A DataError here is the
    original bug wearing a larger number."""
    import asyncio

    from app.models.schemas import InvestigationCreate
    from app.services.investigation_service import (
        MAX_OBSERVABLE_CHARS, InvestigationService,
    )

    too_long = "https://example.com/?x=" + "a" * (MAX_OBSERVABLE_CHARS + 1)
    request = InvestigationCreate(domain=too_long, observable_type="url")
    with pytest.raises(ValueError) as caught:
        asyncio.run(InvestigationService(None).create(request))
    # And it must say what to do, not merely that something was wrong.
    assert str(MAX_OBSERVABLE_CHARS) in str(caught.value).replace(",", "")


def test_a_normal_url_is_still_accepted():
    """The complement. A guard that rejected ordinary URLs would be worse than
    the bug it replaced."""
    from app.services.investigation_service import MAX_OBSERVABLE_CHARS

    assert len("https://example.com/login?id=994") <= MAX_OBSERVABLE_CHARS


def test_a_long_observable_shortens_the_headline_instead_of_failing_the_story():
    """The reported symptom: "the AI case story has not been completed".

    `CaseStory.headline` is `Field(max_length=180)` and the headline was the
    one field built without a slice while every neighbour has one. An
    819-character mail-rewrapped URL produced "suspicious assessment for <the
    whole URL>", Pydantic raised `string_too_long`, and the entire case story
    was dropped with a WARNING while the rest of the investigation concluded
    normally — a finished report with no story and nothing saying why.
    """
    from app.services.investigation_case_story_service import (
        HEADLINE_MAX, CaseStory, _headline,
    )

    headline = _headline("suspicious", _ATP_WRAPPER)
    assert len(headline) <= HEADLINE_MAX
    assert headline.startswith("suspicious assessment for ")
    # And it must actually satisfy the model, which is the thing that broke.
    CaseStory.model_validate({
        "headline": headline, "what_happened": "x", "why_it_matters": "y",
        "score_explanation": "z", "campaign_assessment": "none",
        "soc_handoff_markdown": "none",
    } | {k: [] for k in (
        "score_components", "strongest_evidence", "contradicting_evidence",
        "timeline", "changes_since_last_run", "recommended_actions")})


def test_the_headline_keeps_both_ends_of_a_long_url():
    """Elided in the middle, not cut at the end. The tail of a URL is where
    the interesting path usually is, and a headline ending mid-parameter reads
    as corruption rather than as a deliberate shortening."""
    from app.services.investigation_case_story_service import _headline

    headline = _headline("suspicious", _ATP_WRAPPER)
    assert "…" in headline
    assert _ATP_WRAPPER[:30] in headline, "the start of the URL was lost"
    assert headline.endswith(_ATP_WRAPPER[-12:]), "the end of the URL was lost"


def test_a_short_observable_is_left_exactly_as_it_is():
    """The complement: a rule that elided ordinary observables would make
    every headline worse to fix a rare one."""
    from app.services.investigation_case_story_service import _headline

    assert _headline("benign", "example.com") == "benign assessment for example.com"
    assert "…" not in _headline("benign", "example.com")
