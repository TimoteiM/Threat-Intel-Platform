"""Tests for the get_investigation CLI (storage fully mocked)."""

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Importing app.db builds (but never connects) the engines, which needs settings.
# All database access below is mocked; the URLs point at an unresolvable host so
# nothing can reach a real database even by accident.
os.environ.setdefault("ANTHROPIC_API_KEY", "test-placeholder")
os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@invalid.invalid/test"
os.environ["DATABASE_SYNC_URL"] = "postgresql+psycopg2://test:test@invalid.invalid/test"

from scripts import get_investigation as cli  # noqa: E402


RUN_ID = uuid.UUID("3fa5f320-b3fd-4a6d-a1c2-d7046a234303")
CREATED = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
CONCLUDED = datetime(2026, 10, 1, 12, 0, 25, tzinfo=timezone.utc)


def _investigation():
    return SimpleNamespace(
        id=RUN_ID,
        domain="example.com",
        state="concluded",
        context="SOC ticket 123",
        classification="suspicious",
        confidence="medium",
        risk_score=62,
        recommended_action="investigate",
        analyst_iterations=1,
        created_at=CREATED,
        updated_at=None,
        concluded_at=CONCLUDED,
    )


def _mock_repos(inv=None, evidence=None, report=None, collector_results=()):
    """Patch the repository classes used by the CLI with async fakes."""
    inv_repo = MagicMock(get=AsyncMock(return_value=inv))
    ev_repo = MagicMock(get=AsyncMock(return_value=evidence))
    rep_repo = MagicMock(get_latest=AsyncMock(return_value=report))
    cr_repo = MagicMock(
        get_all_for_investigation=AsyncMock(return_value=list(collector_results))
    )
    return (
        patch.object(cli, "InvestigationRepository", return_value=inv_repo),
        patch.object(cli, "EvidenceRepository", return_value=ev_repo),
        patch.object(cli, "ReportRepository", return_value=rep_repo),
        patch.object(cli, "CollectorResultRepository", return_value=cr_repo),
    )


def _fetch(**repos):
    p1, p2, p3, p4 = _mock_repos(**repos)
    with p1, p2, p3, p4:
        return asyncio.run(cli.fetch_investigation(MagicMock(), RUN_ID))


class TestFetchInvestigation:

    def test_returns_none_when_missing(self):
        assert _fetch(inv=None) is None

    def test_includes_report_evidence_and_collectors(self):
        report = SimpleNamespace(
            iteration=1,
            report_json={"classification": "suspicious", "risk_score": 62},
        )
        evidence = SimpleNamespace(
            evidence_json={"domain": "example.com", "dns": {"a": ["93.184.216.34"]}}
        )
        collector = SimpleNamespace(
            collector_name="dns",
            status="completed",
            duration_ms=150,
            error=None,
            completed_at=CONCLUDED,
        )

        result = _fetch(
            inv=_investigation(),
            evidence=evidence,
            report=report,
            collector_results=[collector],
        )

        assert result["investigation"]["id"] == str(RUN_ID)
        assert result["investigation"]["domain"] == "example.com"
        assert result["investigation"]["context"] == "SOC ticket 123"
        assert result["investigation"]["created_at"] == CREATED.isoformat()
        assert result["investigation"]["updated_at"] is None
        assert result["report"] == report.report_json
        assert result["report_iteration"] == 1
        assert result["evidence"] == evidence.evidence_json
        assert result["collector_results"] == [{
            "collector": "dns",
            "status": "completed",
            "duration_ms": 150,
            "error": None,
            "completed_at": CONCLUDED.isoformat(),
        }]

    def test_in_progress_investigation_has_no_report_or_evidence(self):
        result = _fetch(inv=_investigation())
        assert result["report"] is None
        assert result["report_iteration"] is None
        assert result["evidence"] is None
        assert result["collector_results"] == []

    def test_queries_by_run_id(self):
        p1, p2, p3, p4 = _mock_repos(inv=_investigation())
        with p1 as inv_cls, p2 as ev_cls, p3 as rep_cls, p4:
            asyncio.run(cli.fetch_investigation(MagicMock(), RUN_ID))
        inv_cls.return_value.get.assert_awaited_once_with(RUN_ID)
        ev_cls.return_value.get.assert_awaited_once_with(RUN_ID)
        rep_cls.return_value.get_latest.assert_awaited_once_with(RUN_ID)


class TestMain:

    def test_invalid_run_id_exits_without_db(self, capsys):
        with patch.object(cli, "_fetch_from_db", new=AsyncMock()) as fetch:
            assert cli.main(["5cg2280b4s"]) == cli.EXIT_INVALID_ID
        fetch.assert_not_called()
        assert "Invalid run ID" in capsys.readouterr().err

    def test_not_found(self, capsys):
        with patch.object(cli, "_fetch_from_db", new=AsyncMock(return_value=None)):
            assert cli.main([str(RUN_ID)]) == cli.EXIT_NOT_FOUND
        assert "not found" in capsys.readouterr().err

    def test_prints_json(self, capsys):
        payload = {"investigation": {"id": str(RUN_ID)}, "report": {}, "evidence": {}}
        with patch.object(
            cli, "_fetch_from_db", new=AsyncMock(return_value=payload)
        ) as fetch:
            assert cli.main([str(RUN_ID)]) == 0

        fetch.assert_awaited_once_with(RUN_ID)
        out = json.loads(capsys.readouterr().out)
        assert out["investigation"]["id"] == str(RUN_ID)
        assert "exported_at" in out

    def test_writes_output_file(self, tmp_path):
        target = tmp_path / "inv.json"
        payload = {"investigation": {"id": str(RUN_ID)}}
        with patch.object(cli, "_fetch_from_db", new=AsyncMock(return_value=payload)):
            assert cli.main([str(RUN_ID), "--output", str(target)]) == 0
        assert json.loads(target.read_text())["investigation"]["id"] == str(RUN_ID)

    @pytest.mark.parametrize("raw", [
        str(RUN_ID).upper(),
        f"  {RUN_ID}  ",
    ])
    def test_accepts_uuid_variants(self, raw):
        with patch.object(
            cli, "_fetch_from_db", new=AsyncMock(return_value=None)
        ) as fetch:
            cli.main([raw])
        fetch.assert_awaited_once_with(RUN_ID)
