from __future__ import annotations

import uuid
from types import SimpleNamespace

import sqlalchemy.orm

from app.models.database import Evidence, Investigation
from app.tasks.analysis_task import _persist_results


class _FakeScalarResult:
    def __init__(self, scalar=None, scalars_list=None):
        self._scalar = scalar
        self._scalars_list = scalars_list or []

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return list(self._scalars_list)


class _FakeSession:
    def __init__(self, investigation: Investigation, existing_evidence: Evidence):
        self.investigation = investigation
        self.existing_evidence = existing_evidence
        self.added = []
        self.merged = []
        self.committed = False
        self._execute_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, model, key):
        if model is Investigation:
            return self.investigation
        return None

    def merge(self, obj):
        if isinstance(obj, Evidence):
            raise AssertionError("Evidence rows should be updated in place, not merged")
        self.merged.append(obj)
        return obj

    def add(self, obj):
        self.added.append(obj)

    def execute(self, *_args, **_kwargs):
        self._execute_calls += 1
        if self._execute_calls == 1:
            return _FakeScalarResult(scalar=self.existing_evidence)
        if self._execute_calls == 2:
            return _FakeScalarResult(scalars_list=[])
        return _FakeScalarResult(scalar=None)

    def commit(self):
        self.committed = True


class _SessionFactory:
    def __init__(self, session):
        self.session = session

    def __call__(self, *_args, **_kwargs):
        return self.session


def test_persist_results_updates_existing_evidence_row(monkeypatch):
    investigation_id = uuid.uuid4()
    inv = Investigation(id=investigation_id, domain="example.com", observable_type="domain", state="evaluating")
    existing = Evidence(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        evidence_json={"old": True},
        signals=[],
        data_gaps=[],
        external_context=None,
    )
    inv.evidence = existing
    fake_session = _FakeSession(inv, existing)

    monkeypatch.setattr(sqlalchemy.orm, "Session", _SessionFactory(fake_session))
    monkeypatch.setattr("app.db.session.sync_engine", object())
    monkeypatch.setattr("app.tasks.analysis_task._check_client_alerts_sync", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.tasks.analysis_task._update_batch_progress", lambda *args, **kwargs: None)

    evidence_data = {"domain": "example.com", "signals": [{"id": "sig1"}], "data_gaps": [], "external_context": {"source": "test"}}
    report_data = {
        "classification": "benign",
        "confidence": "high",
        "risk_score": 5,
        "recommended_action": "monitor",
        "executive_summary": "ok",
        "technical_narrative": "ok",
        "recommendations_narrative": "ok",
        "iocs": [],
    }

    _persist_results(str(investigation_id), evidence_data, report_data, {})

    assert fake_session.committed is True
    assert existing.evidence_json == evidence_data
    assert existing.signals == evidence_data["signals"]
    assert existing.external_context == evidence_data["external_context"]
