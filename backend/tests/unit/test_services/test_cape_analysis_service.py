"""The sandbox-analysis record: idempotency, audited transitions, and secrecy.

The database is faked rather than real, matching the rest of this suite. What
is being tested is the decision logic — which of two racing callers wins, what
the audit trail records, and what may appear in an API response.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.services import cape_analysis_service as svc

SHA = "a" * 64


class Row:
    """Stands in for a SandboxAnalysis without needing Postgres."""

    def __init__(self, **kw):
        self.id = kw.get("id", "11111111-1111-1111-1111-111111111111")
        self.status = kw.get("status", svc.STATUS_QUEUED)
        self.sha256 = kw.get("sha256", SHA)
        self.sha1 = None
        self.md5 = None
        self.provider = svc.PROVIDER_CAPE
        self.client = kw.get("client")
        self.sample_name = kw.get("sample_name")
        self.sample_size = None
        self.sample_type = None
        self.investigation_id = None
        self.alert_run_id = None
        self.artifact_id = None
        self.idempotency_key = kw.get("idempotency_key", "k")
        self.target_kind = kw.get("target_kind", "file")
        self.target_url = kw.get("target_url")
        self.policy_version = svc.ANALYSIS_POLICY_VERSION
        self.run_seq = 1
        self.provider_task_id = kw.get("provider_task_id")
        self.reused_existing = False
        self.verdict = None
        self.malscore = None
        self.normalized_json = {}
        self.raw_summary = {}
        self.state_history = []
        self.error = None
        self.poll_attempts = 0
        self.deadline_at = kw.get("deadline_at")
        self.requested_by = kw.get("requested_by")
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = None
        self.submitted_at = None
        self.completed_at = None


class Result:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def first(self):
        return self._value


class FakeDB:
    def __init__(self, existing=None, *, raise_on_commit=False, after_conflict=None):
        self.existing = existing
        self.raise_on_commit = raise_on_commit
        self.after_conflict = after_conflict
        self.added = []
        self.commits = 0
        self.rolled_back = False
        self._commit_count = 0

    def execute(self, *_a, **_k):
        if self.rolled_back and self.after_conflict is not None:
            return Result(self.after_conflict)
        return Result(self.existing)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self._commit_count += 1
        if self.raise_on_commit and self._commit_count == 1:
            raise IntegrityError("duplicate", {}, Exception("unique violation"))
        self.commits += 1

    def rollback(self):
        self.rolled_back = True

    def refresh(self, _row):
        pass


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_the_key_covers_tenant_sample_provider_and_policy():
    key = svc.make_idempotency_key(client="ACME", sha256=SHA)
    assert key.split("|") == ["acme", SHA, "cape", svc.ANALYSIS_POLICY_VERSION, "1"]


def test_two_tenants_with_the_same_sample_get_separate_analyses():
    assert svc.make_idempotency_key(client="a", sha256=SHA) != svc.make_idempotency_key(client="b", sha256=SHA)


def test_a_deliberate_rerun_changes_the_key():
    assert svc.make_idempotency_key(client="a", sha256=SHA) != svc.make_idempotency_key(
        client="a", sha256=SHA, run_seq=2
    )


def test_an_existing_analysis_is_returned_rather_than_a_second_one_created():
    existing = Row()
    db = FakeDB(existing=existing)
    row, created = svc.get_or_create(db, sha256=SHA)
    assert row is existing and created is False
    assert db.added == [], "a duplicate submission must not create a row"


def test_a_race_between_two_workers_converges_on_one_analysis():
    """Both callers insert; the loser catches the unique violation and adopts
    the winner's row. This is the ordinary outcome of two workers, not an error."""
    winner = Row()
    db = FakeDB(existing=None, raise_on_commit=True, after_conflict=winner)
    row, created = svc.get_or_create(db, sha256=SHA)
    assert row is winner and created is False
    assert db.rolled_back is True


def test_a_new_analysis_is_created_when_there_is_none():
    db = FakeDB(existing=None)
    row, created = svc.get_or_create(db, sha256=SHA, client="acme", requested_by="timotei")
    assert created is True
    assert row.status == svc.STATUS_QUEUED
    assert row.requested_by == "timotei"
    assert row.deadline_at is not None, "an analysis must have a polling deadline"


def test_a_bad_digest_is_refused():
    with pytest.raises(ValueError):
        svc.get_or_create(FakeDB(), sha256="nope")


# ── Audited transitions ──────────────────────────────────────────────────────


def test_every_transition_is_recorded_with_who_and_when():
    row, db = Row(), FakeDB()
    svc.transition(db, row, svc.STATUS_SUBMITTING, actor="timotei", note="pressed submit")
    svc.transition(db, row, svc.STATUS_SUBMITTED, actor="worker")

    assert row.status == svc.STATUS_SUBMITTED
    assert [e["status"] for e in row.state_history] == [svc.STATUS_SUBMITTING, svc.STATUS_SUBMITTED]
    assert row.state_history[0]["actor"] == "timotei"
    assert row.state_history[0]["from"] == svc.STATUS_QUEUED
    assert row.state_history[0]["note"] == "pressed submit"
    assert row.state_history[1]["actor"] == "worker"
    assert all(e["at"] for e in row.state_history)


def test_the_history_is_reassigned_so_postgres_actually_stores_it():
    """An in-place append to a JSONB list is invisible to SQLAlchemy."""
    row, db = Row(), FakeDB()
    before = row.state_history
    svc.transition(db, row, svc.STATUS_RUNNING)
    assert row.state_history is not before


def test_reaching_a_terminal_state_stamps_completion():
    row, db = Row(), FakeDB()
    svc.transition(db, row, svc.STATUS_FAILED, error="CAPE said no")
    assert row.completed_at is not None
    assert row.error == "CAPE said no"


def test_submission_stamps_the_submitted_time_once():
    row, db = Row(), FakeDB()
    svc.transition(db, row, svc.STATUS_SUBMITTED)
    first = row.submitted_at
    svc.transition(db, row, svc.STATUS_SUBMITTED)
    assert row.submitted_at == first


def test_an_unknown_state_is_refused():
    with pytest.raises(ValueError):
        svc.transition(FakeDB(), Row(), "exploded")


def test_the_state_vocabulary_is_the_documented_one():
    assert set(svc.ALL_STATUSES) == {
        "queued", "submitting", "submitted", "pending", "running",
        "processing", "reported", "failed", "timed_out", "cancelled",
    }


def test_only_finished_failures_may_be_retried():
    assert svc.RETRYABLE_STATUSES == {"failed", "timed_out", "cancelled"}
    assert svc.STATUS_REPORTED not in svc.RETRYABLE_STATUSES


# ── Deadlines ────────────────────────────────────────────────────────────────


def test_an_analysis_past_its_deadline_is_expired():
    past = Row(deadline_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    future = Row(deadline_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert svc.is_expired(past) is True
    assert svc.is_expired(future) is False
    assert svc.is_expired(Row(deadline_at=None)) is False


def test_a_naive_deadline_is_treated_as_utc_rather_than_crashing():
    row = Row(deadline_at=(datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None))
    assert svc.is_expired(row) is True


# ── What an API may return ───────────────────────────────────────────────────


def test_the_public_view_never_carries_the_credential():
    row = Row(client="acme", provider_task_id="501")
    row.raw_summary = {"provider": "cape", "task_id": 501}
    payload = svc.to_public_dict(row)
    serialized = repr(payload).lower()
    for forbidden in ("token", "authorization", "cape_api", "secret", "bearer"):
        assert forbidden not in serialized, f"{forbidden} must not appear in an API payload"
    assert payload["provider_task_id"] == "501"


def test_the_public_view_carries_the_audit_trail_and_limitations():
    row = Row(sample_name="invoice.pdf")
    svc.transition(FakeDB(), row, svc.STATUS_RUNNING, actor="worker")
    payload = svc.to_public_dict(row)
    assert payload["state_history"][-1]["status"] == svc.STATUS_RUNNING
    assert payload["limitations"], "a PDF must carry its guest-image limitation"


# ── Guest-image limitations ──────────────────────────────────────────────────


def test_a_pdf_is_flagged_because_no_reader_is_installed():
    notes = svc.sample_limitations(sample_name="statement.PDF")
    assert notes and "PDF" in notes[0]
    assert "not evidence that the file is safe" in notes[0]


def test_other_file_types_are_not_blocked_by_the_pdf_limitation():
    for name in ("invoice.exe", "macro.docm", "script.js", "archive.zip"):
        assert svc.sample_limitations(sample_name=name) == []


def test_the_limitation_is_found_by_declared_type_too():
    assert svc.sample_limitations(sample_name="blob", sample_type="PDF document") != []


# ── URL targets ──────────────────────────────────────────────────────────────


def test_a_url_analysis_is_identified_by_its_url():
    key = svc.make_idempotency_key(client="acme", target_url="http://evil.test/a", target_kind="url")
    assert key.split("|")[1] == "url:http://evil.test/a"


def test_urls_that_mean_the_same_page_are_one_analysis():
    """Otherwise a trailing slash detonates the same page twice."""
    a = svc.make_idempotency_key(client="acme", target_url="Evil.TEST/a/", target_kind="url")
    b = svc.make_idempotency_key(client="acme", target_url="http://evil.test/a", target_kind="url")
    assert a == b


def test_a_url_and_a_file_never_collide():
    assert svc.make_idempotency_key(client="a", sha256=SHA) != svc.make_idempotency_key(
        client="a", target_url="http://x.test", target_kind="url"
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "http://example.com"),
        ("HTTPS://Example.com:443/a/", "https://example.com/a"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        ("", ""),
    ],
)
def test_url_normalisation(raw, expected):
    assert svc.normalise_url(raw) == expected


def test_a_url_analysis_needs_a_url_and_a_file_analysis_needs_a_digest():
    with pytest.raises(ValueError):
        svc.get_or_create(FakeDB(), target_kind="url", target_url="")
    with pytest.raises(ValueError):
        svc.get_or_create(FakeDB(), target_kind="file", sha256=None)


def test_a_url_analysis_records_its_target():
    db = FakeDB(existing=None)
    row, created = svc.get_or_create(db, target_kind="url", target_url="Evil.test/Path/")
    assert created is True
    assert row.target_kind == "url"
    assert row.target_url == "http://evil.test/Path"
    assert row.sha256 is None
