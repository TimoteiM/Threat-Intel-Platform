"""The credential expiry register — backlog item 7, and its cry-wolf failure.

Why it exists: the Spamhaus SIA token was a JWT whose `exp` decoded to
2026-05-12, the same day the integration was committed, and the intel
collector then failed on 2,198 consecutive runs for 98 days. The expiry was
in the token, in the database, readable, and nothing read it.

Why it is central rather than per-integration: each keeping a private timer
is how the first one became invisible. One register means "which credentials
are near expiry" is a question with an answer.

The dangerous direction here is **not** missing an expiry — it is reporting
everything. A 30-minute access token appearing in an expiry report for ever
makes the report noise, and a noisy report is one nobody reads, which is
functionally the same as not having it. The first version did exactly that
and it was caught on the first live run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services import credential_expiry_service as expiry


@pytest.fixture(autouse=True)
def _clean():
    expiry._SEEN.clear()
    yield
    expiry._SEEN.clear()


def _in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


# ─── the cry-wolf failure, asserted directly ─────────────────────────────

def test_a_short_lived_access_token_is_excluded_not_reported():
    """Falcon's token lasts 1,798 seconds and is refreshed on every call.
    Reporting it as near-expiry would put every integration in the report
    permanently."""
    expiry.record(tenant_id="c00", tool="falcon", token_status={
        "expires_at": _in(1798), "expires_in_seconds": 1798,
        "near_expiry": False,
    })
    report = expiry.report()
    assert report["near_expiry"] == []
    assert report["observed"] == []
    # Excluded, and the exclusion is visible rather than silent.
    assert report["short_lived_tokens_excluded"] == 1


def test_the_tokens_own_near_expiry_flag_does_not_decide_it():
    """The bug the first version had: it keyed on the token's own flag,
    which a freshly-issued short token sets to False — so the token fell
    through and was reported against the 14-day horizon."""
    expiry.record(tenant_id="c00", tool="falcon", token_status={
        "expires_at": _in(1798), "expires_in_seconds": 1798,
        "near_expiry": False,          # fresh token says it is fine
    })
    assert expiry.report()["near_expiry"] == []


# ─── the control: a real expiry must still be reported ───────────────────

def test_a_long_lived_credential_near_expiry_is_named():
    """The Spamhaus case. A credential that will not be refreshed in the
    ordinary course of work and is running out."""
    expiry.record(tenant_id="c00", tool="falcon", token_status={
        "expires_at": _in(3 * 86400), "near_expiry": False,
    })
    report = expiry.report()
    assert len(report["near_expiry"]) == 1
    entry = report["near_expiry"][0]
    assert entry["tenant_id"] == "c00" and entry["tool"] == "falcon"


def test_a_long_lived_credential_with_time_left_is_observed_not_flagged():
    expiry.record(tenant_id="c00", tool="falcon", token_status={
        "expires_at": _in(90 * 86400),
    })
    report = expiry.report()
    assert report["near_expiry"] == []
    assert len(report["observed"]) == 1


def test_an_already_expired_credential_is_flagged():
    expiry.record(tenant_id="c00", tool="other", token_status={
        "expires_at": _in(-86400),
    })
    assert len(expiry.report()["near_expiry"]) == 1


# ─── it never holds a token ──────────────────────────────────────────────

def test_a_token_value_is_stripped_if_one_is_passed():
    """Defensive: the one key that must never arrive here."""
    expiry.record(tenant_id="c00", tool="falcon", token_status={
        "expires_at": _in(90 * 86400), "access_token": "tok-secret-value",
    })
    assert "tok-secret-value" not in str(expiry.report())


# ─── absence is not agreement ────────────────────────────────────────────

def test_an_unobserved_credential_is_absent_rather_than_healthy():
    """A credential this process has never fetched a token for does not
    appear — and the note says so, because an empty report must not read as
    'everything is fine'."""
    report = expiry.report()
    assert report["observed"] == []
    assert "absence is not agreement" in report["note"]


def test_forget_drops_an_observation():
    expiry.record(tenant_id="c00", tool="falcon",
                  token_status={"expires_at": _in(90 * 86400)})
    assert len(expiry.report()["observed"]) == 1
    expiry.forget(tenant_id="c00", tool="falcon")
    assert expiry.report()["observed"] == []
