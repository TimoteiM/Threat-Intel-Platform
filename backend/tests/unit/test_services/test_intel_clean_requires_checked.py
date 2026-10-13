"""The intel limb of the benign precondition, against the dangerous direction.

The companion to `test_clean_requires_checked.py`, which did this for
ThreatFox. Same defect, different source, and this one is worse in three
ways, all measured on 2026-10-13:

  * the intel collector did not merely fail to answer — it failed outright
    on 2,198 consecutive runs from 2026-07-07, taking crt.sh, both DNSBLs and
    URLhaus down with a 401 from an unrelated fourth source;
  * `blocklist_hits` merges four sources, so an empty list is eight different
    claims and the payload could express only one of them;
  * there was no `checked` flag to consume. ThreatFox's existed and nothing
    read it; this one had to be built.

583 benign verdicts across 374 distinct domains were reached with this
collector dead. The tests below are the ones that would have failed then.

What the precondition does and does not reach
---------------------------------------------
Measured 2026-10-13, after the fix, on a payload clean on every other axis:

    everything asked, nothing listed        benign  high    15  monitor
    intel collector dead                    benign  medium  15  monitor
    threatfox never answered                benign  medium  15  monitor
    both dead                               benign  medium  15  monitor
    one Spamhaus DBL listing                benign  medium  15  monitor
    two listings (SURBL + Spamhaus DBL)     suspicious medium 60 investigate

So the precondition closes the **high-confidence** benign branch and nothing
more. `benign, medium, 15, monitor` is the ladder's final `else`, reached
whenever nothing escalated, and it consults no feed at all — its only guard
is `reputation_available`, which is satisfied by any non-empty
`feeds_checked`. Risk score and recommended action do not move.

That is a smaller consequence than it first looks, and it is recorded here
rather than described, because the same claim was stated too strongly in the
commit for the threatfox half of this fix. The two `xfail(strict=True)`
tests at the bottom hold the gap: if the ladder is ever changed so an
unchecked estate cannot reach benign at all, they turn into failures and ask
for this file to be updated.
"""

from __future__ import annotations

import pytest

from app.services.decision_engine import build_decision_report
from app.services.threatfox_match_scope import (
    HOST_AGGREGATE,
    intel_hits_about_observable,
)


BLOCKLIST_SOURCES = ("SURBL", "Spamhaus DBL", "URLhaus (abuse.ch)", "Spamhaus SIA")


def _clean_feeds() -> dict:
    return {"feeds_checked": ["threatfox", "google_safe_browsing"]}


def _evidence(*, intel: dict, domain: str = "ordinary-business.example") -> dict:
    """A payload that is clean on every axis except the one under test."""
    return {
        "domain": domain,
        "observable_type": "domain",
        "vt": {"found": True, "meta": {"status": "completed"},
               "malicious_count": 0, "suspicious_count": 0, "total_vendors": 70},
        "threat_feeds": _clean_feeds(),
        "whois": {"domain_age_days": 4000},
        "http": {},
        "intel": intel,
        "hybrid_analysis": {},
        "urlscan": {},
    }


def _verdict(evidence: dict, domain: str | None = None):
    if domain is not None:
        evidence["domain"] = domain
    return build_decision_report(evidence, "domain")


def test_a_source_that_answered_nothing_permits_benign():
    """The control. All four asked, none listed it — a real clean result, and
    the branch must still fire or the fix has broken benign entirely."""
    v = _verdict(_evidence(intel={
        "blocklist_hits": [],
        "sources_checked": list(BLOCKLIST_SOURCES),
        "sources_skipped": {},
    }))
    assert v["classification"] == "benign", v.get("key_evidence")


def test_a_collector_that_never_ran_does_not_permit_benign():
    """The live fault, 2,198 rows of it: every field empty because the
    collector raised, and `blocklist_hits: []` is a Pydantic default."""
    v = _verdict(_evidence(intel={
        "meta": {"status": "failed",
                 "error": "RuntimeError: Spamhaus SIA login failed: HTTP 401"},
        "blocklist_hits": [],
        "sources_checked": [],
        "sources_skipped": {},
    }))
    assert not (v["classification"] == "benign" and v["confidence"] == "high"), (
        "a collector that failed outright unlocked the high-confidence benign "
        "branch: this is the state 2,198 runs were in"
    )


def test_four_refusals_do_not_permit_benign():
    """Every source asked, every source refused. Measured: both DNSBL zones
    answer only refusal codes from this resolver."""
    v = _verdict(_evidence(intel={
        "blocklist_hits": [],
        "sources_checked": [],
        "sources_skipped": {
            s: {"absent": True, "kind": "check_failed", "reason": "refused", "raw": None}
            for s in BLOCKLIST_SOURCES
        },
    }))
    assert not (v["classification"] == "benign" and v["confidence"] == "high")


def test_evidence_with_no_checked_field_does_not_permit_benign():
    """Every row written before today. Unknown is not clean."""
    v = _verdict(_evidence(intel={"blocklist_hits": []}))
    assert not (v["classification"] == "benign" and v["confidence"] == "high")


def test_one_source_answering_is_enough():
    """Three down and one answering is a weak but real negative, and the
    estate is in exactly that state today: URLhaus answers, both DNSBLs
    refuse this resolver, and SIA has no credential."""
    v = _verdict(_evidence(intel={
        "blocklist_hits": [],
        "sources_checked": ["URLhaus (abuse.ch)"],
        "sources_skipped": {
            s: {"absent": True, "kind": "check_failed", "reason": "refused", "raw": None}
            for s in ("SURBL", "Spamhaus DBL", "Spamhaus SIA")
        },
    }))
    assert v["classification"] == "benign", v.get("key_evidence")


# ─── granularity: the other half of the instruction ───────────────────────

def test_a_host_aggregate_does_not_block_benign():
    """URLhaus reporting 9,654 malicious URLs under github.com says nothing
    about the GitHub URL we were asked about. Restoring the feed at host
    granularity would have escalated every GitHub, Discord and Google
    observable in the estate — most of them."""
    v = _verdict(
        _evidence(intel={
            "blocklist_hits": [{
                "source": "URLhaus (abuse.ch)",
                "indicator": "github.com",
                "category": HOST_AGGREGATE,
                "severity": "high",
                "details": "URLhaus holds 9654 malicious URL(s) under github.com",
            }],
            "sources_checked": ["URLhaus (abuse.ch)"],
            "sources_skipped": {},
        }),
        domain="https://github.com/sindresorhus/got",
    )
    assert v["classification"] == "benign", v.get("key_evidence")


def test_a_listing_for_another_path_does_not_block_benign():
    """The four real hits found by the 2026-10-13 re-query were all of this
    shape: a listed URL on the same host, under somebody else's path."""
    v = _verdict(
        _evidence(intel={
            "blocklist_hits": [{
                "source": "URLhaus (abuse.ch)",
                "indicator": "https://github.com/MajorRaikage45/MimiLokinil/releases/download/v2.6/Loader.v2.6.zip",
                "category": "malware_download",
                "severity": "high",
                "details": "Threat: malware_download, Status: online",
            }],
            "sources_checked": ["URLhaus (abuse.ch)"],
            "sources_skipped": {},
        }),
        domain="https://github.com/sindresorhus/got",
    )
    assert v["classification"] == "benign", v.get("key_evidence")


def test_a_listing_for_our_own_path_does_block_benign():
    """The control for the control. A guard that drops every URLhaus hit
    would pass both tests above and detect nothing — which is the shape of
    the bug this fix is for, placed inside the fix."""
    v = _verdict(
        _evidence(intel={
            "blocklist_hits": [{
                "source": "URLhaus (abuse.ch)",
                "indicator": "https://github.com/sindresorhus/got",
                "category": "malware_download",
                "severity": "high",
                "details": "Threat: malware_download, Status: online",
            }],
            "sources_checked": ["URLhaus (abuse.ch)"],
            "sources_skipped": {},
        }),
        domain="https://github.com/sindresorhus/got",
    )
    assert not (v["classification"] == "benign" and v["confidence"] == "high"), (
        "a URLhaus listing for the exact URL under investigation left the "
        "high-confidence benign branch open, so the scoping drops everything"
    )


def test_a_dnsbl_hit_always_blocks_benign():
    """A DNSBL answers the exact name it was asked about, so its indicator is
    the observable by construction and no scoping may drop it."""
    v = _verdict(_evidence(intel={
        "blocklist_hits": [{
            "source": "Spamhaus DBL",
            "indicator": "ordinary-business.example",
            "category": "blocklist",
            "severity": "high",
            "details": "Listed in Spamhaus DBL (response: 127.0.1.2)",
        }],
        "sources_checked": ["Spamhaus DBL"],
        "sources_skipped": {},
    }))
    assert not (v["classification"] == "benign" and v["confidence"] == "high")


def test_an_unknown_observable_keeps_every_hit():
    """The direction that matters: unscopable is not irrelevant. Keeping an
    unscopable hit only blocks the benign branch; dropping it unlocks it."""
    hits = [{"source": "URLhaus (abuse.ch)", "indicator": "https://x.example/p",
             "category": "malware_download"}]
    assert intel_hits_about_observable("", hits) == hits


# ─── the gap this fix does not close ──────────────────────────────────────
#
# Recorded as strict xfails rather than prose. Both are pre-existing ladder
# behaviour, neither is created by this change, and both are the kind of
# claim that is easier to assert than to remember.

@pytest.mark.xfail(
    strict=True,
    reason="The ladder's final `else` is `benign, medium, 15, monitor`, "
           "reached whenever nothing escalated and consulting no feed. Its "
           "only guard is `reputation_available`, which any non-empty "
           "feeds_checked satisfies. So an estate where every blocklist is "
           "down still reaches benign — at medium rather than high.",
)
def test_a_dead_estate_cannot_reach_benign_at_all():
    v = _verdict(_evidence(intel={"blocklist_hits": [], "sources_checked": []}))
    assert v["classification"] != "benign"


@pytest.mark.xfail(
    strict=True,
    reason="Escalation needs `len(intel_hits) >= 2`, so one listing in "
           "Spamhaus DBL — a low-false-positive blocklist — escalates "
           "nothing. Measured 2026-10-13: benign, medium, 15, monitor. The "
           "threshold also counts list entries rather than sources, and one "
           "URLhaus listing used to produce eleven entries while one DNSBL "
           "listing produces one, so the unit was never a count of anything.",
)
def test_one_reputable_blocklist_listing_is_not_benign():
    v = _verdict(_evidence(intel={
        "blocklist_hits": [{
            "source": "Spamhaus DBL", "indicator": "ordinary-business.example",
            "category": "blocklist", "severity": "high",
        }],
        "sources_checked": ["Spamhaus DBL"],
        "sources_skipped": {},
    }))
    assert v["classification"] != "benign"
