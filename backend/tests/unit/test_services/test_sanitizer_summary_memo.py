"""Backlog 43: the whole-input scan is memoised, and the count is unchanged.

`_replace_pattern.repl` ran `token not in text` — a scan of the entire input —
once per match. Measured on one 2,244,098-char body: 44,002 calls, 78.9s, six
distinct tokens. O(matches x length), quadratic for repetitive content, and
the realised cost was an alert that received no analysis after 1,792 seconds
of worker time.

The predicate is **memoised, not redefined**, because `entry_summary` is a
count the API serves. The obvious tidier rule — "count distinct entities" —
would have silently re-based it.

Measured before/after against the pre-change module loaded from git, over
3,000 corpus bodies: `sanitized_text`, `token_map` and `summary` all
identical in every case, and the 2.24M body went from 83.09s to 3.69s.

These tests pin the part that measurement cannot: the adversarial input where
the memoised predicate is actually *true*, which is rare in the corpus and is
exactly where a wrong rewrite would hide.
"""

from __future__ import annotations

from app.services.assistant_sanitizer_service import sanitize_entries


def test_a_repeated_value_with_its_literal_token_present_suppresses_the_count():
    """The dangerous direction, aimed at the function that changed.

    My first attempt at this test used `computername="..."`, which is handled
    by `_replace_keyed_host_pattern` — a different function that increments
    unconditionally and that I had not touched. The test passed against code
    it was not exercising. The memoised branch is `_replace_pattern`, which
    handles the context-free patterns: IP, email, SID, bare FQDN.

    Behaviour confirmed against the pre-change module loaded from git before
    this expectation was written, so it pins the old semantics rather than my
    reading of them.
    """
    body = ('note [IP_1]\n'
            'src_ip=203.0.113.9 dst=203.0.113.9 a=203.0.113.9 b=203.0.113.9\n')
    entry = sanitize_entries([body]).entries[0]
    assert entry.token_map, "nothing was tokenised; the count is vacuous"
    assert "203.0.113.9" not in entry.sanitized_text
    # Four matches of one value whose token appears literally: the first
    # counts via the special case, the rest are suppressed.
    assert entry.summary.get("ips") == 1


def test_without_the_literal_token_every_occurrence_counts():
    """The positive control. Same body, no literal token: 4, not 1.

    Without this the assertion above could be satisfied by a rewrite that
    always returns 1 — which would re-base the published count on every
    entry while passing the dangerous-direction test.
    """
    body = 'src_ip=203.0.113.9 dst=203.0.113.9 a=203.0.113.9 b=203.0.113.9\n'
    entry = sanitize_entries([body]).entries[0]
    assert entry.summary.get("ips") == 4


def test_the_memo_is_keyed_per_token_not_per_label():
    """Two values, one of whose tokens appears literally: the other still counts.

    This is the distinction a `set`-of-labels rewrite would have lost.
    """
    body = 'note [IP_1] src_ip=203.0.113.9 dst_ip=198.51.100.7\n'
    entry = sanitize_entries([body]).entries[0]
    assert entry.summary.get("ips") == 2


def test_the_first_match_counts_even_when_suppressed():
    """The `entry_summary.get(label_key, 0) == 0` special case, preserved.

    One value and its literal token: suppression applies, but the first match
    counts regardless. Dropping the special case gives 0 and reports an entry
    with a tokenised address as having tokenised none.
    """
    body = 'note [IP_1] src_ip=203.0.113.9\n'
    entry = sanitize_entries([body]).entries[0]
    assert entry.summary.get("ips") == 1
    assert "203.0.113.9" not in entry.sanitized_text


def test_the_scan_is_memoised_not_repeated():
    """The property the fix exists for, asserted rather than timed.

    A timing assertion would be flaky on shared hardware. Instead: count how
    many times the expensive operation happens, by making the input large
    enough that a per-match scan is unmistakable, and asserting the work is
    bounded by distinct tokens rather than by matches.
    """
    import app.services.assistant_sanitizer_service as mod

    scans = {"n": 0}
    real_contains = str.__contains__

    class _CountingStr(str):
        def __contains__(self, item):           # type: ignore[override]
            scans["n"] += 1
            return real_contains(self, item)

    body = _CountingStr('src_ip=10.0.0.1 computername="a.b.example.net" ' * 400)
    entry = mod.sanitize_entries([body]).entries[0]
    assert entry.token_map, "nothing was tokenised; the count below is vacuous"
    # 400 repetitions of two matchable values. A per-match scan would be in
    # the hundreds; memoised it is a handful.
    assert scans["n"] < 40, (
        f"the whole-input scan ran {scans['n']} times; it should be once per "
        f"distinct token"
    )


# ── the size limit, decided rather than defaulted ──────────────────────────

def test_a_prompt_over_the_context_ceiling_is_refused_before_the_work():
    """The 2026-08-31 case, as it would go now.

    An 11M-character body spent 1,792 seconds being sanitised and was then
    rejected by the provider: "prompt is too long: 5,284,191 tokens >
    200,000". The analyst got no narrative and the work was unrecoverable.

    Now it is refused up front, cheaply, and recorded as `withheld` rather
    than `failed` — a decision we made, not a crash.
    """
    from app.services import alert_body_ai_service as ai

    # Big enough to exceed the 180,000-token ceiling on the platform's own
    # estimator, without building 11MB in a unit test.
    body = "src_ip=203.0.113.9 host=\"alpha.corp.example.net\" " * 20_000
    report = ai.run_alert_body_ai_analysis(
        alert_body=body, title="probe",
        boundary=__import__("app.services.token_boundary", fromlist=["x"]).in_memory(
            tenant_id="t", investigation_id="i"),
    )
    assert report["status"] == "failed"
    assert report["withheld"] is True
    assert "not sent" in (report["error"] or "")
    assert "ceiling" in (report["error"] or "")


def test_an_ordinary_prompt_is_not_refused():
    """The positive control.

    A ceiling that refuses everything would pass the test above and stop the
    platform analysing anything — the RLS lesson, where six refusal tests
    were green while the feature denied every read.
    """
    from app.services import alert_body_ai_service as ai
    from app.services import token_boundary as tb

    sent = {}

    async def _capture(session_factory, *, entry_text, title, model, boundary):
        sent["text"] = entry_text
        return {"report_markdown": "ok"}

    original = ai._run_assistant
    ai._run_assistant = _capture
    try:
        report = ai.run_alert_body_ai_analysis(
            alert_body='src_ip=203.0.113.9 host="alpha.corp.example.net"',
            title="probe",
            boundary=tb.in_memory(tenant_id="t", investigation_id="i"),
        )
    finally:
        ai._run_assistant = original
    assert report["status"] == "completed"
    assert report["withheld"] is False
    assert sent["text"], "nothing reached the assistant"
