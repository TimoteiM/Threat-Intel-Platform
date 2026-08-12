"""
The analyst-agent leg of run_analysis, end to end with a stub agent.

The load-bearing assertion is `test_decision_engine_overrides_the_analyst_verdict`: the
deterministic decision engine owns classification, confidence, risk_score,
recommended_action and risk_rationale, and `apply_decision_to_report` overwrites whatever
the model proposed. Two runs over identical evidence must produce the same verdict — that
is the product. If someone removes either overlay call in run_analysis, this fails.

Offline: no agent is ever built and no model is constructed.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

import app.tasks.analysis_task as analysis_task
from app.models.schemas import AnalystReport

# Evidence the decision engine reads as malicious: heavy VT consensus plus a verified
# phishing feed hit.
MALICIOUS_RESULTS = [
    {
        "collector": "vt",
        "status": "completed",
        "evidence": {
            "found": True,
            "malicious_count": 30,
            "suspicious_count": 5,
            "total_vendors": 90,
            "meta": {"status": "completed", "duration_ms": 10},
        },
        "artifacts": {},
    },
    {
        "collector": "threat_feeds",
        "status": "completed",
        "evidence": {
            "openphish": {"listed": True},
            "meta": {"status": "completed", "duration_ms": 5},
        },
        "artifacts": {},
    },
]

# Deliberately wrong on every canonical field.
WRONG_VERDICT = {
    "classification": "benign",
    "confidence": "high",
    "investigation_state": "concluded",
    "primary_reasoning": "Looks fine to me.",
    "legitimate_explanation": "",
    "malicious_explanation": "",
    "recommended_action": "monitor",
    "risk_score": 5,
    "findings": [],
    "iocs": [],
    "executive_summary": "Nothing to see here.",
}


@pytest.fixture
def isolated_task(monkeypatch):
    """
    run_analysis with persistence and progress publishing stubbed out.

    The case-story leg is left alone — it imports its builder function-locally and traps
    its own errors, so it needs no stub and exercises one more real code path.
    """
    monkeypatch.setattr(analysis_task, "_persist_results", lambda *a, **k: None)
    monkeypatch.setattr(analysis_task, "_publish_progress", lambda *a, **k: None)
    return analysis_task


def _run(analyst_return):
    return analysis_task.run_analysis(
        MALICIOUS_RESULTS,
        domain="evil-phish.tk",
        investigation_id="inv-test",
        observable_type="domain",
    )


def test_decision_engine_overrides_the_analyst_verdict(isolated_task, monkeypatch):
    """The single assertion that matters: the engine wins, the model contributes prose."""
    monkeypatch.setattr(
        analysis_task,
        "_run_analyst_sync",
        lambda evidence_data, **kwargs: (dict(WRONG_VERDICT), "structured", "gpt-5.6-luna"),
    )

    report = _run(WRONG_VERDICT)["report"]

    assert report["classification"] == "malicious"
    assert report["recommended_action"] == "block"
    assert report["risk_score"] and report["risk_score"] >= 70
    # Provenance is stamped, so a stored report says which half decided.
    assert report["decision_engine"]["source"] == "deterministic"
    assert "classification" in report["decision_engine"]["canonical_fields"]


def test_two_runs_over_identical_evidence_agree(isolated_task, monkeypatch):
    """Determinism is the promise; only the narrative may differ between runs."""
    narratives = iter(["First phrasing.", "Totally different phrasing."])
    monkeypatch.setattr(
        analysis_task,
        "_run_analyst_sync",
        lambda evidence_data, **kwargs: (
            {**WRONG_VERDICT, "primary_reasoning": next(narratives)},
            "structured",
            "gpt-5.6-luna",
        ),
    )

    first = _run(WRONG_VERDICT)["report"]
    second = _run(WRONG_VERDICT)["report"]

    canonical = ("classification", "confidence", "risk_score", "recommended_action")
    assert {k: first[k] for k in canonical} == {k: second[k] for k in canonical}


def test_analyst_report_source_is_recorded(isolated_task, monkeypatch):
    """Lands in report_json — no migration — and survives the whole post-processing tail."""
    monkeypatch.setattr(
        analysis_task,
        "_run_analyst_sync",
        lambda evidence_data, **kwargs: (dict(WRONG_VERDICT), "salvaged", "gpt-5.6-luna"),
    )

    assert _run(WRONG_VERDICT)["report"]["analyst_report_source"] == "salvaged"


def test_ai_model_stays_a_bare_model_id(isolated_task, monkeypatch):
    """
    The frontend badge string-matches bare ids.

    ExecutiveSummaryTab.tsx branches on `startsWith("claude-")` and `== "gpt-5.6-luna"`,
    falling through to rendering the raw string — so describe_model()'s
    "openai:gpt-5.6-luna" form must never reach report_json.ai_model.
    """
    monkeypatch.setattr(
        analysis_task,
        "_run_analyst_sync",
        lambda evidence_data, **kwargs: (dict(WRONG_VERDICT), "structured", "gpt-5.6-luna"),
    )

    ai_model = _run(WRONG_VERDICT)["report"]["ai_model"]

    assert ai_model == "gpt-5.6-luna"
    assert ":" not in ai_model and "@" not in ai_model


def test_the_parser_fallback_report_is_swapped_for_the_rule_based_one(isolated_task, monkeypatch):
    """
    Tier-3 output must still trip `_is_parser_fallback_report`.

    That detector needs all four of: the sentinel substring in primary_reasoning, no
    findings, no iocs, and an inconclusive classification.
    """
    from app.analyst.report import fallback_report

    unparseable = fallback_report("raw model babble").model_dump(mode="json")
    assert analysis_task._is_parser_fallback_report(unparseable), "sentinel contract broke"

    monkeypatch.setattr(
        analysis_task,
        "_run_analyst_sync",
        lambda evidence_data, **kwargs: (unparseable, "fallback", ""),
    )

    report = _run(unparseable)["report"]

    # Swapped for the rule-based report, which the engine then overlays as malicious.
    assert "Analyst response parse fallback applied." in report["primary_reasoning"]
    assert report["classification"] == "malicious"


def test_non_domain_observables_never_reach_the_analyst(isolated_task, monkeypatch):
    """The LLM bypass for hash/file/ip. No agent on that path, and ai_model stays None."""
    def _boom(*args, **kwargs):
        raise AssertionError("the analyst must not run for this observable type")

    monkeypatch.setattr(analysis_task, "_run_analyst_sync", _boom)

    report = analysis_task.run_analysis(
        MALICIOUS_RESULTS,
        domain="8.8.8.8",
        investigation_id="inv-ip",
        observable_type="ip",
    )["report"]

    assert report["ai_model"] is None
    assert "analyst_report_source" not in report


# ── _run_analyst_sync itself, against a stub agent ───────────────────────────────

class StubAgent:
    """Records the invoke payload and returns a canned state."""

    def __init__(self, report, *, messages=None):
        self.report = report
        self.messages = messages or []
        self.seen_files = None
        self.seen_message = None

    async def ainvoke(self, payload, config=None):
        self.seen_files = payload.get("files")
        self.seen_message = payload["messages"][0]["content"]
        return {
            "messages": self.messages,
            "structured_response": self.report,
            "files": payload.get("files"),
        }


def _stub_report() -> AnalystReport:
    return AnalystReport(
        classification="suspicious",
        confidence="medium",
        investigation_state="concluded",
        primary_reasoning="Reasoned over the bundle.",
        legitimate_explanation="",
        malicious_explanation="",
        recommended_action="investigate",
    )


@pytest.fixture
def stub_agent(monkeypatch):
    """Patch build_agent so _run_analyst_sync drives the real run_analyst over a stub."""
    agent = StubAgent(
        _stub_report(),
        messages=[AIMessage(content="done", response_metadata={"model_name": "gpt-5.6-luna"})],
    )
    import app.analyst.agent as agent_module

    monkeypatch.setattr(agent_module, "build_agent", lambda **kwargs: agent)
    return agent


def test_run_analyst_sync_mounts_the_bundle_as_file_data(stub_agent, monkeypatch):
    """
    The FileData wrapping bug guard.

    `StateBackend` stores {path: {"content": ..., "encoding": ...}} and calls
    file_data_to_string on every entry, so handing it {path: str} makes the agent's first
    `ls` raise TypeError — and the analyst leg then degrades to an error path with a green
    test suite, because a stub agent accepts any dict.
    """
    from deepagents.backends.utils import file_data_to_string

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    report_dict, source, model = analysis_task._run_analyst_sync(
        {"domain": "evil.tk", "observable_type": "domain", "vt": {"malicious_count": 9}},
        investigation_id="inv-1",
        statuses={"vt": "completed"},
        digest_markdown="# Evidence digest\n\n- something",
        decision={"classification": "malicious"},
        timeout_seconds=30,
    )

    assert source == "structured"
    assert model == "gpt-5.6-luna"
    assert report_dict["classification"] == "suspicious"

    files = stub_agent.seen_files
    for path, entry in files.items():
        assert isinstance(entry, dict), f"{path} was not wrapped as FileData"
        assert file_data_to_string(entry), f"{path} did not round-trip"

    assert "/investigations/inv-1/manifest.json" in files
    assert "/investigations/inv-1/digest.md" in files
    assert "/investigations/inv-1/decision.json" in files
    assert "/investigations/inv-1/evidence/vt.json" in files
    # The digest reaches the model in the prompt, not only on disk.
    assert "# Evidence digest" in stub_agent.seen_message


def test_run_analyst_sync_falls_back_to_the_configured_id_without_metadata(monkeypatch):
    """No response_metadata (a local server that omits it) still yields a bare id."""
    import app.analyst.agent as agent_module
    from app.config import get_settings

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")
    get_settings.cache_clear()
    monkeypatch.setattr(agent_module, "build_agent", lambda **kwargs: StubAgent(_stub_report()))

    try:
        _report, _source, model = analysis_task._run_analyst_sync(
            {"domain": "evil.tk", "observable_type": "domain"},
            investigation_id="inv-2",
            statuses={},
            digest_markdown="",
            decision=None,
            timeout_seconds=30,
        )
    finally:
        get_settings.cache_clear()

    assert model == "gpt-5.6-luna"
