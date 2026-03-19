from app.analyst.system_prompt import ANALYST_SYSTEM_PROMPT


def test_system_prompt_requires_structured_primary_reasoning_for_domain_url_email():
    assert "One-line Summary" in ANALYST_SYSTEM_PROMPT
    assert "Associated With" in ANALYST_SYSTEM_PROMPT
    assert "Analysis:" in ANALYST_SYSTEM_PROMPT
    assert "Verdict:" in ANALYST_SYSTEM_PROMPT
    assert "do not repeat raw data" in ANALYST_SYSTEM_PROMPT.lower()
