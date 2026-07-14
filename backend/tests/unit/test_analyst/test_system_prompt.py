from app.analyst.system_prompt import ANALYST_SYSTEM_PROMPT


def test_system_prompt_requires_structured_primary_reasoning_for_domain_url_email():
    assert "Produce a complete analyst-facing report" in ANALYST_SYSTEM_PROMPT
    assert "`primary_reasoning`: 3-5 sentences" in ANALYST_SYSTEM_PROMPT
    assert "`technical_narrative`: 4-8 compact bullets" in ANALYST_SYSTEM_PROMPT
    assert "Findings: include up to 8 high-signal findings" in ANALYST_SYSTEM_PROMPT
    assert "do not repeat raw dumps" in ANALYST_SYSTEM_PROMPT.lower()
