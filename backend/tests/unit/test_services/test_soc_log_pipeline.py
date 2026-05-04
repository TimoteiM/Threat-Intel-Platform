import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
loaded_app = sys.modules.get("app")
if loaded_app and Path(str(getattr(loaded_app, "__file__", ""))).resolve() == BACKEND_ROOT / "__init__.py":
    sys.modules.pop("app", None)

from app.services.soc_log_pipeline import (  # noqa: E402
    build_prompt,
    process_log,
    reinject,
    tokenize,
    validate_ai_output,
)


def test_tokenize_replaces_multiple_token_types_and_deduplicates_values() -> None:
    log = (
        "srcip=10.10.10.5 dstip=10.10.10.5 host=mail.company.com "
        "url=https://mail.company.com/login user=jdoe email=jdoe@company.com"
    )

    sanitized, mapping = tokenize(log)

    assert sanitized.count("IP_1") == 2
    assert "IP_2" not in sanitized
    assert sanitized.count("HOST_1") == 2
    assert "USER_1" in sanitized
    assert "EMAIL_1" in sanitized
    assert mapping["IP_1"] == "10.10.10.5"
    assert mapping["HOST_1"] == "mail.company.com"
    assert mapping["USER_1"] == "jdoe"
    assert mapping["EMAIL_1"] == "jdoe@company.com"


def test_tokenize_assigns_unique_tokens_per_sensitive_value() -> None:
    sanitized, mapping = tokenize(
        "srcip=10.0.0.1 dstip=10.0.0.2 host=a.example.com ref=b.example.com"
    )

    assert "IP_1" in sanitized
    assert "IP_2" in sanitized
    assert "HOST_1" in sanitized
    assert "HOST_2" in sanitized
    assert mapping["IP_1"] == "10.0.0.1"
    assert mapping["IP_2"] == "10.0.0.2"
    assert mapping["HOST_1"] == "a.example.com"
    assert mapping["HOST_2"] == "b.example.com"


def test_reinject_handles_punctuation_repetition_casing_and_spacing() -> None:
    text = "Seen IP_1, then ip_1. Host was HOST _ 1; account USER_1."
    mapping = {
        "IP_1": "10.10.10.5",
        "HOST_1": "mail.company.com",
        "USER_1": "jdoe",
    }

    reinjected = reinject(text, mapping)

    assert reinjected == (
        "Seen 10.10.10.5, then 10.10.10.5. "
        "Host was mail.company.com; account jdoe."
    )


def test_reinject_leaves_missing_tokens_unchanged() -> None:
    assert reinject("IP_1 contacted HOST_99.", {"IP_1": "10.0.0.1"}) == (
        "10.0.0.1 contacted HOST_99."
    )


def test_reinject_does_not_replace_partial_token_words() -> None:
    assert reinject("XIP_1 should stay, IP_1 should change.", {"IP_1": "10.0.0.1"}) == (
        "XIP_1 should stay, 10.0.0.1 should change."
    )


def test_build_prompt_enforces_json_contract_and_immutable_tokens() -> None:
    prompt = build_prompt("HOST_1 contacted IP_1")

    assert "Return valid JSON only" in prompt
    assert '{"summary": string, "details": string, "reasonlist": [string]}' in prompt
    assert "immutable identifiers" in prompt
    assert "HOST_1 contacted IP_1" in prompt


def test_validate_ai_output_accepts_valid_schema() -> None:
    result = validate_ai_output(
        json.dumps(
            {
                "summary": "HOST_1 contacted IP_1",
                "details": "USER_1 authenticated.",
                "reasonlist": ["HOST_1 appears in the log."],
            }
        )
    )

    assert result["summary"] == "HOST_1 contacted IP_1"
    assert result["reasonlist"] == ["HOST_1 appears in the log."]


def test_validate_ai_output_rejects_malformed_json() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        validate_ai_output("summary: HOST_1 contacted IP_1")


def test_validate_ai_output_rejects_wrong_schema() -> None:
    with pytest.raises(ValueError, match="reasonlist"):
        validate_ai_output(json.dumps({"summary": "ok", "details": "ok"}))

    with pytest.raises(ValueError, match="list of strings"):
        validate_ai_output(json.dumps({"summary": "ok", "details": "ok", "reasonlist": "bad"}))


def test_process_log_returns_reinjected_structured_result() -> None:
    log = "srcip=10.10.10.5 host=mail.company.com user=jdoe action=blocked"

    output = process_log(log)

    assert output["mapping"]["IP_1"] == "10.10.10.5"
    assert output["mapping"]["HOST_1"] == "mail.company.com"
    assert output["mapping"]["USER_1"] == "jdoe"
    assert "10.10.10.5" in output["result"]["details"]
    assert "mail.company.com" in output["result"]["details"]
    assert "HOST_1" not in output["result"]["details"]


def test_process_log_raises_for_bad_llm_response() -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        process_log("srcip=10.10.10.5", llm=lambda _prompt: "not json")


def test_process_log_reinjects_slightly_inconsistent_llm_tokens() -> None:
    def inconsistent_llm(_prompt: str) -> str:
        return json.dumps(
            {
                "summary": "host_1 saw IP _ 1.",
                "details": "USER_1 accessed HOST_1, then ip_1.",
                "reasonlist": ["HOST _ 1 and IP_1 are present."],
            }
        )

    output = process_log(
        "srcip=10.10.10.5 host=mail.company.com user=jdoe",
        llm=inconsistent_llm,
    )

    assert output["result"] == {
        "summary": "mail.company.com saw 10.10.10.5.",
        "details": "jdoe accessed mail.company.com, then 10.10.10.5.",
        "reasonlist": ["mail.company.com and 10.10.10.5 are present."],
    }


def test_edge_cases_invalid_ipv4_and_non_string_inputs() -> None:
    sanitized, mapping = tokenize("bad=999.10.10.10 good=10.10.10.10")

    assert "999.10.10.10" in sanitized
    assert "IP_1" in sanitized
    assert mapping == {"IP_1": "10.10.10.10"}

    with pytest.raises(TypeError):
        tokenize(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        reinject(None, {})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        validate_ai_output(None)  # type: ignore[arg-type]
