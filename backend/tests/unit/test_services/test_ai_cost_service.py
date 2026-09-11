"""Metering and pricing for AI spend.

The rule these enforce: tokens are counted exactly, and a model with no
configured rate is reported as unpriced rather than costed at zero or at a
guess. A plausible wrong number on a spend page is worse than a visible gap.
"""

from __future__ import annotations

import pytest

from app.services import ai_cost_service
from app.services.ai_cost_service import ModelPrice, cost_micros, price_for


def test_dated_snapshot_ids_resolve_to_the_family_price():
    # The configured Anthropic model is a dated snapshot; longest-prefix match
    # has to find it, or every Claude call would meter as unpriced.
    assert price_for("claude-haiku-4-5-20251001") == ModelPrice(1.00, 5.00, 0.10)
    assert price_for("claude-opus-5") == ModelPrice(5.00, 25.00, 0.50)


def test_cost_is_computed_per_million_tokens():
    # 1M input at $1 + 1M output at $5 = $6.00, in micro-dollars.
    assert cost_micros("claude-haiku-4-5", input_tokens=1_000_000, output_tokens=1_000_000) == 6_000_000


def test_cached_input_bills_at_the_cache_rate():
    # 1M input of which 1M is a cache read: $0.10, not $1.00.
    assert cost_micros(
        "claude-haiku-4-5", input_tokens=1_000_000, output_tokens=0, cached_input_tokens=1_000_000
    ) == 100_000


def test_an_unknown_model_is_unpriced_not_free():
    """The whole point. None means 'we do not know', and the caller must say so."""
    assert price_for("gpt-5.6-luna") is None
    assert cost_micros("gpt-5.6-luna", input_tokens=50_000, output_tokens=5_000) is None


def test_operator_supplied_rates_are_used(monkeypatch):
    class _Settings:
        ai_model_prices = '{"gpt-5.6-luna": {"input": 1.25, "output": 10.0}}'
        redis_url = "redis://localhost:6379/0"

    monkeypatch.setattr(ai_cost_service, "get_settings", lambda: _Settings())
    assert price_for("gpt-5.6-luna") == ModelPrice(1.25, 10.0, None)
    # 1M in at $1.25 + 1M out at $10.00
    assert cost_micros("gpt-5.6-luna", input_tokens=1_000_000, output_tokens=1_000_000) == 11_250_000


def test_unusable_price_json_falls_back_rather_than_crashing(monkeypatch):
    class _Settings:
        ai_model_prices = "{not json"
        redis_url = "redis://localhost:6379/0"

    monkeypatch.setattr(ai_cost_service, "get_settings", lambda: _Settings())
    # Built-ins survive; the bad override is ignored, not fatal.
    assert price_for("claude-opus-5") == ModelPrice(5.00, 25.00, 0.50)


@pytest.mark.parametrize(
    "usage, expected_in, expected_out",
    [
        ({"input_tokens": 10, "output_tokens": 4}, 10, 4),          # Anthropic / OpenAI Responses
        ({"prompt_tokens": 7, "completion_tokens": 3}, 7, 3),        # OpenAI Chat Completions
    ],
)
def test_usage_is_read_from_either_provider_shape(monkeypatch, usage, expected_in, expected_out):
    captured = {}

    def _record(provider, model, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(ai_cost_service, "record_ai_usage", _record)

    class _Response:
        pass

    response = _Response()
    response.usage = type("U", (), usage)()
    ai_cost_service.record_from_response("openai", "some-model", response)

    assert captured["input_tokens"] == expected_in
    assert captured["output_tokens"] == expected_out
