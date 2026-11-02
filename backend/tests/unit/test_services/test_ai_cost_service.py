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
    """The whole point. None means 'we do not know', and the caller must say so.

    Uses a model nothing could have a rate for — gpt-5.6-luna was the example
    until an operator configured it, which is exactly the behaviour this file
    documents rather than a reason to weaken the assertion.
    """
    assert price_for("no-such-model-v9") is None
    assert cost_micros("no-such-model-v9", input_tokens=50_000, output_tokens=5_000) is None


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


def test_cost_matches_hand_arithmetic_at_the_configured_rate(monkeypatch):
    """The figure on the page has to survive being checked on paper."""
    class _Settings:
        ai_model_prices = '{"gpt-5.6-luna": {"input": 0.20, "output": 1.20}}'
        redis_url = "redis://localhost:6379/0"

    monkeypatch.setattr(ai_cost_service, "get_settings", lambda: _Settings())
    # 989,961 / 1e6 * 0.20 = 0.1979922 ; 13,898 / 1e6 * 1.20 = 0.0166776
    micros = cost_micros("gpt-5.6-luna", input_tokens=989_961, output_tokens=13_898)
    assert micros == round((0.1979922 + 0.0166776) * 1_000_000)
    assert abs(micros / 1_000_000 - 0.2147) < 0.0001


class _FakeRedis:
    """Enough Redis to exercise the window summation, and nothing more.

    Written because the real store held a single day when the windows were
    built, so every window returned the same total and there was no way to see
    whether the summation worked or merely looked like it did.
    """

    def __init__(self, hashes: dict, sets: dict):
        self._hashes = hashes
        self._sets = sets

    def hgetall(self, key):
        return {k.encode(): str(v).encode() for k, v in self._hashes.get(key, {}).items()}

    def smembers(self, key):
        return {m.encode() for m in self._sets.get(key, set())}

    def get(self, key):
        return None

    def exists(self, key):
        return 1 if key in self._hashes else 0

    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, client):
        self._client = client
        self._queued = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def exists(self, key):
        self._queued.append(key)
        return self

    def execute(self):
        return [self._client.exists(key) for key in self._queued]


def _three_days_of_usage(monkeypatch):
    """Today, yesterday and six days ago — so 24h, 7d and 30d must differ."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    days = [(now - timedelta(days=n)).strftime("%Y-%m-%d") for n in (0, 1, 6)]
    label = "openai:test-model"
    hashes, sets = {}, {}
    for day, tokens in zip(days, (1_000_000, 2_000_000, 4_000_000)):
        hashes[f"ai_cost:day:{day}"] = {"calls": 1}
        hashes[f"ai_cost:day:{day}:model:{label}"] = {
            "calls": 1, "input_tokens": tokens, "output_tokens": 0, "cached_input_tokens": 0,
        }
        sets[f"ai_cost:models:{day}"] = {label}

    class _Settings:
        ai_model_prices = '{"test-model": {"input": 1.00, "output": 1.00}}'
        redis_url = "redis://localhost:6379/0"

    monkeypatch.setattr(ai_cost_service, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        ai_cost_service.redis_lib.Redis, "from_url",
        staticmethod(lambda *a, **k: _FakeRedis(hashes, sets)),
    )
    return days


def test_each_window_sums_only_the_days_it_covers(monkeypatch):
    _three_days_of_usage(monkeypatch)
    # $1 per million input, so the dollars equal the millions of tokens.
    assert ai_cost_service.ai_spend_summary(days=1)["window"]["usd"] == 1.0
    assert ai_cost_service.ai_spend_summary(days=2)["window"]["usd"] == 3.0
    assert ai_cost_service.ai_spend_summary(days=7)["window"]["usd"] == 7.0
    assert ai_cost_service.ai_spend_summary(days=30)["window"]["usd"] == 7.0


def test_window_reports_the_span_it_covers(monkeypatch):
    days = _three_days_of_usage(monkeypatch)
    summary = ai_cost_service.ai_spend_summary(days=7)
    assert summary["window_end"] == days[0]
    # Six days ago is the oldest bucket held, and the panel needs to say so
    # rather than let identical totals read as a broken control.
    assert summary["first_recorded_day"] == days[2]
