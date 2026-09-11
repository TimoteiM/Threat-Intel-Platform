"""What the AI providers cost us, metered from our own requests.

Neither provider will tell us a remaining balance. OpenAI's Usage API reports
spend and needs an admin-scoped key (a project key returns 403 `Missing scopes:
api.usage.read`); the endpoint that once returned a prepaid balance was a
dashboard-session route and is gone. So the number on the Settings page is one
we compute: every call reports its own token usage, we price it, and we total
it against a budget the analyst enters.

Two consequences worth being honest about, both surfaced in the payload rather
than hidden:

* This counts what *this app* spends. Anything else on the same key — another
  service, someone's console session — is invisible here.
* A model with no configured price is metered in tokens and reported as
  unpriced. It is never silently costed at zero, and never at a guess.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import redis as redis_lib

from app.config import get_settings

logger = logging.getLogger(__name__)

DAY_TTL_SECONDS = 90 * 24 * 60 * 60
MONTH_TTL_SECONDS = 400 * 24 * 60 * 60

# Costs are held as integer micro-dollars. Redis has no decimal type, and
# float accumulation over tens of thousands of small charges drifts.
MICROS_PER_DOLLAR = 1_000_000


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens."""

    input_per_mtok: float
    output_per_mtok: float
    # Cache reads bill at roughly a tenth of the input rate on Anthropic.
    cached_input_per_mtok: float | None = None


# Anthropic list prices, first-party API, as published 2026-06-24. Matched by
# longest prefix so dated snapshot ids (claude-haiku-4-5-20251001) resolve.
#
# There are deliberately no OpenAI defaults here — a rate this file invented
# would be a plausible wrong number on a spend page. Operator-supplied rates
# come from AI_MODEL_PRICES and are merged over this table, which is also why
# cost is computed when the page is read rather than when the call was made:
# configuring a rate today has to price the tokens already recorded.
ANTHROPIC_PRICES: dict[str, ModelPrice] = {
    "claude-fable-5": ModelPrice(10.00, 50.00, 1.00),
    "claude-mythos-5": ModelPrice(10.00, 50.00, 1.00),
    "claude-opus-5": ModelPrice(5.00, 25.00, 0.50),
    "claude-opus-4-8": ModelPrice(5.00, 25.00, 0.50),
    "claude-opus-4-7": ModelPrice(5.00, 25.00, 0.50),
    "claude-opus-4-6": ModelPrice(5.00, 25.00, 0.50),
    "claude-sonnet-5": ModelPrice(2.00, 10.00, 0.20),
    "claude-sonnet-4-6": ModelPrice(3.00, 15.00, 0.30),
    "claude-haiku-4-5": ModelPrice(1.00, 5.00, 0.10),
}

PRICES_SOURCE = "Anthropic list prices as published 2026-06-24; OpenAI rates from AI_MODEL_PRICES"


def _configured_prices() -> dict[str, ModelPrice]:
    """Operator-supplied rates, merged over the built-ins.

    AI_MODEL_PRICES is JSON: {"gpt-5.6-luna": {"input": 1.25, "output": 10.0}}
    """
    raw = str(getattr(get_settings(), "ai_model_prices", "") or "").strip()
    if not raw:
        return dict(ANTHROPIC_PRICES)
    merged = dict(ANTHROPIC_PRICES)
    try:
        for model, rates in (json.loads(raw) or {}).items():
            merged[str(model)] = ModelPrice(
                float(rates.get("input") or 0.0),
                float(rates.get("output") or 0.0),
                float(rates["cached_input"]) if rates.get("cached_input") is not None else None,
            )
    except Exception as exc:
        logger.warning("AI_MODEL_PRICES is not usable JSON, ignoring it: %s", exc)
    return merged


def price_for(model: str) -> ModelPrice | None:
    """Longest matching prefix wins, so dated snapshot ids still resolve."""
    name = str(model or "").strip().lower()
    if not name:
        return None
    prices = _configured_prices()
    match = max((k for k in prices if name.startswith(k.lower())), key=len, default=None)
    return prices[match] if match else None


def cost_micros(
    model: str,
    *,
    input_tokens: int,
    output_tokens: int,
    cached_input_tokens: int = 0,
) -> int | None:
    """Micro-dollars for one call, or None when the model has no known price."""
    price = price_for(model)
    if price is None:
        return None
    billed_input = max(0, input_tokens - cached_input_tokens)
    cached_rate = price.cached_input_per_mtok
    if cached_rate is None:
        # No separate cache rate configured: count cached tokens at full input
        # rate rather than free, so the estimate errs high instead of low.
        billed_input = input_tokens
        cached_input_tokens = 0
        cached_rate = 0.0
    dollars = (
        billed_input * price.input_per_mtok
        + cached_input_tokens * cached_rate
        + output_tokens * price.output_per_mtok
    ) / 1_000_000
    return int(round(dollars * MICROS_PER_DOLLAR))


def record_ai_usage(
    provider: str,
    model: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cached_input_tokens: int = 0,
    purpose: str | None = None,
) -> None:
    """Meter one AI call. Never raises — accounting must not fail a request."""
    if input_tokens <= 0 and output_tokens <= 0:
        return
    try:
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        month = now.strftime("%Y-%m")
        micros = cost_micros(
            model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
        )
        client = redis_lib.Redis.from_url(get_settings().redis_url)
        with client.pipeline() as pipe:
            for scope, period, ttl in (("day", day, DAY_TTL_SECONDS), ("month", month, MONTH_TTL_SECONDS)):
                key = f"ai_cost:{scope}:{period}"
                pipe.hincrby(key, "input_tokens", input_tokens)
                pipe.hincrby(key, "output_tokens", output_tokens)
                pipe.hincrby(key, "cached_input_tokens", cached_input_tokens)
                pipe.hincrby(key, "calls", 1)
                if micros is not None:
                    pipe.hincrby(key, "micros", micros)
                else:
                    pipe.hincrby(key, "unpriced_calls", 1)
                    pipe.sadd(f"ai_cost:unpriced_models:{period}", f"{provider}:{model}")
                    pipe.expire(f"ai_cost:unpriced_models:{period}", ttl)
                # Per model, so the breakdown can say where the money went.
                model_key = f"ai_cost:{scope}:{period}:model:{provider}:{model}"
                pipe.hincrby(model_key, "input_tokens", input_tokens)
                pipe.hincrby(model_key, "output_tokens", output_tokens)
                pipe.hincrby(model_key, "cached_input_tokens", cached_input_tokens)
                pipe.hincrby(model_key, "calls", 1)
                if micros is not None:
                    pipe.hincrby(model_key, "micros", micros)
                pipe.expire(model_key, ttl)
                pipe.sadd(f"ai_cost:models:{period}", f"{provider}:{model}")
                pipe.expire(f"ai_cost:models:{period}", ttl)
                pipe.expire(key, ttl)
            pipe.execute()
    except Exception as exc:
        logger.debug("Could not record AI usage for %s/%s: %s", provider, model, exc)


def record_from_response(provider: str, model: str, response: Any, *, purpose: str | None = None) -> None:
    """Pull the token counts off a provider response and meter them.

    Anthropic returns input_tokens/output_tokens (plus cache fields); OpenAI's
    Responses API returns input_tokens/output_tokens, its Chat Completions API
    prompt_tokens/completion_tokens. Handles all three rather than making every
    call site know which it is holding.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return

    def _get(*names: str) -> int:
        for name in names:
            value = getattr(usage, name, None)
            if value is None and isinstance(usage, dict):
                value = usage.get(name)
            if isinstance(value, (int, float)):
                return int(value)
        return 0

    cached = _get("cache_read_input_tokens")
    if not cached:
        details = getattr(usage, "input_tokens_details", None)
        if details is not None:
            cached = int(getattr(details, "cached_tokens", 0) or 0)

    record_ai_usage(
        provider,
        model,
        input_tokens=_get("input_tokens", "prompt_tokens"),
        output_tokens=_get("output_tokens", "completion_tokens"),
        cached_input_tokens=cached,
        purpose=purpose,
    )


def _read_hash(client: redis_lib.Redis, key: str) -> dict[str, int]:
    raw = client.hgetall(key) or {}
    out: dict[str, int] = {}
    for name, value in raw.items():
        name = name.decode() if isinstance(name, bytes) else str(name)
        try:
            out[name] = int(value)
        except (TypeError, ValueError):
            continue
    return out


def _members(client: redis_lib.Redis, key: str) -> list[str]:
    return sorted(
        (m.decode() if isinstance(m, bytes) else str(m))
        for m in (client.smembers(key) or set())
    )


# The windows the Settings page offers. Buckets are UTC calendar days, so "24h"
# means today so far rather than a rolling window — labelled accordingly rather
# than pretending to a precision the storage does not have.
WINDOWS: dict[int, str] = {
    1: "Today (UTC)",
    7: "Last 7 days",
    30: "Last 30 days",
}


def ai_spend_summary(days: int = 30) -> dict[str, Any]:
    """Spend over the last `days` UTC days, priced now rather than when recorded.

    Cost is derived at read time from the stored token counts. Recording the
    dollars instead would freeze them: a model with no rate configured would
    stay at zero for ever, and correcting a rate would never reach the history
    it was wrong about. Tokens are the fact; the price is a lookup.
    """
    days = max(1, int(days))
    now = datetime.now(timezone.utc)
    day_keys = [(now - timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days)]
    month = now.strftime("%Y-%m")

    try:
        client = redis_lib.Redis.from_url(get_settings().redis_url)

        per_model: dict[str, dict[str, int]] = {}
        calls = 0
        for day in day_keys:
            for label in _members(client, f"ai_cost:models:{day}"):
                stats = _read_hash(client, f"ai_cost:day:{day}:model:{label}")
                if not stats:
                    continue
                bucket = per_model.setdefault(
                    label, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0}
                )
                for field in bucket:
                    bucket[field] += stats.get(field, 0)
            calls += _read_hash(client, f"ai_cost:day:{day}").get("calls", 0)

        # The budget is a monthly figure, so it is always measured against the
        # calendar month regardless of which window is on screen.
        # Month-to-date is read from the month's own buckets, not from the
        # selected window — the budget is monthly, so the figure it is measured
        # against must not change when someone picks "24h".
        month_micros = 0
        for label in _members(client, f"ai_cost:models:{month}"):
            stats = _read_hash(client, f"ai_cost:month:{month}:model:{label}")
            if not stats:
                continue
            _, _, model_name = label.partition(":")
            month_micros += (
                cost_micros(
                    model_name,
                    input_tokens=stats.get("input_tokens", 0),
                    output_tokens=stats.get("output_tokens", 0),
                    cached_input_tokens=stats.get("cached_input_tokens", 0),
                )
                or 0
            )
        budget_micros = _read_budget(client)
    except Exception as exc:
        logger.warning("Could not read AI spend: %s", exc)
        return {"available": False, "reason": "usage store unreachable"}

    models: list[dict[str, Any]] = []
    window_micros = 0
    unpriced_calls = 0
    unpriced: list[str] = []

    for label, stats in per_model.items():
        provider, _, model = label.partition(":")
        micros = cost_micros(
            model,
            input_tokens=stats["input_tokens"],
            output_tokens=stats["output_tokens"],
            cached_input_tokens=stats["cached_input_tokens"],
        )
        price = price_for(model)
        if micros is None:
            unpriced_calls += stats["calls"]
            unpriced.append(label)
        else:
            window_micros += micros
        models.append(
            {
                "provider": provider,
                "model": model,
                "calls": stats["calls"],
                "input_tokens": stats["input_tokens"],
                "output_tokens": stats["output_tokens"],
                "usd": round((micros or 0) / MICROS_PER_DOLLAR, 4),
                "priced": price is not None,
                # Shown next to the cost so the arithmetic is checkable by hand.
                "input_per_mtok": price.input_per_mtok if price else None,
                "output_per_mtok": price.output_per_mtok if price else None,
            }
        )
    models.sort(key=lambda m: (-m["usd"], -m["calls"]))

    budget: dict[str, Any] | None = None
    if budget_micros:
        budget = {
            "monthly_usd": round(budget_micros / MICROS_PER_DOLLAR, 2),
            "remaining_usd": round((budget_micros - month_micros) / MICROS_PER_DOLLAR, 2),
            "percent_used": round(min(999.0, month_micros * 100 / budget_micros), 1),
        }

    return {
        "available": True,
        "window_days": days,
        "window_label": WINDOWS.get(days, f"Last {days} days"),
        "window": {
            "calls": calls,
            "usd": round(window_micros / MICROS_PER_DOLLAR, 4),
            "input_tokens": sum(m["input_tokens"] for m in models),
            "output_tokens": sum(m["output_tokens"] for m in models),
            "unpriced_calls": unpriced_calls,
        },
        "month_to_date_usd": round(month_micros / MICROS_PER_DOLLAR, 4),
        "by_model": models,
        "unpriced_models": sorted(set(unpriced)),
        "budget": budget,
        "prices_source": PRICES_SOURCE,
        "scope_note": (
            "Metered from this application's own requests. Spend on the same API "
            "key from anywhere else is not included, and neither provider exposes "
            "a remaining prepaid balance through its API."
        ),
    }


BUDGET_KEY = "ai_cost:budget_micros"


def _read_budget(client: redis_lib.Redis) -> int:
    try:
        value = client.get(BUDGET_KEY)
        return int(value) if value else 0
    except Exception:
        return 0


def get_budget_usd() -> float:
    try:
        return _read_budget(redis_lib.Redis.from_url(get_settings().redis_url)) / MICROS_PER_DOLLAR
    except Exception:
        return 0.0


def set_budget_usd(amount: float) -> float:
    """Set (or clear, with 0) the monthly budget the remaining figure counts down from."""
    micros = max(0, int(round(float(amount) * MICROS_PER_DOLLAR)))
    client = redis_lib.Redis.from_url(get_settings().redis_url)
    if micros:
        client.set(BUDGET_KEY, micros)
    else:
        client.delete(BUDGET_KEY)
    return micros / MICROS_PER_DOLLAR
