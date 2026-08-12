"""
Chat model construction.

One seam, three providers:

1. `openai`             — the hosted API, unchanged from the pre-LangChain build.
2. `openai_compatible`  — a locally hosted server (Ollama, vLLM, LM Studio,
                          llama.cpp, TGI) reached over an OpenAI-compatible /v1
                          endpoint. This is what makes an air-gapped deployment
                          possible.
3. `anthropic`          — the hosted Claude API.

Everything downstream takes a `BaseChatModel`, so switching providers touches
nothing but `.env`.

Models are constructed as instances, not `"provider:model"` strings, because
`init_chat_model` cannot set `base_url`, `max_tokens` or `timeout`.

`langchain-anthropic` stays installed either way: `deepagents.graph` imports
`ChatAnthropic` at module top level.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.language_models import BaseChatModel

from app.config import (
    get_settings,
    require_anthropic_key,
    require_openai_compatible_config,
)

logger = logging.getLogger(__name__)


def message_text(response: Any) -> str:
    """
    Plain text of a chat-model response.

    `.text` is a property on current langchain messages; older builds exposed it as a
    method, and the back-compat shim is a callable str — so test for str first, or calling
    it emits a deprecation warning. Falls back to `.content`, which is a list of typed
    blocks on some providers rather than a string.
    """
    text = getattr(response, "text", None)
    if not isinstance(text, str) and callable(text):
        text = text()
    if isinstance(text, str) and text:
        return text

    content = getattr(response, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "") for block in content if isinstance(block, dict)
        )
    return ""


def _output_tokens(max_tokens: int | None) -> int:
    """Per-call output cap, defaulting to the analyst's."""
    return max_tokens if max_tokens else get_settings().analyst_max_output_tokens


def _build_openai_compatible(model: str, *, max_tokens: int | None = None) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    settings = get_settings()
    base_url = require_openai_compatible_config(model)
    return ChatOpenAI(
        model=model,
        base_url=base_url,
        # Local servers ignore it, but the client rejects an empty key.
        api_key=settings.llm_api_key or "not-needed",
        temperature=settings.llm_temperature,
        max_tokens=_output_tokens(max_tokens),
        timeout=settings.analyst_timeout_seconds,
    )


def _build_openai(model: str, *, max_tokens: int | None = None) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    settings = get_settings()
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not set but LLM_PROVIDER=openai.")
    return ChatOpenAI(
        model=model,
        api_key=settings.openai_api_key,
        temperature=settings.llm_temperature,
        max_tokens=_output_tokens(max_tokens),
        timeout=settings.analyst_timeout_seconds,
    )


def _build_anthropic(model: str, *, max_tokens: int | None = None) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    settings = get_settings()
    return ChatAnthropic(
        model=model,
        api_key=require_anthropic_key(),
        max_tokens=_output_tokens(max_tokens),
        timeout=settings.analyst_timeout_seconds,
    )


def build_model(
    model_override: str | None = None,
    *,
    max_tokens: int | None = None,
) -> BaseChatModel:
    """
    The analyst model, and the shared seam for every other model call in the app.

    `model_override` preserves the platform's existing routing convention: a name
    starting with "claude-" goes to Anthropic regardless of LLM_PROVIDER. That test is
    the only provider discriminator in this codebase (assistant_service,
    attack_ai_service) and callers depend on it.

    `max_tokens` is the per-call output cap. Sites other than the analyst have their own
    (4096 assistant, 3000 email interpreter, 1024 attack AI), and passing it here beats
    rebinding it onto a returned instance.
    """
    settings = get_settings()
    if model_override and model_override.startswith("claude-"):
        return _build_anthropic(model_override, max_tokens=max_tokens)

    provider = settings.llm_provider
    if provider == "anthropic":
        return _build_anthropic(model_override or settings.anthropic_model, max_tokens=max_tokens)
    if provider == "openai_compatible":
        return _build_openai_compatible(
            model_override or settings.llm_model, max_tokens=max_tokens
        )
    return _build_openai(model_override or settings.openai_model, max_tokens=max_tokens)


def build_anthropic_model(
    model_override: str | None = None,
    *,
    max_tokens: int | None = None,
) -> BaseChatModel:
    """
    Anthropic explicitly, for call sites whose *fallback* is Anthropic by design.

    `build_model` cannot express that: it routes by LLM_PROVIDER, so on a local-only
    deployment it would hand back the local model and the "fallback" would retry the same
    server that just failed.
    """
    return _build_anthropic(model_override or get_settings().anthropic_model, max_tokens=max_tokens)


def build_fallback_model() -> BaseChatModel | None:
    """
    Second model for `ModelFallbackMiddleware`, or None when none is configured.

    Hosted deployments keep the platform's existing OpenAI-primary / Anthropic-fallback
    behaviour. With a single local server there is usually nothing to fail over to, so
    this returns None and the middleware is simply not installed.

    Note what this does *not* do: it never falls back on the `anthropic` provider,
    because a caller who set LLM_PROVIDER=anthropic asked for Anthropic.
    """
    settings = get_settings()
    if settings.llm_provider == "openai" and settings.anthropic_api_key:
        return _build_anthropic(settings.anthropic_model)
    if settings.llm_provider == "anthropic":
        return None
    if not settings.llm_fallback_model:
        return None
    return _build_openai_compatible(settings.llm_fallback_model)


def primary_model_configured(settings: Any | None = None) -> bool:
    """
    Whether the configured primary provider can actually be built.

    The provider ladders (assistant, email interpreter, attack AI) need this to decide
    whether to attempt the primary at all. They used to test `openai_api_key` directly,
    which silently skipped the primary on a local-only deployment and then demanded an
    Anthropic key — reporting "OPENAI_API_KEY and ANTHROPIC_API_KEY are both unset" on a
    box that had a perfectly good model configured.

    `settings` is accepted so a caller holding its own instance (AssistantService keeps one
    on `self.settings`, and its tests inject a stub) is honoured instead of the global
    singleton. `getattr` throughout, because those stubs only carry the fields under test.
    """
    settings = settings if settings is not None else get_settings()
    provider = getattr(settings, "llm_provider", "openai")
    if provider == "openai_compatible":
        return bool(
            (getattr(settings, "llm_model", "") or "").strip()
            and (getattr(settings, "llm_base_url", "") or "").strip()
        )
    if provider == "anthropic":
        return bool(getattr(settings, "anthropic_api_key", ""))
    return bool(getattr(settings, "openai_api_key", ""))


def configured_model_id(settings: Any | None = None) -> str:
    """
    The bare model id for the configured provider.

    Distinct from `describe_model()` on purpose. This value is what reaches
    `report_json.ai_model`, and the frontend badge
    (frontend/src/components/report/ExecutiveSummaryTab.tsx:57-70) matches bare ids —
    `startswith("claude-")`, `== "gpt-5.6-luna"` — falling through to rendering the raw
    string. So it carries no provider prefix and no base URL.

    Takes an optional `settings` for the same reason as `primary_model_configured`.
    """
    settings = settings if settings is not None else get_settings()
    provider = getattr(settings, "llm_provider", "openai")
    if provider == "anthropic":
        return getattr(settings, "anthropic_model", "") or ""
    if provider == "openai_compatible":
        return getattr(settings, "llm_model", "") or ""
    return getattr(settings, "openai_model", "") or ""


def describe_model() -> str:
    """
    Human-readable model target, for logs and /api/health.

    Reported rather than raised: health has to stay answerable precisely when the model
    is misconfigured. Never use this for `report_json.ai_model` — see
    `configured_model_id`.
    """
    settings = get_settings()
    if settings.llm_provider == "anthropic":
        return f"anthropic:{settings.anthropic_model}"
    if settings.llm_provider == "openai_compatible":
        if not (settings.llm_model and settings.llm_base_url):
            return "unconfigured (set LLM_MODEL and LLM_BASE_URL)"
        return f"{settings.llm_model} @ {settings.llm_base_url}"
    return f"openai:{settings.openai_model}"
