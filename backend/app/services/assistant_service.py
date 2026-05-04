from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from uuid import UUID

import anthropic
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from openai import AsyncOpenAI

from app.config import get_settings
from app.models.database import AssistantEntry, AssistantSession, Investigation
from app.services.provider_usage_metrics import record_provider_request
from app.services.assistant_prompt_service import (
    build_alert_analysis_prompt,
    build_incident_correlation_prompt,
)
from app.services.assistant_sanitizer_service import sanitize_entries

logger = logging.getLogger(__name__)

PRIMARY_MODEL = "claude-haiku-4-5-20251001"
FALLBACK_MODEL = "gpt-5-mini"


class AssistantService:
    def __init__(self, session: AsyncSession, settings=None):
        self.session = session
        self.settings = settings or get_settings()

    async def create_session(
        self,
        *,
        title: str | None,
        mode: str,
        source_type: str = "manual",
        linked_investigation_id: UUID | None = None,
    ) -> AssistantSession:
        normalized_title = title.strip() if title else ""
        if not normalized_title:
            normalized_title = (
                "Alert Analysis"
                if mode == "alert_analysis"
                else "Incident Correlation"
            )
        assistant_session = AssistantSession(
            title=normalized_title,
            mode=mode,
            source_type=source_type,
            linked_investigation_id=linked_investigation_id,
        )
        self.session.add(assistant_session)
        await self.session.flush()
        await self.session.commit()
        return assistant_session

    async def add_entry(
        self,
        session_id: UUID,
        *,
        text: str,
        entry_label: str | None = None,
        entry_index: int | None = None,
    ) -> AssistantEntry:
        assistant_session = await self._get_session(session_id)
        if assistant_session is None:
            raise ValueError(f"Assistant session {session_id} not found")
        next_index = entry_index if entry_index is not None else len(assistant_session.entries)
        entry = AssistantEntry(
            session_id=assistant_session.id,
            entry_index=next_index,
            entry_label=entry_label,
            raw_text=text,
            sanitized_text="",
            token_map_json={},
        )
        self.session.add(entry)
        await self.session.flush()
        await self.session.commit()
        return entry

    async def list_sessions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
    ) -> dict[str, object]:
        normalized_search = (search or "").strip()
        base_query = select(AssistantSession)
        count_query = select(func.count(func.distinct(AssistantSession.id)))

        if normalized_search:
            pattern = f"%{normalized_search}%"
            search_filter = or_(
                AssistantSession.title.ilike(pattern),
                AssistantEntry.raw_text.ilike(pattern),
            )
            base_query = (
                base_query
                .outerjoin(AssistantEntry, AssistantEntry.session_id == AssistantSession.id)
                .where(search_filter)
            )
            count_query = (
                count_query
                .select_from(AssistantSession)
                .outerjoin(AssistantEntry, AssistantEntry.session_id == AssistantSession.id)
                .where(search_filter)
            )
        else:
            count_query = count_query.select_from(AssistantSession)

        result = await self.session.execute(
            base_query
            .distinct()
            .order_by(AssistantSession.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        total_result = await self.session.execute(count_query)
        return {
            "items": list(result.scalars().all()),
            "total": int(total_result.scalar_one()),
            "limit": limit,
            "offset": offset,
        }

    async def get_session(self, session_id: UUID) -> AssistantSession | None:
        return await self._get_session(session_id)

    async def run_session(self, session_id: UUID, *, model: str | None = None) -> AssistantSession:
        assistant_session = await self._get_session(session_id)
        if assistant_session is None:
            raise ValueError(f"Assistant session {session_id} not found")

        assistant_session.status = "processing"
        assistant_session.error = None
        await self.session.commit()

        try:
            sanitization = sanitize_entries([entry.raw_text for entry in assistant_session.entries])
            for entry, sanitized in zip(assistant_session.entries, sanitization.entries, strict=False):
                entry.sanitized_text = sanitized.sanitized_text
                entry.token_map_json = sanitized.token_map

            assistant_session.sanitization_summary_json = sanitization.summary

            merged_token_map: dict[str, str] = {}
            for entry in assistant_session.entries:
                merged_token_map.update(entry.token_map_json or {})

            sanitized_entries = [
                {
                    "entry_label": entry.entry_label,
                    "sanitized_text": entry.sanitized_text,
                }
                for entry in assistant_session.entries
            ]
            raw_entries = [entry.raw_text for entry in assistant_session.entries]

            if assistant_session.mode == "incident_correlation":
                system, user_text = build_incident_correlation_prompt(
                    title=assistant_session.title,
                    sanitized_entries=sanitized_entries,
                    raw_entries=raw_entries,
                    token_map=merged_token_map,
                )
            else:
                system, user_text = build_alert_analysis_prompt(
                    title=assistant_session.title,
                    sanitized_entries=sanitized_entries,
                    raw_entries=raw_entries,
                    token_map=merged_token_map,
                )

            report_markdown = await self._call_with_fallback(
                model=model,
                system=system,
                user_text=user_text,
            )
            # Strip AI-generated parenthetical expansions (e.g. "[IP_1] (10.0.0.1)")
            # before restoring tokens so the final report stays clean.
            cleaned = self._scrub_token_leakage(report_markdown)
            # Restore any tokens Claude used inline, then append the full identifier
            # table so analysts always see every resolved value.
            restored = self._restore_tokens(cleaned, merged_token_map)
            restored = self._replace_unresolved_tokens(restored, merged_token_map)
            final_report = self._append_resolved_identifiers(restored, merged_token_map)

            assistant_session.result_json = {
                "mode": assistant_session.mode,
                "title": assistant_session.title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            assistant_session.report_markdown = final_report
            assistant_session.status = "completed"
            assistant_session.completed_at = datetime.now(timezone.utc)
            await self.session.commit()
            reloaded = await self._get_session(session_id)
            return reloaded or assistant_session
        except Exception as exc:
            assistant_session.status = "failed"
            assistant_session.error = str(exc)
            await self.session.commit()
            raise

    async def create_from_investigation(self, investigation_id: UUID) -> AssistantSession:
        result = await self.session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            raise ValueError(f"Investigation {investigation_id} not found")

        assistant_session = await self.create_session(
            title=f"Investigation {investigation.domain}",
            mode="incident_correlation",
            source_type="from_investigation",
            linked_investigation_id=investigation.id,
        )
        await self.add_entry(
            assistant_session.id,
            text=(
                f"Investigation domain: {investigation.domain}\n"
                f"Observable type: {investigation.observable_type}\n"
                f"State: {investigation.state}\n"
                f"Risk score: {investigation.risk_score}\n"
            ),
            entry_label="investigation-summary",
            entry_index=0,
        )
        return await self._get_session(assistant_session.id)  # type: ignore[return-value]

    async def _get_session(self, session_id: UUID) -> AssistantSession | None:
        result = await self.session.execute(
            select(AssistantSession)
            .options(selectinload(AssistantSession.entries))
            .where(AssistantSession.id == session_id)
        )
        return result.scalar_one_or_none()

    async def _call_with_fallback(self, *, model: str | None, system: str, user_text: str) -> str:
        if model:
            if model.startswith("claude-"):
                return await self._call_claude(model=model, system=system, user_text=user_text)
            return await self._call_openai(model=model, system=system, user_text=user_text)

        if self.settings.anthropic_api_key:
            try:
                logger.info("Assistant primary model=%s", PRIMARY_MODEL)
                text = await self._call_claude(model=PRIMARY_MODEL, system=system, user_text=user_text)
                if text.strip():
                    return text
                logger.warning("Assistant Haiku returned empty output; falling back to GPT-5 Mini")
            except Exception as exc:
                logger.warning(
                    "Assistant Haiku call failed (%s: %s); falling back to GPT-5 Mini",
                    type(exc).__name__,
                    exc,
                )

        if not self.settings.openai_api_key:
            raise ValueError(
                "Both primary (Haiku) and fallback (GPT-5 Mini) are unavailable: "
                "ANTHROPIC_API_KEY and OPENAI_API_KEY are both unset."
            )
        logger.info("Assistant fallback model=%s", FALLBACK_MODEL)
        return await self._call_openai(model=FALLBACK_MODEL, system=system, user_text=user_text)

    async def _call_openai(self, *, model: str, system: str, user_text: str) -> str:
        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        record_provider_request("openai")
        response = await client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
            max_output_tokens=4096,
        )
        raw_text = getattr(response, "output_text", None) or ""
        if raw_text:
            return raw_text
        chunks: list[str] = []
        for item in getattr(response, "output", []) or []:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if text:
                    chunks.append(text)
        return "\n".join(chunks).strip()

    async def _call_claude(self, *, model: str, system: str, user_text: str) -> str:
        client = anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key)
        record_provider_request("anthropic")
        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user_text}],
        )
        return response.content[0].text if response and response.content else ""

    async def export_session_markdown(self, session_id: UUID) -> str:
        assistant_session = await self._get_session(session_id)
        if assistant_session is None:
            raise ValueError(f"Assistant session {session_id} not found")
        return assistant_session.report_markdown or ""

    def _scrub_token_leakage(self, text: str) -> str:
        """Remove parenthetical values the AI adds after tokens despite instructions.

        e.g. "[ACCOUNT_1] (povgrp\\pom29)" → "[ACCOUNT_1]"
        """
        return re.sub(r"(\[[A-Z]+_\d+\])\s*\([^)]{1,200}\)", r"\1", text)

    def _restore_tokens(self, text: str, token_map: dict[str, str]) -> str:
        restored = text
        for token, original in sorted(token_map.items(), key=lambda item: len(item[0]), reverse=True):
            restored = restored.replace(token, original)
            escaped_token = token.replace("[", r"\[").replace("]", r"\]")
            restored = restored.replace(escaped_token, original)
            token_pattern = re.escape(token).replace(r"\[", r"\\?\[").replace(r"\]", r"\\?\]")
            restored = re.sub(token_pattern, original, restored, flags=re.IGNORECASE)
        return restored

    _INLINE_TOKEN_RE = re.compile(r"\\?\[(?P<prefix>[A-Z]+)_(?P<number>\d+)\\?\]", re.IGNORECASE)
    _UNRESOLVED_TOKEN_LABELS: dict[str, str] = {
        "HOST": "the affected host",
        "ACCOUNT": "the affected account",
        "EMAIL": "the affected email address",
        "SID": "the affected security identifier",
        "IP": "the affected IP address",
    }

    def _replace_unresolved_tokens(self, text: str, token_map: dict[str, str]) -> str:
        known_tokens = {token.upper() for token in token_map}

        def repl(match: re.Match[str]) -> str:
            token = f"[{match.group('prefix').upper()}_{match.group('number')}]"
            if token in known_tokens:
                return match.group(0)
            return self._UNRESOLVED_TOKEN_LABELS.get(match.group("prefix").upper(), "the affected identifier")

        return self._INLINE_TOKEN_RE.sub(repl, text)

    _TOKEN_CATEGORY: dict[str, str] = {
        "IP": "IP Address",
        "HOST": "Hostname",
        "EMAIL": "Email Address",
        "ACCOUNT": "Account",
        "SID": "Security Identifier",
    }
    _TOKEN_RE = re.compile(r"^\[([A-Z]+)_(\d+)\]$")

    def _append_resolved_identifiers(self, report: str, token_map: dict[str, str]) -> str:
        if not token_map:
            return report
        rows: list[str] = []
        for token in sorted(token_map.keys()):
            m = self._TOKEN_RE.match(token)
            if m:
                category = self._TOKEN_CATEGORY.get(m.group(1), m.group(1).title())
                value = token_map[token]
                rows.append(f"| `{token}` | {category} | `{value}` |")
        if not rows:
            return report
        table = (
            "\n\n---\n\n## Resolved Identifiers\n\n"
            "Sensitive values were redacted before AI analysis. "
            "The table below maps every redacted token to its original value:\n\n"
            "| Token | Category | Value |\n"
            "|-------|----------|-------|\n"
            + "\n".join(rows)
        )
        return report + table
