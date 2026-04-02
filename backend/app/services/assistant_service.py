from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.models.database import AssistantEntry, AssistantSession, Investigation
from app.services.assistant_prompt_service import (
    build_alert_analysis_prompt,
    build_incident_correlation_prompt,
)
from app.services.assistant_sanitizer_service import sanitize_entries


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
                )
            else:
                system, user_text = build_alert_analysis_prompt(
                    title=assistant_session.title,
                    sanitized_entries=sanitized_entries,
                    raw_entries=raw_entries,
                )

            report_markdown = await self._call_openai(
                model=model or self.settings.openai_model,
                system=system,
                user_text=user_text,
            )
            restored_report_markdown = self._restore_tokens(
                report_markdown,
                assistant_session.entries[0].token_map_json if assistant_session.entries else {},
            )

            assistant_session.result_json = {
                "mode": assistant_session.mode,
                "title": assistant_session.title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            assistant_session.report_markdown = restored_report_markdown
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

    async def _call_openai(self, *, model: str, system: str, user_text: str) -> str:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
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

    async def export_session_markdown(self, session_id: UUID) -> str:
        assistant_session = await self._get_session(session_id)
        if assistant_session is None:
            raise ValueError(f"Assistant session {session_id} not found")
        return assistant_session.report_markdown or ""

    def _restore_tokens(self, text: str, token_map: dict[str, str]) -> str:
        restored = text
        for token, original in sorted(token_map.items(), key=lambda item: len(item[0]), reverse=True):
            restored = restored.replace(token, original)
        return restored
