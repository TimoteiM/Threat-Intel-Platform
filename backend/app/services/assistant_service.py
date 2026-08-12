from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, time, timedelta, timezone
from pathlib import PureWindowsPath
from uuid import UUID

from langchain_core.messages import HumanMessage, SystemMessage
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.models.database import AssistantEntry, AssistantSession, Investigation
from app.services.provider_usage_metrics import record_provider_request
from app.services.assistant_prompt_service import (
    build_alert_analysis_prompt,
    build_incident_correlation_prompt,
)
from app.services.assistant_sanitizer_service import sanitize_entries
from app.services.assistant_incident_graph_service import build_assistant_incident_graph

logger = logging.getLogger(__name__)

PRIMARY_MODEL = "gpt-5.6-luna"
FALLBACK_MODEL = "claude-haiku-4-5-20251001"


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

    async def get_daily_alert_metrics(
        self,
        *,
        day: date,
        timezone_offset_minutes: int = 0,
    ) -> dict[str, object]:
        """Return completed alert-analysis volume for one analyst-local day."""
        local_tz = timezone(timedelta(minutes=-timezone_offset_minutes))
        start_local = datetime.combine(day, time.min, tzinfo=local_tz)
        end_local = start_local + timedelta(days=1)
        previous_start_local = start_local - timedelta(days=1)
        start_utc = previous_start_local.astimezone(timezone.utc)
        end_utc = end_local.astimezone(timezone.utc)

        result = await self.session.execute(
            select(AssistantSession.completed_at).where(
                AssistantSession.mode == "alert_analysis",
                AssistantSession.status == "completed",
                AssistantSession.completed_at.is_not(None),
                AssistantSession.completed_at >= start_utc,
                AssistantSession.completed_at < end_utc,
            )
        )

        hourly_counts = [0] * 24
        previous_total = 0
        for completed_at in result.scalars().all():
            if completed_at is None:
                continue
            if completed_at.tzinfo is None:
                completed_at = completed_at.replace(tzinfo=timezone.utc)
            completed_local = completed_at.astimezone(local_tz)
            if completed_local.date() == day:
                hourly_counts[completed_local.hour] += 1
            elif completed_local.date() == day - timedelta(days=1):
                previous_total += 1

        total = sum(hourly_counts)
        peak_hour_index = max(range(24), key=hourly_counts.__getitem__) if total else None
        change_percent = (
            round(((total - previous_total) / previous_total) * 100)
            if previous_total
            else None
        )
        return {
            "date": day.isoformat(),
            "timezone_offset_minutes": timezone_offset_minutes,
            "total": total,
            "previous_total": previous_total,
            "change_percent": change_percent,
            "peak_hour": (
                f"{peak_hour_index:02d}:00-{(peak_hour_index + 1) % 24:02d}:00"
                if peak_hour_index is not None
                else None
            ),
            "hourly": [
                {"hour": f"{hour:02d}:00", "count": count}
                for hour, count in enumerate(hourly_counts)
            ],
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
            if assistant_session.mode == "alert_analysis":
                restored = self._ensure_alert_key_observables(restored, raw_entries)
            final_report = self._append_resolved_identifiers(restored, merged_token_map)

            incident_graph = build_assistant_incident_graph(assistant_session, final_report)
            assistant_session.result_json = {
                "mode": assistant_session.mode,
                "title": assistant_session.title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "incident_graph": incident_graph,
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

        from app.analyst.models import configured_model_id, primary_model_configured

        # The primary model id comes from the configured provider, not from openai_model:
        # under LLM_PROVIDER=openai_compatible that would ask the local server for
        # "gpt-5.6-luna" and 404.
        primary_model = (configured_model_id(self.settings) or PRIMARY_MODEL).strip() or PRIMARY_MODEL
        fallback_model = (getattr(self.settings, "anthropic_model", None) or FALLBACK_MODEL).strip()

        if primary_model_configured(self.settings):
            try:
                logger.info("Assistant primary model=%s", primary_model)
                text = await self._call_openai(model=primary_model, system=system, user_text=user_text)
                if text.strip():
                    return text
                logger.warning("Assistant primary model returned empty output; falling back to Anthropic")
            except Exception as exc:
                logger.warning(
                    "Assistant primary model call failed (%s: %s); falling back to Anthropic",
                    type(exc).__name__,
                    exc,
                )

        if not self.settings.anthropic_api_key:
            raise ValueError(
                "Primary and fallback AI providers are unavailable. Configure a primary "
                "(LLM_PROVIDER=openai_compatible with LLM_MODEL and LLM_BASE_URL, or "
                "OPENAI_API_KEY), or set ANTHROPIC_API_KEY as the fallback."
            )
        logger.info("Assistant fallback model=%s", fallback_model)
        return await self._call_claude(model=fallback_model, system=system, user_text=user_text)

    async def _call_openai(self, *, model: str, system: str, user_text: str) -> str:
        """
        The primary call, through the configured provider.

        Kept named `_call_openai` because `_call_with_fallback` above and the service's
        tests both address it by name; with LLM_PROVIDER=openai_compatible it reaches a
        local server instead. Everything around it — the PII tokenization in
        sanitize_entries, `_scrub_token_leakage`, `_restore_tokens` — is untouched.
        """
        from app.analyst.models import build_model, message_text

        record_provider_request("openai")
        response = await build_model(model, max_tokens=4096).ainvoke(
            [SystemMessage(system), HumanMessage(user_text)]
        )
        return message_text(response)

    async def _call_claude(self, *, model: str, system: str, user_text: str) -> str:
        """
        The Anthropic fallback.

        Explicitly Anthropic rather than build_model: routing the fallback by LLM_PROVIDER
        would retry whatever just failed.
        """
        from app.analyst.models import build_anthropic_model, message_text

        record_provider_request("anthropic")
        response = await build_anthropic_model(model, max_tokens=4096).ainvoke(
            [SystemMessage(system), HumanMessage(user_text)]
        )
        return message_text(response)

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

    def _ensure_alert_key_observables(self, report: str, raw_entries: list[str]) -> str:
        """Add one readable sentence when the model omits core endpoint observables."""
        observables = self._extract_endpoint_observables(raw_entries)
        if not observables:
            return report
        core: list[tuple[str, str]] = []
        for label, value in observables:
            if label in {"process", "object file"}:
                core.append((label, PureWindowsPath(value).name or value))
            elif label in {"endpoint", "SHA-1", "SHA-256", "MD5", "process SHA-1", "process SHA-256", "process MD5"}:
                core.append((label, value))
        if not core:
            return report
        report_folded = report.casefold()
        if all(value.casefold() in report_folded for _, value in core):
            return report

        endpoint = next((value for label, value in core if label == "endpoint"), "")
        process = next((value for label, value in core if label == "process"), "")
        object_file = next((value for label, value in core if label == "object file"), "")
        hash_item = next(((label, value) for label, value in core if "SHA" in label or "MD5" in label), None)
        clauses: list[str] = []
        if process:
            clauses.append(f"the process as {process}")
        if endpoint:
            clauses.append(f"the endpoint as {endpoint}")
        if object_file:
            clauses.append(f"the extracted file as {object_file}")
        sentence = "The observed evidence identifies " + self._join_natural_clauses(clauses) + "."
        if hash_item:
            sentence += f" Its {hash_item[0]} is {hash_item[1]}."

        if "event interpretation" not in report.casefold():
            return f"## Event Interpretation\n\n{report.strip()} {sentence}".strip()
        return report.rstrip() + " " + sentence

    @staticmethod
    def _join_natural_clauses(clauses: list[str]) -> str:
        if not clauses:
            return "the relevant endpoint activity"
        if len(clauses) == 1:
            return clauses[0]
        if len(clauses) == 2:
            return f"{clauses[0]} and {clauses[1]}"
        return ", ".join(clauses[:-1]) + f", and {clauses[-1]}"

    @staticmethod
    def _extract_endpoint_observables(raw_entries: list[str]) -> list[tuple[str, str]]:
        observables: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(label: str, value: object) -> None:
            text = str(value or "").strip()
            key = (label, text.casefold())
            if not text or key in seen:
                return
            seen.add(key)
            observables.append((label, text[:700]))

        field_labels = {
            "processFilePath": "process",
            "processCmd": "command line",
            "objectFilePath": "object file",
            "objectFileHashSha1": "SHA-1",
            "objectFileHashSha256": "SHA-256",
            "objectFileHashMd5": "MD5",
            "processFileHashSha1": "process SHA-1",
            "processFileHashSha256": "process SHA-256",
            "processFileHashMd5": "process MD5",
        }

        for raw in raw_entries:
            try:
                payload = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            endpoint = payload.get("endpoint") or {}
            if isinstance(endpoint, dict):
                add("endpoint", endpoint.get("name"))
            for detection in payload.get("filters") or []:
                if not isinstance(detection, dict):
                    continue
                add("detection", detection.get("name"))
                add("severity", detection.get("level"))
                tactics = [str(value) for value in detection.get("tactics") or [] if value]
                techniques = [str(value) for value in detection.get("techniques") or [] if value]
                if tactics or techniques:
                    add("ATT&CK", ", ".join([*tactics, *techniques]))
                for highlighted in detection.get("highlightedObjects") or []:
                    if not isinstance(highlighted, dict):
                        continue
                    field = str(highlighted.get("field") or "")
                    label = field_labels.get(field)
                    if label:
                        add(label, highlighted.get("value"))
            if observables:
                break
        return observables
