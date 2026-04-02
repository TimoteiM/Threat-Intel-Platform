from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from app.dependencies import DBSession
from app.models.schemas import (
    AssistantEntryCreate,
    AssistantEntryRead,
    AssistantSessionCreate,
    AssistantSessionDetailResponse,
    AssistantSessionListItem,
    AssistantSessionRunRequest,
)
from app.services.assistant_service import AssistantService


router = APIRouter(prefix="/api/assistant", tags=["assistant"])


def _serialize_session(session) -> dict:
    return AssistantSessionListItem.model_validate(session).model_dump(mode="json")


def _serialize_detail(session) -> dict:
    return AssistantSessionDetailResponse.model_validate(session).model_dump(mode="json")


@router.post("/sessions", status_code=201)
async def create_session(request: AssistantSessionCreate, session: DBSession):
    service = AssistantService(session)
    created = await service.create_session(
        title=request.title,
        mode=request.mode,
        source_type=request.source_type,
        linked_investigation_id=request.linked_investigation_id,
    )
    reloaded = await service.get_session(created.id)
    return _serialize_detail(reloaded)


@router.get("/sessions")
async def list_sessions(
    session: DBSession,
    limit: int = 50,
    offset: int = 0,
    search: str | None = None,
):
    service = AssistantService(session)
    results = await service.list_sessions(limit=limit, offset=offset, search=search)
    return {
        "items": [_serialize_session(item) for item in results["items"]],
        "total": results["total"],
        "limit": results["limit"],
        "offset": results["offset"],
    }


@router.get("/sessions/{session_id}")
async def get_session(session_id: uuid.UUID, session: DBSession):
    service = AssistantService(session)
    assistant_session = await service.get_session(session_id)
    if assistant_session is None:
        raise HTTPException(status_code=404, detail="Assistant session not found")
    return _serialize_detail(assistant_session)


@router.post("/sessions/{session_id}/entries", status_code=201)
async def add_entry(session_id: uuid.UUID, request: AssistantEntryCreate, session: DBSession):
    service = AssistantService(session)
    try:
        created = await service.add_entry(
            session_id,
            text=request.text,
            entry_label=request.entry_label,
            entry_index=request.entry_index,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return AssistantEntryRead.model_validate(created).model_dump(mode="json")


@router.post("/sessions/{session_id}/run")
async def run_session(
    session_id: uuid.UUID,
    request: AssistantSessionRunRequest,
    session: DBSession,
):
    service = AssistantService(session)
    try:
        result = await service.run_session(session_id, model=request.model)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _serialize_detail(result)


@router.get("/sessions/{session_id}/export")
async def export_session(session_id: uuid.UUID, session: DBSession):
    service = AssistantService(session)
    try:
        content = await service.export_session_markdown(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PlainTextResponse(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="assistant-{session_id}.md"'},
    )


@router.post("/sessions/from-investigation/{investigation_id}", status_code=201)
async def create_from_investigation(investigation_id: uuid.UUID, session: DBSession):
    service = AssistantService(session)
    try:
        created = await service.create_from_investigation(investigation_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _serialize_detail(created)
