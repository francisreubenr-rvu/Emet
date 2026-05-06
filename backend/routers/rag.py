from __future__ import annotations

from datetime import datetime
import os
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import ChatMessageModel, ChatSessionModel
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.knowledge_ingest import (
    SUPPORTED_INGEST_SOURCES,
    ingest_payload_by_source,
    load_json_from_file,
    load_json_from_url,
)
from services.rag_service import build_grounded_response, keyword_retrieve

router = APIRouter(prefix="/api/rag", tags=["rag"])


class ChatCreateRequest(BaseModel):
    title: str = "New Session"


class ChatMessageRequest(BaseModel):
    content: str


class IngestKnowledgeRequest(BaseModel):
    source: str
    payload: dict


class IngestFromFileRequest(BaseModel):
    source: str
    file_path: str


class IngestFromUrlRequest(BaseModel):
    source: str
    url: str


@router.post("/sessions")
async def create_session(payload: ChatCreateRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request)
    actor = str(token.get("sub", "unknown"))
    session_id = f"chat-{uuid4().hex[:12]}"
    row = ChatSessionModel(id=session_id, owner=actor, title=payload.title, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.add(row)
    db.commit()
    write_audit_event(event_type="rag.session.created", actor=actor, details={"session_id": session_id})
    return {"session_id": session_id, "title": payload.title}


@router.get("/sessions")
async def list_sessions(request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="read")
    actor = str(token.get("sub", "unknown"))
    rows = db.query(ChatSessionModel).filter(ChatSessionModel.owner == actor).order_by(ChatSessionModel.updated_at.desc()).all()
    return [{"session_id": item.id, "title": item.title, "updated_at": item.updated_at.isoformat()} for item in rows]


@router.get("/sessions/{session_id}")
async def session_messages(session_id: str, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="read")
    actor = str(token.get("sub", "unknown"))
    session = db.get(ChatSessionModel, session_id)
    if session is None or session.owner != actor:
        raise HTTPException(status_code=404, detail="Session not found")
    messages = db.query(ChatMessageModel).filter(ChatMessageModel.session_id == session_id).order_by(ChatMessageModel.created_at.asc()).all()
    return [
        {
            "id": item.id,
            "role": item.role,
            "content": item.content,
            "citations": item.citations,
            "created_at": item.created_at.isoformat(),
        }
        for item in messages
    ]


@router.post("/sessions/{session_id}/messages")
async def send_message(session_id: str, payload: ChatMessageRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request)
    actor = str(token.get("sub", "unknown"))
    session = db.get(ChatSessionModel, session_id)
    if session is None or session.owner != actor:
        raise HTTPException(status_code=404, detail="Session not found")

    user_msg = ChatMessageModel(session_id=session_id, role="user", content=payload.content, citations=[], created_at=datetime.utcnow())
    db.add(user_msg)

    docs = keyword_retrieve(db, payload.content, limit=5)
    response, citations = build_grounded_response(payload.content, docs)
    assistant_msg = ChatMessageModel(
        session_id=session_id,
        role="assistant",
        content=response,
        citations=citations,
        created_at=datetime.utcnow(),
    )
    db.add(assistant_msg)
    session.updated_at = datetime.utcnow()
    db.commit()
    write_audit_event(event_type="rag.message.sent", actor=actor, details={"session_id": session_id})
    return {"reply": response, "citations": assistant_msg.citations}


@router.post("/ingest")
async def ingest_knowledge(payload: IngestKnowledgeRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))

    try:
        result = ingest_payload_by_source(db, payload.source, payload.payload, origin="api:json")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    write_audit_event(event_type="rag.ingest.completed", actor=actor, details=result)
    return {"status": "ok", **result}


@router.post("/ingest/file")
async def ingest_knowledge_from_file(payload: IngestFromFileRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    if payload.source.strip().lower() not in SUPPORTED_INGEST_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported source")

    allowed_root = os.getenv("INGEST_ALLOWED_ROOT", "/app/datasets")
    try:
        raw_payload, resolved_path = load_json_from_file(payload.file_path, allowed_root=allowed_root)
        result = ingest_payload_by_source(db, payload.source, raw_payload, origin=f"file:{resolved_path}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    write_audit_event(event_type="rag.ingest.completed", actor=actor, details=result)
    return {"status": "ok", "origin": resolved_path, **result}


@router.post("/ingest/url")
async def ingest_knowledge_from_url(payload: IngestFromUrlRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    if payload.source.strip().lower() not in SUPPORTED_INGEST_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported source")

    try:
        raw_payload = await load_json_from_url(payload.url)
        result = ingest_payload_by_source(db, payload.source, raw_payload, origin=f"url:{payload.url}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {exc}") from exc

    write_audit_event(event_type="rag.ingest.completed", actor=actor, details=result)
    return {"status": "ok", "origin": payload.url, **result}
