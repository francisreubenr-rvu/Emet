from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import func

from db.database import get_db
from db.models import AuditTrailModel, CveKnowledgeModel, SystemSettingModel
from services.auth_guard import verify_access_token, verify_admin

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/dataset-status")
async def dataset_status(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    counts = {
        source: count
        for source, count in db.query(CveKnowledgeModel.source, func.count(CveKnowledgeModel.id)).group_by(CveKnowledgeModel.source).all()
    }

    def _row(name: str, source_label: str, key: str):
        count = int(counts.get(key, 0))
        status = "LOADED" if count > 0 else "NOT_LOADED"
        return {"name": name, "source": source_label, "status": status, "size": count}

    return [
        _row("NVD CVE Feed", "NIST", "nvd"),
        _row("Exploit-DB", "Offensive Security", "exploitdb"),
        _row("OSV", "Google", "osv"),
    ]


@router.get("/dataset-history")
async def dataset_history(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    rows = (
        db.query(AuditTrailModel)
        .filter(
            AuditTrailModel.event_type.in_(
                ["rag.ingest.completed", "rag.ingest.scheduled", "rag.ingest.scheduled.failed"]
            )
        )
        .order_by(AuditTrailModel.created_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": item.id,
            "created_at": item.created_at.isoformat(),
            "event_type": item.event_type,
            "actor": item.actor,
            "details": item.details,
        }
        for item in rows
    ]


@router.get("")
async def get_settings(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    rows = db.query(SystemSettingModel).all()
    return {row.key: row.value for row in rows}


@router.put("")
async def put_settings(payload: dict, request: Request, db: Session = Depends(get_db)):
    token = verify_admin(request)
    actor = str(token.get("sub", "unknown"))
    for key, value in payload.items():
        row = db.get(SystemSettingModel, key)
        if row is None:
            row = SystemSettingModel(key=key, value=value)
            db.add(row)
        else:
            row.value = value
    db.add(AuditTrailModel(event_type="settings.updated", actor=actor, details={"keys": list(payload.keys())}, signature="settings-update"))
    db.commit()
    return {"status": "ok", "updated": list(payload.keys())}
