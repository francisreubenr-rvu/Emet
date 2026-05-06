from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import AuditTrailModel
from services.auth_guard import verify_admin

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/logs")
async def get_audit_logs(
    request: Request,
    db: Session = Depends(get_db),
    event_type: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
):
    verify_admin(request)
    query = db.query(AuditTrailModel)
    if event_type:
        query = query.filter(AuditTrailModel.event_type == event_type)
    if actor:
        query = query.filter(AuditTrailModel.actor == actor)
    rows = query.order_by(AuditTrailModel.created_at.desc()).limit(limit).all()
    return [
        {
            "id": row.id,
            "created_at": row.created_at.isoformat(),
            "event_type": row.event_type,
            "actor": row.actor,
            "scan_id": row.scan_id,
            "details": row.details,
            "signature": row.signature,
        }
        for row in rows
    ]
