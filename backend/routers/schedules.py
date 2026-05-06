from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db.database import get_db
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.redis_bus import get_redis_client
from services.scheduler import create_schedule, delete_schedule, enqueue_schedule_now, list_schedules, update_schedule


SCHEDULE_LOCKS: set[int] = set()

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


class ScheduleCreateRequest(BaseModel):
    name: str = "Scheduled Scan"
    target: str
    profile: str = "standard"
    scanners: list[str]
    recurrence: str = Field(default="daily")
    cron_expr: str = ""


class ScheduleUpdateRequest(BaseModel):
    name: str
    profile: str
    scanners: list[str]
    recurrence: str
    cron_expr: str = ""
    enabled: bool = True


@router.get("")
async def get_schedules(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    rows = list_schedules(db)
    return [
        {
            "id": row.id,
            "name": row.name,
            "target": row.target,
            "profile": row.profile,
            "scanners": row.scanners,
            "recurrence": row.recurrence,
            "cron_expr": row.cron_expr,
            "enabled": row.enabled,
            "next_run_at": row.next_run_at.isoformat(),
            "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
            "created_by": row.created_by,
            "updated_at": row.updated_at.isoformat(),
        }
        for row in rows
    ]


@router.post("")
async def post_schedule(payload: ScheduleCreateRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))

    recurrence = payload.recurrence.strip().lower()
    if recurrence not in {"daily", "weekly", "monthly", "cron"}:
        raise HTTPException(status_code=400, detail="Unsupported recurrence")
    if recurrence == "cron" and not payload.cron_expr.strip():
        raise HTTPException(status_code=400, detail="cron_expr is required for cron recurrence")

    try:
        row = create_schedule(
            db,
            name=payload.name,
            target=payload.target,
            profile=payload.profile,
            scanners=payload.scanners,
            recurrence=recurrence,
            cron_expr=payload.cron_expr,
            created_by=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    write_audit_event(
        event_type="schedule.created",
        actor=actor,
        details={"schedule_id": row.id, "target": row.target, "recurrence": row.recurrence, "created_at": datetime.utcnow().isoformat()},
    )
    return {"id": row.id, "status": "created", "next_run_at": row.next_run_at.isoformat()}


@router.put("/{schedule_id}")
async def put_schedule(schedule_id: int, payload: ScheduleUpdateRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    recurrence = payload.recurrence.strip().lower()
    if recurrence not in {"daily", "weekly", "monthly", "cron"}:
        raise HTTPException(status_code=400, detail="Unsupported recurrence")
    if recurrence == "cron" and not payload.cron_expr.strip():
        raise HTTPException(status_code=400, detail="cron_expr is required for cron recurrence")
    try:
        row = update_schedule(
            db,
            schedule_id=schedule_id,
            name=payload.name,
            profile=payload.profile,
            scanners=payload.scanners,
            recurrence=recurrence,
            cron_expr=payload.cron_expr,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit_event(event_type="schedule.updated", actor=actor, details={"schedule_id": row.id})
    return {"id": row.id, "status": "updated", "next_run_at": row.next_run_at.isoformat()}


@router.delete("/{schedule_id}")
async def remove_schedule(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    ok = delete_schedule(db, schedule_id=schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    write_audit_event(event_type="schedule.deleted", actor=actor, details={"schedule_id": schedule_id})
    return {"id": schedule_id, "status": "deleted"}


@router.post("/{schedule_id}/run-now")
async def run_schedule_now(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    redis = get_redis_client()
    if schedule_id in SCHEDULE_LOCKS:
        raise HTTPException(status_code=409, detail="Schedule already queued")
    SCHEDULE_LOCKS.add(schedule_id)
    try:
        scan_id = await enqueue_schedule_now(db, redis, schedule_id=schedule_id, actor=actor)
    except ValueError as exc:
        SCHEDULE_LOCKS.discard(schedule_id)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    finally:
        SCHEDULE_LOCKS.discard(schedule_id)
    write_audit_event(event_type="schedule.run_now", actor=actor, details={"schedule_id": schedule_id, "scan_id": scan_id})
    return {"schedule_id": schedule_id, "scan_id": scan_id, "status": "queued"}
