from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from db.models import ScheduledScanModel
from normalizer.unified_schema import ScanCreateRequest
from security.target_validation import validate_target
from services.scan_store import upsert_scan_record
from services.queueing import queue_name_for_profile


def _parse_cron_field(field: str, min_value: int, max_value: int) -> set[int] | None:
    value = field.strip()
    if value == "*":
        return set(range(min_value, max_value + 1))
    if value.startswith("*/"):
        step_text = value[2:]
        if not step_text.isdigit():
            return None
        step = int(step_text)
        if step <= 0:
            return None
        return set(range(min_value, max_value + 1, step))

    values: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                return None
            start = int(start_text)
            end = int(end_text)
            if start > end or start < min_value or end > max_value:
                return None
            values.update(range(start, end + 1))
        else:
            if not part.isdigit():
                return None
            number = int(part)
            if number < min_value or number > max_value:
                return None
            values.add(number)
    return values


def validate_cron_expr(expr: str) -> bool:
    fields = expr.split()
    if len(fields) != 5:
        return False
    minute = _parse_cron_field(fields[0], 0, 59)
    hour = _parse_cron_field(fields[1], 0, 23)
    day = _parse_cron_field(fields[2], 1, 31)
    month = _parse_cron_field(fields[3], 1, 12)
    weekday = _parse_cron_field(fields[4], 0, 6)
    return all(item is not None for item in [minute, hour, day, month, weekday])


def _matches_cron(expr: str, dt: datetime) -> bool:
    fields = expr.split()
    minute = _parse_cron_field(fields[0], 0, 59)
    hour = _parse_cron_field(fields[1], 0, 23)
    day = _parse_cron_field(fields[2], 1, 31)
    month = _parse_cron_field(fields[3], 1, 12)
    weekday = _parse_cron_field(fields[4], 0, 6)
    if None in {minute, hour, day, month, weekday}:
        return False
    current_weekday = (dt.weekday() + 1) % 7
    return (
        dt.minute in minute
        and dt.hour in hour
        and dt.day in day
        and dt.month in month
        and current_weekday in weekday
    )


def compute_next_run(recurrence: str, now: datetime | None = None) -> datetime:
    current = now or datetime.utcnow()
    mode = recurrence.strip().lower()
    if mode == "daily":
        return current + timedelta(days=1)
    if mode == "weekly":
        return current + timedelta(weeks=1)
    if mode == "monthly":
        return current + timedelta(days=30)
    if mode.startswith("cron:"):
        expr = mode.split("cron:", 1)[1].strip()
        if not validate_cron_expr(expr):
            return current + timedelta(hours=1)
        probe = current.replace(second=0, microsecond=0) + timedelta(minutes=1)
        end = current + timedelta(days=366)
        while probe <= end:
            if _matches_cron(expr, probe):
                return probe
            probe += timedelta(minutes=1)
        return current + timedelta(hours=1)
    return current + timedelta(days=1)


def list_schedules(db: Session) -> list[ScheduledScanModel]:
    return db.query(ScheduledScanModel).order_by(ScheduledScanModel.created_at.desc()).all()


def create_schedule(
    db: Session,
    *,
    name: str,
    target: str,
    profile: str,
    scanners: list[str],
    recurrence: str,
    cron_expr: str,
    created_by: str,
) -> ScheduledScanModel:
    ok, reason = validate_target(target)
    if not ok:
        raise ValueError(reason)

    ScanCreateRequest(target=target, scanners=scanners, profile=profile)

    if recurrence == "cron" and not validate_cron_expr(cron_expr):
        raise ValueError("Invalid cron expression")

    now = datetime.utcnow()
    next_run = compute_next_run(f"cron:{cron_expr}" if recurrence == "cron" else recurrence, now)
    row = ScheduledScanModel(
        name=name,
        target=target,
        profile=profile,
        scanners=scanners,
        recurrence=recurrence,
        cron_expr=cron_expr,
        enabled=True,
        next_run_at=next_run,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_schedule(
    db: Session,
    *,
    schedule_id: int,
    name: str,
    profile: str,
    scanners: list[str],
    recurrence: str,
    cron_expr: str,
    enabled: bool,
) -> ScheduledScanModel:
    row = db.get(ScheduledScanModel, schedule_id)
    if row is None:
        raise ValueError("Schedule not found")

    ScanCreateRequest(target=row.target, scanners=scanners, profile=profile)
    if recurrence == "cron" and not validate_cron_expr(cron_expr):
        raise ValueError("Invalid cron expression")

    row.name = name
    row.profile = profile
    row.scanners = scanners
    row.recurrence = recurrence
    row.cron_expr = cron_expr
    row.enabled = enabled
    mode = f"cron:{cron_expr}" if recurrence == "cron" else recurrence
    row.next_run_at = compute_next_run(mode)
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def delete_schedule(db: Session, *, schedule_id: int) -> bool:
    row = db.get(ScheduledScanModel, schedule_id)
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


async def enqueue_schedule_now(db: Session, redis, *, schedule_id: int, actor: str) -> str:
    row = db.get(ScheduledScanModel, schedule_id)
    if row is None:
        raise ValueError("Schedule not found")

    scan_id = f"scan-{uuid4().hex[:10]}"
    upsert_scan_record(
        db,
        scan_id=scan_id,
        target=row.target,
        profile=row.profile,
        status="queued",
        tools=row.scanners,
        findings=[],
        actor=actor,
        queue_identity="scheduler",
    )
    payload = {
        "scan_id": scan_id,
        "target": row.target,
        "profile": row.profile,
        "scanners": row.scanners,
        "actor": actor,
        "scheduled_scan_id": row.id,
        "enqueued_at": datetime.utcnow().isoformat(),
    }
    queue = queue_name_for_profile(row.profile)
    payload["queue"] = queue
    await redis.lpush(queue, json.dumps(payload))
    row.last_run_at = datetime.utcnow()
    mode = f"cron:{row.cron_expr}" if row.recurrence == "cron" else row.recurrence
    row.next_run_at = compute_next_run(mode)
    row.updated_at = datetime.utcnow()
    db.commit()
    return scan_id


async def enqueue_due_schedules(db: Session, redis, *, actor: str = "scheduler") -> list[str]:
    now = datetime.utcnow()
    max_per_cycle = int(os.getenv("SCHEDULE_MAX_ENQUEUE_PER_CYCLE", "20"))
    due = (
        db.query(ScheduledScanModel)
        .filter(ScheduledScanModel.enabled.is_(True), ScheduledScanModel.next_run_at <= now)
        .order_by(ScheduledScanModel.next_run_at.asc())
        .limit(max_per_cycle)
        .all()
    )
    created_scan_ids: list[str] = []
    for schedule in due:
        scan_id = f"scan-{uuid4().hex[:10]}"
        upsert_scan_record(
            db,
            scan_id=scan_id,
            target=schedule.target,
            profile=schedule.profile,
            status="queued",
            tools=schedule.scanners,
            findings=[],
            actor=actor,
            queue_identity="scheduler",
        )
        payload = {
            "scan_id": scan_id,
            "target": schedule.target,
            "profile": schedule.profile,
            "scanners": schedule.scanners,
            "actor": actor,
            "scheduled_scan_id": schedule.id,
            "enqueued_at": datetime.utcnow().isoformat(),
        }
        queue = queue_name_for_profile(schedule.profile)
        payload["queue"] = queue
        await redis.lpush(queue, json.dumps(payload))
        schedule.last_run_at = now
        mode = f"cron:{schedule.cron_expr}" if schedule.recurrence == "cron" else schedule.recurrence
        schedule.next_run_at = compute_next_run(mode, now)
        schedule.updated_at = now
        created_scan_ids.append(scan_id)
    db.commit()
    return created_scan_ids
