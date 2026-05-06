from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from uuid import uuid4

from db.database import SessionLocal
from db.models import ScanJobModel
from services.audit import write_audit_event
from services.progress import publish_progress
from services.redis_bus import get_redis_client
from services.scan_pipeline import execute_scan_job
from services.queueing import dead_letter_queue_name, worker_queue_list
from services.worker_control import can_execute_scan, heartbeat_key, lock_key

MAX_ATTEMPTS = int(os.getenv("WORKER_MAX_ATTEMPTS", "3"))


async def _refresh_heartbeat(redis, worker_id: str) -> None:
    ttl = int(os.getenv("WORKER_HEARTBEAT_TTL_SECONDS", "45"))
    await redis.set(heartbeat_key(worker_id), datetime.utcnow().isoformat(), ex=ttl)


async def run_worker() -> None:
    redis = get_redis_client()
    worker_id = os.getenv("WORKER_ID", f"worker-{uuid4().hex[:8]}")
    lock_ttl = int(os.getenv("SCAN_LOCK_TTL_SECONDS", "3600"))
    metrics_prefix = f"metrics:worker:{worker_id}"

    while True:
        await _refresh_heartbeat(redis, worker_id)
        queue_list = worker_queue_list()
        job = await redis.brpop(queue_list, timeout=0)
        if not job:
            continue
        queue_name, payload = job

        try:
            data = json.loads(payload)
        except Exception:
            write_audit_event(event_type="scan.job.invalid", actor=worker_id, details={"payload": str(payload)[:300]})
            await redis.incr(f"{metrics_prefix}:invalid")
            continue

        scan_id = data.get("scan_id")
        if not scan_id:
            write_audit_event(event_type="scan.job.invalid", actor=worker_id, details={"reason": "missing_scan_id"})
            await redis.incr(f"{metrics_prefix}:invalid")
            continue

        attempts = int(data.get("attempts") or 0)

        lock = lock_key(scan_id)
        acquired = await redis.set(lock, worker_id, ex=lock_ttl, nx=True)
        if not acquired:
            write_audit_event(event_type="scan.job.skipped.locked", actor=worker_id, scan_id=scan_id)
            await redis.incr(f"{metrics_prefix}:skipped_locked")
            continue

        db = SessionLocal()
        try:
            row = db.get(ScanJobModel, scan_id)
            if row is None:
                write_audit_event(event_type="scan.job.skipped.missing", actor=worker_id, scan_id=scan_id)
                await redis.delete(lock)
                await redis.incr(f"{metrics_prefix}:skipped_missing")
                continue
            if not can_execute_scan(row.status):
                write_audit_event(
                    event_type="scan.job.skipped.terminal",
                    actor=worker_id,
                    scan_id=scan_id,
                    details={"status": row.status},
                )
                await redis.delete(lock)
                await redis.incr(f"{metrics_prefix}:skipped_terminal")
                continue
        finally:
            db.close()

        write_audit_event(event_type="scan.job.picked", actor=worker_id, scan_id=scan_id)
        await redis.incr(f"{metrics_prefix}:picked")
        started_at = time.monotonic()
        await publish_progress(
            scan_id,
            {
                "phase": "QUEUED",
                "progress": 2,
                "message": f"Job picked by {worker_id}",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        try:
            await execute_scan_job(
                scan_id=scan_id,
                target=data["target"],
                profile=data["profile"],
                scanners=data["scanners"],
                actor=data.get("actor", worker_id),
            )
            await redis.incr(f"{metrics_prefix}:completed")
            elapsed_ms = int((time.monotonic() - started_at) * 1000)
            await redis.incrby(f"{metrics_prefix}:duration_ms_total", elapsed_ms)
            for scanner in data.get("scanners") or []:
                await redis.incr(f"{metrics_prefix}:scanner:{scanner}")
        finally:
            await redis.delete(lock)

        db = SessionLocal()
        try:
            row = db.get(ScanJobModel, scan_id)
            failed = row is not None and row.status == "failed"
        finally:
            db.close()

        if failed:
            await redis.incr(f"{metrics_prefix}:failed")
            if attempts + 1 < MAX_ATTEMPTS:
                data["attempts"] = attempts + 1
                await redis.lpush(queue_name, json.dumps(data))
                write_audit_event(
                    event_type="scan.job.retry.queued",
                    actor=worker_id,
                    scan_id=scan_id,
                    details={"attempt": attempts + 1, "queue": queue_name},
                )
            else:
                dead_queue = dead_letter_queue_name()
                data["attempts"] = attempts + 1
                await redis.lpush(dead_queue, json.dumps(data))
                write_audit_event(
                    event_type="scan.job.dead_lettered",
                    actor=worker_id,
                    scan_id=scan_id,
                    details={"attempts": attempts + 1, "dead_queue": dead_queue},
                )


if __name__ == "__main__":
    asyncio.run(run_worker())
