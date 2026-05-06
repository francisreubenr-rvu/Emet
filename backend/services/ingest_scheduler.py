from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta

from db.database import SessionLocal
from services.audit import write_audit_event
from services.knowledge_ingest import ingest_nvd_payload, ingest_osv_payload
from services.scheduler import enqueue_due_schedules
from services.redis_bus import get_redis_client
from services.queueing import worker_queue_list
from scripts.download_nvd import fetch_nvd_payload
from scripts.download_osv import fetch_osv_payload


async def run_ingest_cycle() -> None:
    nvd_enabled = os.getenv("INGEST_NVD_ENABLED", "true").lower() == "true"
    osv_enabled = os.getenv("INGEST_OSV_ENABLED", "true").lower() == "true"

    db = SessionLocal()
    try:
        if nvd_enabled:
            nvd_payload = await fetch_nvd_payload(api_key=os.getenv("NVD_API_KEY") or None)
            result = ingest_nvd_payload(db, nvd_payload, origin="scheduler:nvd")
            write_audit_event(event_type="rag.ingest.scheduled", actor="system", details=result)

        if osv_enabled:
            osv_payload = await fetch_osv_payload()
            result = ingest_osv_payload(db, osv_payload, origin="scheduler:osv")
            write_audit_event(event_type="rag.ingest.scheduled", actor="system", details=result)

        redis = get_redis_client()
        queue_depth = 0
        for name in worker_queue_list():
            queue_depth += int(await redis.llen(name))
        max_depth = int(os.getenv("SCHEDULE_QUEUE_MAX_DEPTH", "250"))
        if queue_depth >= max_depth:
            write_audit_event(
                event_type="schedule.enqueue.skipped",
                actor="system",
                details={"reason": "queue_backpressure", "queue_depth": queue_depth, "max_depth": max_depth},
            )
            return
        scan_ids = await enqueue_due_schedules(db, redis, actor="scheduler")
        if scan_ids:
            write_audit_event(
                event_type="schedule.enqueued",
                actor="system",
                details={"count": len(scan_ids), "scan_ids": scan_ids[:20]},
            )
    except Exception as exc:
        write_audit_event(
            event_type="rag.ingest.scheduled.failed",
            actor="system",
            details={"error": str(exc)},
        )
    finally:
        db.close()


async def scheduler_loop() -> None:
    interval_minutes = int(os.getenv("INGEST_INTERVAL_MINUTES", "180"))
    while True:
        start = datetime.utcnow()
        await run_ingest_cycle()
        next_run = start + timedelta(minutes=interval_minutes)
        sleep_for = max((next_run - datetime.utcnow()).total_seconds(), 5.0)
        await asyncio.sleep(sleep_for)
