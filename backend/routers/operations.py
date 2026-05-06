from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request

from services.auth_guard import verify_access_token, verify_admin
from services.cspm_connectors import list_cspm_connectors
from services.queueing import dead_letter_queue_name, estimate_queue_oldest_age_seconds, queue_name_for_profile, worker_queue_list
from services.redis_bus import get_redis_client
from services.audit import write_audit_event

router = APIRouter(prefix="/api/operations", tags=["operations"])


@router.get("/workers")
async def worker_health(request: Request):
    verify_access_token(request, required_scope="read")
    redis = get_redis_client()
    keys = await redis.keys("worker:heartbeat:*")
    rows = []
    for key in keys:
        heartbeat = await redis.get(key)
        rows.append({"worker_id": key.replace("worker:heartbeat:", ""), "heartbeat": heartbeat})
    return rows


@router.get("/queue")
async def queue_health(request: Request):
    verify_access_token(request, required_scope="read")
    redis = get_redis_client()
    queue_depths = {}
    queue_oldest_age = {}
    total = 0
    for name in worker_queue_list():
        value = int(await redis.llen(name))
        queue_depths[name] = value
        total += value
        messages = await redis.lrange(name, 0, 25)
        queue_oldest_age[name] = estimate_queue_oldest_age_seconds(queue_items=messages)
    dead = int(await redis.llen(dead_letter_queue_name()))
    return {"queues": queue_depths, "queue_oldest_age_seconds": queue_oldest_age, "total_depth": total, "dead_letter_depth": dead}


@router.get("/cspm/connectors")
async def cspm_connectors(request: Request):
    verify_access_token(request, required_scope="read")
    return list_cspm_connectors()


@router.get("/metrics/workers")
async def worker_metrics(request: Request):
    verify_access_token(request, required_scope="read")
    redis = get_redis_client()
    keys = await redis.keys("metrics:worker:*")
    grouped: dict[str, dict[str, int]] = {}
    for key in keys:
        raw = await redis.get(key)
        try:
            value = int(raw or 0)
        except Exception:
            value = 0
        parts = key.split(":")
        if len(parts) < 4:
            continue
        worker_id = parts[2]
        metric = ":".join(parts[3:])
        grouped.setdefault(worker_id, {})[metric] = value
    return [{"worker_id": worker, "metrics": metrics} for worker, metrics in grouped.items()]


@router.post("/queue/dead-letter/replay")
async def replay_dead_letter(request: Request):
    token = verify_admin(request)
    actor = str(token.get("sub", "unknown"))
    redis = get_redis_client()
    dead_queue = dead_letter_queue_name()
    payload = await redis.rpop(dead_queue)
    if payload is None:
        raise HTTPException(status_code=404, detail="Dead-letter queue is empty")

    try:
        data = json.loads(payload)
        profile = str(data.get("profile") or "standard")
        target_queue = queue_name_for_profile(profile)
    except Exception:
        target_queue = queue_name_for_profile("standard")

    await redis.lpush(target_queue, payload)
    write_audit_event(
        event_type="operations.dead_letter.replay",
        actor=actor,
        details={"target_queue": target_queue},
    )
    return {"status": "replayed", "target_queue": target_queue}
