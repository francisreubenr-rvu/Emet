from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import AsyncIterator

from services.redis_bus import get_redis_client


def _channel(scan_id: str) -> str:
    return f"scan-progress:{scan_id}"


def _seq_key(scan_id: str) -> str:
    return f"scan-progress:seq:{scan_id}"


def _last_key(scan_id: str) -> str:
    return f"scan-progress:last:{scan_id}"


async def publish_progress(scan_id: str, event: dict) -> None:
    redis = get_redis_client()
    sequence = await redis.incr(_seq_key(scan_id))
    payload = {
        **event,
        "scan_id": scan_id,
        "sequence": sequence,
        "timestamp": event.get("timestamp") or datetime.utcnow().isoformat(),
    }
    encoded = json.dumps(payload)
    await redis.set(_last_key(scan_id), encoded, ex=3600)
    await redis.publish(_channel(scan_id), encoded)


async def subscribe_progress(scan_id: str) -> AsyncIterator[dict]:
    redis = get_redis_client()
    pubsub = redis.pubsub()
    await pubsub.subscribe(_channel(scan_id))

    latest = await redis.get(_last_key(scan_id))
    if latest:
        try:
            yield json.loads(latest)
        except json.JSONDecodeError:
            pass

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if not message:
                await asyncio.sleep(0.1)
                continue
            data = message.get("data")
            if not isinstance(data, str):
                continue
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                continue
            yield payload
            if payload.get("phase") in {"COMPLETE", "FAILED", "CANCELLED"}:
                break
    finally:
        await pubsub.unsubscribe(_channel(scan_id))
        await pubsub.close()


def encode_sse_event(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"
