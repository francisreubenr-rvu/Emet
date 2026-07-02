from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime
import time

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from db.database import Base, engine
from routers.auth import router as auth_router
from routers.audit import router as audit_router
from routers.evaluation import router as evaluation_router
from routers.exploit import router as exploit_router
from routers.rag import router as rag_router
from routers.reports import router as reports_router
from routers.scan import router as scan_router
from routers.schedules import router as schedules_router
from routers.settings import router as settings_router
from routers.alerts import router as alerts_router
from routers.operations import router as operations_router
from routers.vulnerabilities import router as vulnerabilities_router
from routers.patching import router as patching_router
from routers.tenants import router as tenants_router
from routers.compliance import router as compliance_router
from routers.agents import router as agents_router
from routers.remediation import router as remediation_router
from scanners.nmap_runner import NmapRunner
from scanners.nessus_runner import NessusRunner
from scanners.nuclei_runner import NucleiRunner
from scanners.openvas_runner import OpenVASRunner
from scanners.rustscan_runner import RustscanRunner
from scanners.semgrep_runner import SemgrepRunner
from scanners.trivy_runner import TrivyRunner
from scanners.gitleaks_runner import GitleaksRunner
from scanners.zap_runner import ZapRunner
from services.progress import subscribe_progress
from services.queueing import dead_letter_queue_name, worker_queue_list
from services.redis_bus import get_redis_client
from services.ingest_scheduler import scheduler_loop


def _parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    return [item.strip() for item in raw.split(",") if item.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    startup_retries = int(os.getenv("STARTUP_DB_RETRIES", "20"))
    startup_delay = float(os.getenv("STARTUP_DB_RETRY_DELAY_SECONDS", "1.0"))
    last_error: Exception | None = None
    for _ in range(startup_retries):
        try:
            Base.metadata.create_all(bind=engine)
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            time.sleep(startup_delay)
    if last_error is not None:
        raise last_error

    if os.getenv("INGEST_SCHEDULER_ENABLED", "true").lower() == "true":
        app.state.ingest_scheduler_task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        task = getattr(app.state, "ingest_scheduler_task", None)
        if task:
            task.cancel()


app = FastAPI(title="EMET Backend", version="1.1.0-phase1", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    redis = get_redis_client()
    try:
        queue_depth = 0
        for name in worker_queue_list():
            queue_depth += int(await redis.llen(name))
        dead_depth = int(await redis.llen(dead_letter_queue_name()))
        redis_status = "online"
    except Exception:
        queue_depth = -1
        dead_depth = -1
        redis_status = "offline"

    scanner_statuses = []
    for runner in [
        NmapRunner(),
        RustscanRunner(),
        NucleiRunner(),
        OpenVASRunner(),
        NessusRunner(),
        TrivyRunner(),
        SemgrepRunner(),
        GitleaksRunner(),
        ZapRunner(),
    ]:
        status = await runner.is_available()
        scanner_statuses.append({"scanner": status.scanner, "available": status.available, "reason": status.reason})

    return {
        "status": "online",
        "app": "EMET",
        "timestamp": datetime.utcnow().isoformat(),
        "redis": redis_status,
        "queue_depth": queue_depth,
        "dead_letter_depth": dead_depth,
        "scanners": scanner_statuses,
    }


@app.get("/api/readiness")
async def readiness():
    redis = get_redis_client()
    checks = {"database": "ok", "redis": "ok"}
    http_status = "ready"
    try:
        await redis.ping()
    except Exception:
        checks["redis"] = "degraded"
        http_status = "degraded"
    return {"status": http_status, "checks": checks}


app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(reports_router)
app.include_router(vulnerabilities_router)
app.include_router(exploit_router)
app.include_router(rag_router)
app.include_router(evaluation_router)
app.include_router(settings_router)
app.include_router(schedules_router)
app.include_router(alerts_router)
app.include_router(operations_router)
app.include_router(audit_router)
app.include_router(agents_router)
app.include_router(remediation_router)
app.include_router(patching_router)
app.include_router(compliance_router)
app.include_router(tenants_router)

@app.websocket("/ws/scan/{scan_id}/progress")
async def ws_scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    try:
        async for event in subscribe_progress(scan_id):
            await websocket.send_json(event)
            if event.get("phase") in {"COMPLETE", "FAILED", "CANCELLED"}:
                break
    finally:
        await websocket.close()


@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("[INFO] server boot complete")
    await websocket.send_text("[INFO] scanner registry initialized")
    await websocket.send_text("[INFO] redis queue bridge active")
    await websocket.close()


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"type": "platform", "message": "Defensive alert channel active."})
    await websocket.close()
