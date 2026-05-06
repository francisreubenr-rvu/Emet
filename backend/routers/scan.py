from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanners.gitleaks_runner import GitleaksRunner
from scanners.nessus_runner import NessusRunner
from scanners.nmap_runner import NmapRunner
from scanners.nuclei_runner import NucleiRunner
from scanners.openvas_runner import OpenVASRunner
from scanners.rustscan_runner import RustscanRunner
from scanners.semgrep_runner import SemgrepRunner
from scanners.trivy_runner import TrivyRunner
from scanners.zap_runner import ZapRunner

from ai.gemini_client import analyze_findings
from ai.rag_pipeline import run_rag_pipeline
from db.database import get_db
from db.models import ScanJobModel
from normalizer.unified_schema import ScanCreateRequest, ScanCreateResponse, ScanJobStatus, UnifiedFinding
from security.target_validation import validate_repo_target, validate_target
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.progress import encode_sse_event, publish_progress, subscribe_progress
from services.rate_limit import scan_rate_limiter
from services.redis_bus import get_redis_client
from services.queueing import queue_name_for_profile
from services.scan_store import get_scan_findings, list_scan_records, upsert_scan_record

router = APIRouter(prefix="/api/scan", tags=["scan"])


class AnalyzeRequest(BaseModel):
    findings: list[dict]
    mode: str = "unified"


def _rate_limit(identity: str) -> None:
    allowed, retry_after = scan_rate_limiter.allow(identity)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Retry in {retry_after}s")


@router.get("/availability")
async def scanner_availability():
    import os
    simulate = os.getenv("EMET_SIMULATE_SCANS", "false").lower() in ("true", "1", "yes")
    
    runners = [
        NmapRunner(),
        RustscanRunner(),
        NucleiRunner(),
        OpenVASRunner(),
        NessusRunner(),
        TrivyRunner(),
        SemgrepRunner(),
        GitleaksRunner(),
        ZapRunner(),
    ]
    result = []
    for runner in runners:
        if simulate:
            result.append({"scanner": runner.name, "available": True, "reason": "Simulation mode enabled"})
            continue
        status = await runner.is_available()
        result.append({"scanner": status.scanner, "available": status.available, "reason": status.reason})
    return result


@router.post("", response_model=ScanCreateResponse)
async def start_scan(
    request: Request,
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    x_forwarded_for: str | None = Header(default=None),
) -> ScanCreateResponse:
    token_payload = verify_access_token(request, required_scope="write")
    actor = str(token_payload.get("sub", "unknown"))
    identity = (x_forwarded_for or actor or "anonymous").split(",")[0].strip()
    _rate_limit(identity)

    repo_tools = {"trivy", "semgrep", "gitleaks"}
    is_repo_scan = any(scanner in repo_tools for scanner in payload.scanners)
    
    if is_repo_scan:
        ok, reason = validate_repo_target(payload.target)
    else:
        ok, reason = validate_target(payload.target)
        
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    scan_id = f"scan-{uuid4().hex[:10]}"
    upsert_scan_record(
        db,
        scan_id=scan_id,
        target=payload.target,
        profile=payload.profile,
        status=ScanJobStatus.QUEUED.value,
        tools=payload.scanners,
        findings=[],
        actor=actor,
        queue_identity=identity,
    )

    redis = get_redis_client()
    queue_name = queue_name_for_profile(payload.profile)
    await redis.lpush(
        queue_name,
        json.dumps(
            {
                "scan_id": scan_id,
                "target": payload.target,
                "profile": payload.profile,
                "scanners": payload.scanners,
                "actor": actor,
                "queue": queue_name,
                "enqueued_at": datetime.utcnow().isoformat(),
            }
        ),
    )

    await publish_progress(
        scan_id,
        {
            "phase": "QUEUED",
            "message": "Scan request accepted",
        },
    )

    write_audit_event(
        event_type="scan.queued",
        actor=actor,
        scan_id=scan_id,
        details={"target": payload.target, "profile": payload.profile, "scanners": payload.scanners, "queue": queue_name},
    )
    return ScanCreateResponse(scan_id=scan_id, status=ScanJobStatus.QUEUED, started_at=datetime.utcnow())


@router.post("/run")
async def run_scan(
    request: Request,
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    x_forwarded_for: str | None = Header(default=None),
):
    queued = await start_scan(request=request, payload=payload, db=db, x_forwarded_for=x_forwarded_for)
    return {
        "scan_id": queued.scan_id,
        "target": payload.target,
        "status": queued.status.value,
        "duration_seconds": 0,
        "findings": [],
        "unified_report": {},
        "zero_day": {},
        "self_audit": {},
    }


@router.get("")
async def list_scan_jobs(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    records = list_scan_records(db)
    return [
        {
            "scan_id": item.id,
            "target": item.target,
            "status": item.status,
            "profile": item.profile,
            "tools": item.tools,
            "requested_by": item.requested_by,
            "created_at": item.created_at.isoformat(),
            "updated_at": item.updated_at.isoformat(),
        }
        for item in records
    ]


@router.get("/{scan_id}")
async def get_scan_result(scan_id: str, request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    record = db.get(ScanJobModel, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = get_scan_findings(db, scan_id)
    pipeline_meta = {}
    for run in (record.scanner_runs or []):
        if run.get("scanner") == "pipeline":
            pipeline_meta = run.get("metadata", {})
    return {
        "scan_id": record.id,
        "target": record.target,
        "status": record.status,
        "duration_seconds": record.duration_seconds,
        "findings": [
            {
                "finding_id": item.finding_id,
                "scan_id": item.scan_id,
                "target": item.target,
                "scanner_source": item.scanner_source,
                "detected_at": item.detected_at.isoformat(),
                "timestamp": item.detected_at.isoformat(),
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "cvss_score": item.cvss_score,
                "cvss_vector": item.cvss_vector,
                "cve_id": item.cve_id or None,
                "cwe_id": item.cwe_id or None,
                "affected_component": item.affected_component,
                "affected_version": item.affected_version or None,
                "port": item.port or None,
                "protocol": item.protocol,
                "service": item.service or None,
                "evidence": item.evidence,
                "remediation": item.remediation or None,
                "references": item.references,
                "verification_status": item.verification_status,
                "verified": item.verification_status == "verified",
                "confidence_score": item.confidence_score,
                "false_positive_probability": item.false_positive_probability,
                "tags": item.tags,
                "status": item.status,
                "source_artifact_path": item.source_artifact_path,
            }
            for item in findings
        ],
        "unified_report": pipeline_meta.get("unified_report", {}),
        "zero_day": pipeline_meta.get("zero_day", {}),
        "self_audit": pipeline_meta.get("self_audit", {}),
        "scanner_runs": record.scanner_runs,
    }


@router.get("/{scan_id}/events")
async def stream_scan_progress(scan_id: str, request: Request):
    verify_access_token(request, required_scope="read")

    async def event_stream():
        async for event in subscribe_progress(scan_id):
            yield encode_sse_event(event)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))

    record = db.get(ScanJobModel, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status in {"complete", "failed", "cancelled"}:
        return {"scan_id": scan_id, "status": record.status}
    record.status = "cancelled"
    record.cancellation_requested = True
    record.updated_at = datetime.utcnow()
    db.commit()
    await publish_progress(scan_id, {"phase": "CANCELLED", "message": "Cancellation requested by analyst"})
    write_audit_event(event_type="scan.cancelled", actor=actor, scan_id=scan_id)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/analyze")
async def analyze(payload: AnalyzeRequest):
    parsed = [item if isinstance(item, dict) else {} for item in payload.findings]
    findings: list[UnifiedFinding] = []
    for item in parsed:
        try:
            findings.append(UnifiedFinding.model_validate(item))
        except Exception:
            continue

    rag = await run_rag_pipeline(findings)
    return await analyze_findings(findings, rag_context=rag["context"], mode=payload.mode)
