from __future__ import annotations

from datetime import datetime
import io

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import ScanJobModel, VulnerabilityModel
from services.exporter import export_scan_csv, export_scan_json
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.osint import osint_service
from services.scan_store import get_scan_findings, list_scan_records

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/dashboard-stats")
async def dashboard_stats(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    records = list_scan_records(db)
    total = len(records)
    active = sum(1 for item in records if item.status in {"queued", "running"})
    critical = db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "CRITICAL").scalar() or 0
    verified = db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.verification_status == "verified").scalar() or 0
    last_time = records[0].created_at.isoformat() if records else datetime.utcnow().isoformat()
    distribution = {
        "CRITICAL": db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "CRITICAL").scalar() or 0,
        "HIGH": db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "HIGH").scalar() or 0,
        "MEDIUM": db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "MEDIUM").scalar() or 0,
        "LOW": db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "LOW").scalar() or 0,
        "INFO": db.query(func.count(VulnerabilityModel.finding_id)).filter(VulnerabilityModel.severity == "INFO").scalar() or 0,
    }
    return {
        "total_scans": total,
        "active_scans": active,
        "critical_findings": critical,
        "verified_findings": verified,
        "severity_distribution": distribution,
        "last_scan_time": last_time,
        "queue_health": "healthy",
        "rag_availability": "fallback",
        "evaluation_summary": {"latest_f1": 0.0, "latest_accuracy": 0.0},
    }


@router.get("")
async def list_reports(request: Request, db: Session = Depends(get_db)):
    token_payload = verify_access_token(request, required_scope="read")
    actor = str(token_payload.get("sub", "unknown"))
    write_audit_event(event_type="reports.list", actor=actor)
    records = list_scan_records(db)
    return [
        {
            "id": item.id,
            "target": item.target,
            "date": item.created_at.isoformat(),
            "duration": f"{item.duration_seconds // 60}m {item.duration_seconds % 60:02d}s",
            "tools": item.tools,
            "severity": item.severity,
            "findings_count": item.findings_count,
            "status": item.status,
        }
        for item in records
    ]


@router.get("/{report_id}")
async def report_detail(report_id: str, request: Request, db: Session = Depends(get_db)):
    token_payload = verify_access_token(request, required_scope="read")
    actor = str(token_payload.get("sub", "unknown"))
    write_audit_event(event_type="reports.detail", actor=actor, scan_id=report_id)
    record = db.get(ScanJobModel, report_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found")
    findings = get_scan_findings(db, report_id)
    pipeline_meta = {}
    for run in (record.scanner_runs or []):
        if run.get("scanner") == "pipeline":
            pipeline_meta = run.get("metadata", {})
    return {
        "id": record.id,
        "scan_id": record.id,
        "target": record.target,
        "date": record.created_at.isoformat(),
        "duration_seconds": record.duration_seconds,
        "tools": record.tools,
        "severity": record.severity,
        "findings_count": record.findings_count,
        "status": record.status,
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
    }


class OsintRequest(BaseModel):
    target: str


@router.post("/osint")
async def fetch_osint(payload: OsintRequest, request: Request):
    token_payload = verify_access_token(request, required_scope="read")
    actor = str(token_payload.get("sub", "unknown"))
    target = payload.target
    live = await osint_service.fetch(target)
    write_audit_event(event_type="reports.osint", actor=actor, details={"target": target})
    return {
        **live,
        "cve_entries": [
            {
                "cve_id": "CVE-2023-46604",
                "summary": "Potential CVE correlation based on discovered exposed services.",
            }
        ],
        "news": [
            {
                "source": "CISA",
                "title": f"Advisory context generated for {target}",
                "published_at": datetime.utcnow().isoformat(),
            }
        ],
    }


@router.get("/{report_id}/export/json")
async def export_report_json(report_id: str, request: Request, db: Session = Depends(get_db)):
    token_payload = verify_access_token(request, required_scope="read")
    actor = str(token_payload.get("sub", "unknown"))
    scan = db.get(ScanJobModel, report_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Report not found")
    findings = get_scan_findings(db, report_id)
    blob = export_scan_json(scan, findings)
    write_audit_event(event_type="reports.export.json", actor=actor, scan_id=report_id)
    return StreamingResponse(
        io.BytesIO(blob),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={report_id}.json"},
    )


@router.get("/{report_id}/export/csv")
async def export_report_csv(report_id: str, request: Request, db: Session = Depends(get_db)):
    token_payload = verify_access_token(request, required_scope="read")
    actor = str(token_payload.get("sub", "unknown"))
    scan = db.get(ScanJobModel, report_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Report not found")
    findings = get_scan_findings(db, report_id)
    blob = export_scan_csv(findings)
    write_audit_event(event_type="reports.export.csv", actor=actor, scan_id=report_id)
    return StreamingResponse(
        io.BytesIO(blob),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={report_id}.csv"},
    )
