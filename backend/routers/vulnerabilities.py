from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import AttackPathModel, VulnerabilityModel
from normalizer.unified_schema import FindingStatus, VulnerabilityStatusUpdateRequest
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.enrichment import calculate_dynamic_risk_score, mock_fetch_epss_score, mock_check_cisa_kev

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
async def list_vulnerabilities(
    request: Request,
    db: Session = Depends(get_db),
    severity: str | None = Query(default=None),
    scanner: str | None = Query(default=None),
    target: str | None = Query(default=None),
    status: str | None = Query(default=None),
    cve: str | None = Query(default=None),
):
    verify_access_token(request, required_scope="read")
    query = db.query(VulnerabilityModel)
    if severity:
        query = query.filter(VulnerabilityModel.severity == severity.upper())
    if scanner:
        query = query.filter(VulnerabilityModel.scanner_source == scanner.lower())
    if target:
        query = query.filter(VulnerabilityModel.target.ilike(f"%{target}%"))
    if status:
        query = query.filter(VulnerabilityModel.status == status)
    if cve:
        query = query.filter(VulnerabilityModel.cve_id.ilike(f"%{cve}%"))
    rows = query.order_by(VulnerabilityModel.detected_at.desc()).limit(500).all()
    return [
        {
            "finding_id": item.finding_id,
            "scan_id": item.scan_id,
            "target": item.target,
            "scanner_source": item.scanner_source,
            "detected_at": item.detected_at.isoformat(),
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
            "confidence_score": item.confidence_score,
            "false_positive_probability": item.false_positive_probability,
            "tags": item.tags,
            "status": item.status,
            "source_artifact_path": item.source_artifact_path,
        }
        for item in rows
    ]


@router.get("/{finding_id}")
async def get_vulnerability(finding_id: str, request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    row = db.get(VulnerabilityModel, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {
        "finding_id": row.finding_id,
        "scan_id": row.scan_id,
        "target": row.target,
        "scanner_source": row.scanner_source,
        "detected_at": row.detected_at.isoformat(),
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        "cve_id": row.cve_id or None,
        "cwe_id": row.cwe_id or None,
        "affected_component": row.affected_component,
        "affected_version": row.affected_version or None,
        "port": row.port or None,
        "protocol": row.protocol,
        "service": row.service or None,
        "evidence": row.evidence,
        "remediation": row.remediation or None,
        "references": row.references,
        "verification_status": row.verification_status,
        "confidence_score": row.confidence_score,
        "false_positive_probability": row.false_positive_probability,
        "tags": row.tags,
        "status": row.status,
        "source_artifact_path": row.source_artifact_path,
    }


@router.patch("/{finding_id}/status")
async def update_vulnerability_status(
    finding_id: str,
    payload: VulnerabilityStatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    row = db.get(VulnerabilityModel, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if payload.status not in {FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED, FindingStatus.ACCEPTED_RISK}:
        raise HTTPException(status_code=400, detail="Unsupported status")
    row.status = payload.status.value
    row.updated_at = datetime.utcnow()
    db.commit()
    write_audit_event(
        event_type="vuln.status.updated",
        actor=actor,
        scan_id=row.scan_id,
        details={"finding_id": finding_id, "status": payload.status.value},
    )
    return {"finding_id": finding_id, "status": payload.status.value}


@router.post("/{finding_id}/risk/recalculate")
async def recalculate_risk_score(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    verify_access_token(request, required_scope="write")
    row = db.get(VulnerabilityModel, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if row.cve_id:
        row.epss_score = mock_fetch_epss_score(row.cve_id)
        row.cisa_kev = mock_check_cisa_kev(row.cve_id)
    
    row.dynamic_risk_score = calculate_dynamic_risk_score(
        row.cvss_score, row.epss_score, row.cisa_kev
    )
    row.updated_at = datetime.utcnow()
    db.commit()
    
    return {
        "finding_id": finding_id,
        "epss_score": row.epss_score,
        "cisa_kev": row.cisa_kev,
        "dynamic_risk_score": row.dynamic_risk_score,
    }


@router.get("/attack-paths/{scan_id}")
async def get_attack_paths(scan_id: str, request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    rows = (
        db.query(AttackPathModel)
        .filter(AttackPathModel.scan_id == scan_id)
        .order_by(AttackPathModel.confidence_score.desc(), AttackPathModel.id.asc())
        .all()
    )
    return [
        {
            "id": item.id,
            "scan_id": item.scan_id,
            "target": item.target,
            "path_summary": item.path_summary,
            "confidence_score": item.confidence_score,
            "provenance": item.provenance,
            "created_at": item.created_at.isoformat(),
        }
        for item in rows
    ]
