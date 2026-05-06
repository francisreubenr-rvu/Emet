from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import RawArtifactModel, ScanJobModel, VulnerabilityModel
from normalizer.unified_schema import ScannerRunSummary, UnifiedFinding


def upsert_scan_record(
    db: Session,
    *,
    scan_id: str,
    target: str,
    profile: str,
    status: str,
    tools: list[str],
    findings: Iterable[UnifiedFinding] | None = None,
    duration_seconds: int = 0,
    score: float = 0.0,
    unified_report: dict | None = None,
    zero_day: dict | None = None,
    self_audit: dict | None = None,
    scanner_runs: list[ScannerRunSummary] | None = None,
    actor: str = "unknown",
    queue_identity: str = "anonymous",
) -> ScanJobModel:
    record = db.get(ScanJobModel, scan_id)
    finding_models = [item for item in (findings or [])]
    serialized_findings = [item.model_dump(mode="json") for item in finding_models]

    if record is None:
        record = ScanJobModel(
            id=scan_id,
            target=target,
            profile=profile,
            status=status,
            tools=tools,
            scanner_runs=[item.model_dump(mode="json") for item in (scanner_runs or [])],
            requested_by=actor,
            queue_identity=queue_identity,
            duration_seconds=duration_seconds,
            score=score,
            findings_count=len(serialized_findings),
            severity=_derive_severity(serialized_findings),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(record)
    else:
        record.target = target
        record.profile = profile
        record.status = status
        record.tools = tools
        if scanner_runs is not None:
            record.scanner_runs = [item.model_dump(mode="json") for item in scanner_runs]
        record.duration_seconds = duration_seconds
        record.score = score
        record.findings_count = len(serialized_findings)
        record.severity = _derive_severity(serialized_findings)
        record.updated_at = datetime.utcnow()

    # Replace vulnerabilities for this scan id.
    db.query(VulnerabilityModel).filter(VulnerabilityModel.scan_id == scan_id).delete(synchronize_session=False)
    for finding in finding_models:
        db.add(
            VulnerabilityModel(
                finding_id=finding.finding_id,
                scan_id=scan_id,
                target=finding.target,
                scanner_source=finding.scanner_source,
                detected_at=finding.detected_at,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                cve_id=finding.cve_id or "",
                cwe_id=finding.cwe_id or "",
                affected_component=finding.affected_component,
                affected_version=finding.affected_version or "",
                port=finding.port or 0,
                protocol=finding.protocol or "tcp",
                service=finding.service or "",
                evidence=finding.evidence,
                remediation=finding.remediation or "",
                references=finding.references,
                verification_status=finding.verification_status.value,
                confidence_score=finding.confidence_score,
                false_positive_probability=finding.false_positive_probability,
                tags=finding.tags,
                status=finding.status.value,
                source_artifact_path=finding.source_artifact_path,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )

    # Keep lightweight metadata in scanner_runs if report dicts are present.
    if unified_report is not None or zero_day is not None or self_audit is not None:
        metadata = {
            "unified_report": unified_report or {},
            "zero_day": zero_day or {},
            "self_audit": self_audit or {},
        }
        runs = list(record.scanner_runs or [])
        runs.append({"scanner": "pipeline", "status": "success", "metadata": metadata, "captured_at": datetime.utcnow().isoformat()})
        record.scanner_runs = runs[-8:]

    db.commit()
    db.refresh(record)
    return record


def add_raw_artifact(db: Session, *, scan_id: str, scanner_source: str, artifact_path: str, checksum: str = "") -> None:
    if not artifact_path:
        return
    db.add(
        RawArtifactModel(
            scan_id=scan_id,
            scanner_source=scanner_source,
            artifact_path=artifact_path,
            checksum=checksum,
            created_at=datetime.utcnow(),
        )
    )
    db.commit()


def list_scan_records(db: Session) -> list[ScanJobModel]:
    stmt = select(ScanJobModel).order_by(ScanJobModel.created_at.desc())
    return list(db.execute(stmt).scalars().all())


def get_scan_findings(db: Session, scan_id: str) -> list[VulnerabilityModel]:
    stmt = select(VulnerabilityModel).where(VulnerabilityModel.scan_id == scan_id).order_by(VulnerabilityModel.detected_at.desc())
    return list(db.execute(stmt).scalars().all())


def _derive_severity(findings: list[dict]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for level in order:
        if any(item.get("severity") == level for item in findings):
            return level
    return "INFO"
