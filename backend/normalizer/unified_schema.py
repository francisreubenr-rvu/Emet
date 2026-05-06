from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class ScannerRunState(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class UnifiedFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"finding-{uuid4().hex[:12]}")
    scan_id: str
    target: str
    scanner_source: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    severity: Severity = Severity.INFO
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    cve_id: str | None = None
    cwe_id: str | None = None
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cisa_kev: bool = False
    dynamic_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    affected_component: str
    affected_version: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = "tcp"
    service: str | None = None
    evidence: dict = Field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    confidence_score: float = Field(ge=0.0, le=100.0, default=45.0)
    false_positive_probability: float = Field(ge=0.0, le=1.0, default=0.5)
    tags: list[str] = Field(default_factory=list)
    compliance_violations: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    source_artifact_path: str = ""

    # Legacy compatibility fields for current frontend.
    timestamp: datetime | None = None
    verified: bool | None = None

    @model_validator(mode="after")
    def sync_compatibility_fields(self) -> "UnifiedFinding":
        if self.timestamp is None:
            self.timestamp = self.detected_at
        else:
            self.detected_at = self.timestamp

        if self.verified is not None:
            self.verification_status = VerificationStatus.VERIFIED if self.verified else VerificationStatus.UNVERIFIED
        else:
            self.verified = self.verification_status == VerificationStatus.VERIFIED
        return self

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower().strip()
        if normalized not in {"tcp", "udp", "icmp", "http", "https"}:
            return "tcp"
        return normalized

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return Severity(str(value).upper())
        except ValueError:
            return Severity.INFO

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for tag in value:
            clean = tag.strip().lower()
            if not clean or clean in seen:
                continue
            seen.add(clean)
            normalized.append(clean)
        return normalized

    @field_validator("cwe_id")
    @classmethod
    def validate_cwe(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("CWE-"):
            raise ValueError("cwe_id must start with CWE-")
        return value

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("CVE-"):
            raise ValueError("cve_id must start with CVE-")
        return value


class ScannerRunSummary(BaseModel):
    scanner: str
    status: ScannerRunState
    findings_count: int = 0
    error: str = ""
    artifact_path: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime = Field(default_factory=datetime.utcnow)


class ScanCreateRequest(BaseModel):
    target: str
    scanners: list[str]
    profile: str

    @field_validator("scanners")
    @classmethod
    def validate_scanners(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip().lower() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("At least one scanner must be selected")
        supported = {"nmap", "rustscan", "nuclei", "openvas", "nessus", "trivy", "semgrep", "gitleaks", "zap"}
        invalid = sorted({item for item in cleaned if item not in supported})
        if invalid:
            raise ValueError(f"Unsupported scanners: {', '.join(invalid)}")
        return cleaned

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        profile = value.strip().lower()
        if profile not in {"quick", "standard", "deep"}:
            raise ValueError("Invalid scan profile")
        return profile


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: ScanJobStatus
    started_at: datetime


class UnifiedReport(BaseModel):
    executive_summary: str
    key_findings: list[str]
    zero_day_risk_assessment: str
    recommended_actions: list[str]


class ScanReportRecord(BaseModel):
    id: str
    target: str
    date: datetime
    duration_seconds: int
    tools: list[str]
    severity: Severity
    findings_count: int


class VulnerabilityStatusUpdateRequest(BaseModel):
    status: FindingStatus


class VulnerabilityRecord(BaseModel):
    finding_id: str
    scan_id: str
    target: str
    scanner_source: str
    title: str
    severity: Severity
    cve_id: str | None = None
    cwe_id: str | None = None
    verification_status: VerificationStatus
    confidence_score: float
    status: FindingStatus


class ScannerAvailability(BaseModel):
    scanner: str
    available: bool
    reason: str = ""


class DashboardSnapshot(BaseModel):
    total_scans: int
    active_scans: int
    critical_findings: int
    verified_findings: int
    severity_distribution: dict[str, int]
    recent_scans: list[dict]
    scanner_health: list[ScannerAvailability]
    queue_depth: int
    last_enrichment_update: str
    rag_availability: str
    evaluation_summary: dict
