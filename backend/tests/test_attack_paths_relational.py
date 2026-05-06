from datetime import datetime

from db.models import VulnerabilityModel
from services.attack_paths import build_attack_paths, build_relational_attack_paths


def test_build_relational_attack_paths_orders_by_severity_and_score():
    findings = [
        VulnerabilityModel(
            finding_id="f1",
            scan_id="scan-1",
            target="example.com",
            scanner_source="nmap",
            detected_at=datetime.utcnow(),
            title="Low issue",
            description="",
            severity="LOW",
            cvss_score=3.1,
            cvss_vector="",
            cve_id="CVE-2099-3001",
            cwe_id="",
            affected_component="svc",
            affected_version="",
            port=443,
            protocol="tcp",
            service="https",
            evidence={},
            remediation="",
            references=[],
            verification_status="unverified",
            confidence_score=40.0,
            false_positive_probability=0.5,
            tags=[],
            status="open",
            source_artifact_path="",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        ),
        VulnerabilityModel(
            finding_id="f2",
            scan_id="scan-1",
            target="example.com",
            scanner_source="nuclei",
            detected_at=datetime.utcnow(),
            title="Critical issue",
            description="",
            severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="",
            cve_id="CVE-2099-3002",
            cwe_id="",
            affected_component="web",
            affected_version="",
            port=443,
            protocol="tcp",
            service="https",
            evidence={},
            remediation="",
            references=[],
            verification_status="verified",
            confidence_score=88.0,
            false_positive_probability=0.2,
            tags=[],
            status="open",
            source_artifact_path="",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        ),
    ]
    paths = build_relational_attack_paths("scan-1", findings)
    assert paths
    assert paths[0]["scan_id"] == "scan-1"
    assert "CVE-2099-3002" in paths[0]["path_summary"]


def test_build_attack_paths_uses_fallback_when_neo4j_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_NEO4J", "false")
    paths = build_attack_paths("scan-2", [])
    assert paths == []


def test_build_attack_paths_marks_neo4j_fallback_when_enabled_without_config(monkeypatch):
    monkeypatch.setenv("ENABLE_NEO4J", "true")
    monkeypatch.delenv("NEO4J_URI", raising=False)
    paths = build_attack_paths("scan-3", [])
    assert paths == []
