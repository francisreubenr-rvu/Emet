import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime

from main import app
from db.database import Base, engine, get_db
from db.models import VulnerabilityModel, ScanJobModel
from normalizer.unified_schema import UnifiedFinding, Severity

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    with engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection)
        yield session
        session.close()
        transaction.rollback()

@pytest.mark.asyncio
async def test_enrichment_compliance_mapping():
    from services.enrichment import enrich_findings
    
    finding = UnifiedFinding(
        scan_id="scan-compliance-1",
        target="127.0.0.1",
        scanner_source="nmap",
        title="Test Critical Finding",
        description="A critical issue",
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        cve_id="CVE-2021-1234",
        affected_component="OpenSSL"
    )
    
    enriched = await enrich_findings([finding])
    assert len(enriched) == 1
    
    violations = enriched[0].compliance_violations
    assert "SOC2 CC7.1" in violations
    assert "PCI-DSS 6.1" in violations

def test_compliance_api_endpoint(db_session):
    # Override dependency
    app.dependency_overrides[get_db] = lambda: db_session

    scan = ScanJobModel(id="scan-comp", target="10.0.0.1")
    db_session.add(scan)
    db_session.commit()

    vuln1 = VulnerabilityModel(
        finding_id="vuln-comp-1",
        scan_id="scan-comp",
        target="10.0.0.1",
        scanner_source="nessus",
        title="SQL Injection",
        severity="CRITICAL",
        compliance_violations=["SOC2 CC7.1", "PCI-DSS 6.1"]
    )
    vuln2 = VulnerabilityModel(
        finding_id="vuln-comp-2",
        scan_id="scan-comp",
        target="10.0.0.1",
        scanner_source="nessus",
        title="Low severity issue",
        severity="LOW",
        compliance_violations=["HIPAA 164.312"]
    )
    db_session.add_all([vuln1, vuln2])
    db_session.commit()

    response = client.get("/api/v1/compliance/SOC2")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["finding_id"] == "vuln-comp-1"
    assert "SOC2 CC7.1" in data[0]["compliance_violations"]

    response = client.get("/api/v1/compliance/HIPAA")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["finding_id"] == "vuln-comp-2"

    # Reset overrides
    app.dependency_overrides.clear()
