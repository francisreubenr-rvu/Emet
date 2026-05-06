import pytest
from fastapi.testclient import TestClient

from main import app
from db.database import Base, engine, get_db
from db.models import VulnerabilityModel, ScanJobModel
from services.auth_guard import create_access_token
from services.enrichment import calculate_dynamic_risk_score

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def auth_headers():
    token = create_access_token(
        data={"sub": "test_user"},
        scopes=["read", "write"]
    )
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def db_session():
    # Setup
    from sqlalchemy.orm import Session
    with Session(engine) as session:
        yield session

def test_calculate_dynamic_risk_score():
    score1 = calculate_dynamic_risk_score(cvss_score=8.0, epss_score=0.9, cisa_kev=True)
    assert score1 > 8.0 # Should be high because of CISA KEV and high EPSS
    assert score1 <= 10.0
    
    score2 = calculate_dynamic_risk_score(cvss_score=4.0, epss_score=0.01, cisa_kev=False)
    assert score2 == (4.0 * 0.5) + (0.01 * 10 * 0.3)

def test_recalculate_risk_endpoint(db_session, auth_headers):
    # Create scan job
    scan_job = ScanJobModel(
        id="scan-risk-test",
        target="127.0.0.1",
        status="complete"
    )
    db_session.add(scan_job)
    
    # Create vulnerability
    vuln = VulnerabilityModel(
        finding_id="vuln-risk-test-1",
        scan_id="scan-risk-test",
        target="127.0.0.1",
        scanner_source="nmap",
        title="Test Vuln",
        cve_id="CVE-2021-12345",
        cvss_score=7.5
    )
    db_session.add(vuln)
    db_session.commit()

    # Call recalculate endpoint
    response = client.post(
        "/api/vulnerabilities/vuln-risk-test-1/risk/recalculate",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "vuln-risk-test-1"
    assert "epss_score" in data
    assert "cisa_kev" in data
    assert "dynamic_risk_score" in data
    
    # Verify in DB
    updated_vuln = db_session.query(VulnerabilityModel).filter_by(finding_id="vuln-risk-test-1").first()
    assert updated_vuln.epss_score == data["epss_score"]
    assert updated_vuln.cisa_kev == data["cisa_kev"]
    assert updated_vuln.dynamic_risk_score == data["dynamic_risk_score"]
