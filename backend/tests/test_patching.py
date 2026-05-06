import pytest
from fastapi.testclient import TestClient
from main import app
from db.database import Base, engine, SessionLocal
from db.models import VulnerabilityModel, ScanJobModel

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    scan = ScanJobModel(id="SCAN-TEST", target="127.0.0.1")
    db.merge(scan)

    vuln = VulnerabilityModel(
        finding_id="VULN-TEST-123",
        scan_id="SCAN-TEST",
        target="127.0.0.1",
        scanner_source="test",
        title="Test Vuln",
        severity="HIGH"
    )
    db.merge(vuln)
    db.commit()
    db.close()
    yield

def test_deploy_patch():
    response = client.post("/api/v1/patching/deploy", json={
        "vulnerability_id": "VULN-TEST-123",
        "target": "127.0.0.1"
    })
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["status"] == "pending"
    assert data["vulnerability_id"] == "VULN-TEST-123"

def test_get_patch_job():
    res = client.post("/api/v1/patching/deploy", json={
        "vulnerability_id": "VULN-TEST-123",
        "target": "127.0.0.1"
    })
    job_id = res.json()["id"]

    res = client.get(f"/api/v1/patching/jobs/{job_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == job_id
    assert data["status"] in ["pending", "deploying", "success"]
