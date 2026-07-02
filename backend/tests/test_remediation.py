import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from db.database import Base, get_db
from db.models import VulnerabilityModel, RemediationTicketModel

# Setup in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

from sqlalchemy.pool import StaticPool

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    # Re-assert this module's DB override in case another module leaked one.
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    app.dependency_overrides.pop(get_db, None)

def test_create_ticket_finding_not_found():
    response = client.post("/api/v1/remediation/tickets?finding_id=nonexistent")
    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"

def test_create_ticket_success():
    db = TestingSessionLocal()
    vuln = VulnerabilityModel(
        finding_id="test_finding_1",
        scan_id="test_scan_1",
        target="127.0.0.1",
        scanner_source="nmap",
        title="Test Vuln",
        description="Test Description",
        severity="HIGH",
        cve_id="CVE-2023-1234"
    )
    db.add(vuln)
    db.commit()
    db.close()

    response = client.post("/api/v1/remediation/tickets?finding_id=test_finding_1")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "test_finding_1"
    assert data["external_system"] == "jira" or data.get("external_id", "").startswith("JIRA-")
    assert data["status"] == "open"
    assert "Test Vuln" in data["summary"]

def test_get_tickets():
    db = TestingSessionLocal()
    vuln = VulnerabilityModel(
        finding_id="test_finding_2",
        scan_id="test_scan_2",
        target="127.0.0.1",
        scanner_source="nmap",
        title="Test Vuln 2"
    )
    db.add(vuln)
    db.commit()
    
    # create ticket manually
    ticket = RemediationTicketModel(
        finding_id="test_finding_2",
        external_id="JIRA-12345",
        external_system="jira",
        status="open",
        summary="Remediate: Test Vuln 2"
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    ticket_id = ticket.id
    db.close()

    response = client.get("/api/v1/remediation/tickets")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert any(t["finding_id"] == "test_finding_2" for t in data)

def test_sync_ticket():
    db = TestingSessionLocal()
    vuln = VulnerabilityModel(
        finding_id="test_finding_3",
        scan_id="test_scan_3",
        target="127.0.0.1",
        scanner_source="nmap",
        title="Test Vuln 3"
    )
    db.add(vuln)
    db.commit()
    
    # create ticket manually
    ticket = RemediationTicketModel(
        finding_id="test_finding_3",
        external_id="JIRA-9999",
        external_system="jira",
        status="open",
        summary="Remediate: Test Vuln 3"
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    ticket_id = ticket.id
    db.close()

    response = client.post(f"/api/v1/remediation/sync?ticket_id={ticket_id}")
    assert response.status_code == 200
    data = response.json()
    # With no Jira integration configured, sync must NOT fabricate a remote status.
    assert data["synced"] is False
    assert data["status"] == "open"
