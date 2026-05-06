from db.database import SessionLocal
from db.models import ScanJobModel


def test_scan_run_contract_shape(auth_client):
    response = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap", "rustscan"], "profile": "quick"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert set(payload.keys()) >= {"scan_id", "target", "status", "findings", "unified_report"}
    assert payload["status"] == "queued"


def test_scan_list_returns_created_job(auth_client):
    create = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap"], "profile": "quick"},
    )
    assert create.status_code == 200
    created_id = create.json()["scan_id"]

    listing = auth_client.get("/api/scan")
    assert listing.status_code == 200
    ids = [item["scan_id"] for item in listing.json()]
    assert created_id in ids


def test_scan_cancel_changes_status(auth_client):
    create = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap"], "profile": "quick"},
    )
    scan_id = create.json()["scan_id"]

    cancel = auth_client.delete(f"/api/scan/{scan_id}")
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"

    db = SessionLocal()
    try:
        record = db.get(ScanJobModel, scan_id)
        assert record is not None
        assert record.status == "cancelled"
    finally:
        db.close()


def test_scan_availability_includes_phase2_scanners(auth_client):
    response = auth_client.get("/api/scan/availability")
    assert response.status_code == 200
    payload = response.json()
    scanners = {item["scanner"] for item in payload}
    assert {"nmap", "rustscan", "nuclei", "openvas", "nessus", "trivy", "semgrep", "gitleaks", "zap"}.issubset(scanners)
