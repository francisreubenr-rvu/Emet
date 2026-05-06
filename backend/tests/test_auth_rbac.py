def test_login_sets_cookies(client):
    response = client.post("/api/auth/login", json={"identifier": "analyst@emet.local", "password": "emet"})
    assert response.status_code == 200
    cookies = response.headers.get("set-cookie", "")
    assert "emet_access" in cookies
    assert "emet_refresh" in cookies


def test_guest_cannot_start_scan(client):
    response = client.post("/api/auth/login", json={"identifier": "guest", "password": "emet"})
    assert response.status_code == 200
    scan_response = client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap"], "profile": "quick"},
    )
    assert scan_response.status_code == 403
    assert scan_response.json()["detail"] == "Insufficient scope"


def test_analyst_can_start_scan(auth_client):
    response = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap"], "profile": "quick"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["scan_id"].startswith("scan-")


def test_guest_cannot_ingest_knowledge(client):
    response = client.post("/api/auth/login", json={"identifier": "guest", "password": "emet"})
    assert response.status_code == 200

    ingest_response = client.post(
        "/api/rag/ingest",
        json={"source": "nvd", "payload": {"vulnerabilities": []}},
    )
    assert ingest_response.status_code == 403
    assert ingest_response.json()["detail"] == "Insufficient scope"


def test_analyst_cannot_read_audit_logs(auth_client):
    response = auth_client.get("/api/audit/logs")
    assert response.status_code == 403


def test_admin_can_read_audit_logs(client):
    login = client.post("/api/auth/login", json={"identifier": "admin", "password": "emet"})
    assert login.status_code == 200
    response = client.get("/api/audit/logs")
    assert response.status_code == 200
