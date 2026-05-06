def test_report_export_json_and_csv(auth_client):
    create = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap"], "profile": "quick"},
    )
    assert create.status_code == 200
    scan_id = create.json()["scan_id"]

    json_response = auth_client.get(f"/api/reports/{scan_id}/export/json")
    assert json_response.status_code == 200
    assert json_response.headers.get("content-type", "").startswith("application/json")

    csv_response = auth_client.get(f"/api/reports/{scan_id}/export/csv")
    assert csv_response.status_code == 200
    assert csv_response.headers.get("content-type", "").startswith("text/csv")
