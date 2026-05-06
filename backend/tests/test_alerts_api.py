def test_dispatch_alert_and_list(auth_client):
    send = auth_client.post(
        "/api/alerts/dispatch",
        json={"event_type": "critical.finding", "severity": "HIGH", "payload": {"scan_id": "scan-x"}},
    )
    assert send.status_code == 200
    assert "alert_id" in send.json()

    listing = auth_client.get("/api/alerts")
    assert listing.status_code == 200
    rows = listing.json()
    assert rows
    assert rows[0]["event_type"] in {"critical.finding", "scan.completed.top_finding"}


def test_issue_templates(auth_client):
    gh = auth_client.post("/api/alerts/integrations/github/issue-template")
    jira = auth_client.post("/api/alerts/integrations/jira/issue-template")
    assert gh.status_code == 200
    assert jira.status_code == 200
    assert "title" in gh.json()
    assert "fields" in jira.json()


def test_issue_create_endpoints_gracefully_handle_missing_integrations(auth_client):
    gh = auth_client.post(
        "/api/alerts/integrations/github/issue",
        json={"title": "test", "body": "test", "labels": ["security"]},
    )
    jira = auth_client.post(
        "/api/alerts/integrations/jira/issue",
        json={"title": "test", "body": "test", "labels": []},
    )
    assert gh.status_code == 200
    assert jira.status_code == 200
    assert gh.json()["ok"] is False
    assert jira.json()["ok"] is False
