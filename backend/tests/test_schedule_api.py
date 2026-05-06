def test_create_daily_schedule(auth_client):
    response = auth_client.post(
        "/api/schedules",
        json={
            "name": "Daily perimeter",
            "target": "example.com",
            "profile": "quick",
            "scanners": ["nmap"],
            "recurrence": "daily",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "created"
    assert body["id"] > 0


def test_list_schedules(auth_client):
    response = auth_client.get("/api/schedules")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_invalid_cron_schedule_rejected(auth_client):
    response = auth_client.post(
        "/api/schedules",
        json={
            "name": "Bad cron",
            "target": "example.com",
            "profile": "quick",
            "scanners": ["nmap"],
            "recurrence": "cron",
            "cron_expr": "bad cron",
        },
    )
    assert response.status_code == 400


def test_update_and_delete_schedule(auth_client):
    created = auth_client.post(
        "/api/schedules",
        json={
            "name": "Temp schedule",
            "target": "example.com",
            "profile": "quick",
            "scanners": ["nmap"],
            "recurrence": "daily",
        },
    )
    schedule_id = created.json()["id"]

    updated = auth_client.put(
        f"/api/schedules/{schedule_id}",
        json={
            "name": "Updated schedule",
            "profile": "standard",
            "scanners": ["nmap", "nuclei"],
            "recurrence": "weekly",
            "cron_expr": "",
            "enabled": True,
        },
    )
    assert updated.status_code == 200

    deleted = auth_client.delete(f"/api/schedules/{schedule_id}")
    assert deleted.status_code == 200


def test_run_schedule_now(auth_client):
    created = auth_client.post(
        "/api/schedules",
        json={
            "name": "Run now schedule",
            "target": "example.com",
            "profile": "quick",
            "scanners": ["nmap"],
            "recurrence": "daily",
        },
    )
    schedule_id = created.json()["id"]

    queued = auth_client.post(f"/api/schedules/{schedule_id}/run-now")
    assert queued.status_code == 200
    assert queued.json()["status"] == "queued"


def test_run_schedule_now_missing_schedule_returns_404(auth_client):
    response = auth_client.post("/api/schedules/999999/run-now")
    assert response.status_code == 404
