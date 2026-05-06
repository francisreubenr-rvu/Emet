def test_operations_queue_endpoint(auth_client):
    response = auth_client.get("/api/operations/queue")
    assert response.status_code == 200
    body = response.json()
    assert "queues" in body
    assert "queue_oldest_age_seconds" in body
    assert "total_depth" in body
    assert "dead_letter_depth" in body


def test_operations_cspm_connectors_endpoint(auth_client):
    response = auth_client.get("/api/operations/cspm/connectors")
    assert response.status_code == 200
    body = response.json()
    providers = {item["provider"] for item in body}
    assert {"aws", "gcp", "azure"}.issubset(providers)


def test_operations_worker_metrics_endpoint(auth_client):
    response = auth_client.get("/api/operations/metrics/workers")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_dead_letter_replay_requires_admin(auth_client):
    response = auth_client.post("/api/operations/queue/dead-letter/replay")
    assert response.status_code == 403


def test_dead_letter_replay_empty_for_admin(client):
    login = client.post("/api/auth/login", json={"identifier": "admin", "password": "emet"})
    assert login.status_code == 200
    response = client.post("/api/operations/queue/dead-letter/replay")
    assert response.status_code == 404
