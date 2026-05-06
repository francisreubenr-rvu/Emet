def test_scan_queue_and_event_stream_contract(auth_client, monkeypatch):
    async def _fake_events(_scan_id: str):
        yield {"phase": "QUEUED", "message": "queued"}

    import routers.scan as scan_router

    monkeypatch.setattr(scan_router, "subscribe_progress", _fake_events)

    create = auth_client.post(
        "/api/scan/run",
        json={"target": "example.com", "scanners": ["nmap", "rustscan", "nuclei"], "profile": "quick"},
    )
    assert create.status_code == 200
    scan_id = create.json()["scan_id"]

    # Verify queued object exists immediately.
    scan = auth_client.get(f"/api/scan/{scan_id}")
    assert scan.status_code == 200
    payload = scan.json()
    assert payload["status"] in {"queued", "running", "complete", "failed"}

    # Event stream endpoint should be reachable and SSE-typed.
    events = auth_client.get(f"/api/scan/{scan_id}/events")
    assert events.status_code == 200
    assert events.headers.get("content-type", "").startswith("text/event-stream")
