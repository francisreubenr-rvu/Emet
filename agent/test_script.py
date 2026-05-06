import sys
import os

# Add the backend directory to sys.path so we can import from it
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_agent_endpoints():
    print("Testing agent registration...")
    register_response = client.post("/api/v1/agents/register", json={
        "id": "test-agent-123",
        "name": "Test Agent",
        "machine_info": {"os": "Linux"},
        "ip_address": "127.0.0.1",
        "version": "1.0.0"
    })
    print(register_response.status_code)
    print(register_response.json())
    assert register_response.status_code == 200

    print("Testing agent heartbeat...")
    heartbeat_response = client.post("/api/v1/agents/test-agent-123/heartbeat")
    print(heartbeat_response.status_code)
    print(heartbeat_response.json())
    assert heartbeat_response.status_code == 200

    print("Testing fetch tasks...")
    tasks_response = client.get("/api/v1/agents/test-agent-123/tasks")
    print(tasks_response.status_code)
    print(tasks_response.json())
    assert tasks_response.status_code == 200

    print("All tests passed.")

if __name__ == "__main__":
    test_agent_endpoints()
