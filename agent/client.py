import os
import time
import uuid
import socket
import platform
import requests
import json

AGENT_ID = str(uuid.uuid4())
SERVER_URL = os.getenv("EMET_SERVER_URL", "http://localhost:8000/api/v1/agents")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))

def get_machine_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
    }

def get_ip_address():
    try:
        # Create a dummy socket to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def register():
    print(f"Registering agent {AGENT_ID} with {SERVER_URL}...")
    payload = {
        "id": AGENT_ID,
        "name": f"Agent-{socket.gethostname()}",
        "machine_info": get_machine_info(),
        "ip_address": get_ip_address(),
        "version": "1.0.0"
    }
    try:
        response = requests.post(f"{SERVER_URL}/register", json=payload)
        response.raise_for_status()
        print("Successfully registered.")
        return True
    except Exception as e:
        print(f"Failed to register agent: {e}")
        if hasattr(e, "response") and e.response is not None:
            print(f"Response: {e.response.text}")
        return False

def heartbeat():
    try:
        response = requests.post(f"{SERVER_URL}/{AGENT_ID}/heartbeat")
        response.raise_for_status()
        print(f"Heartbeat sent for {AGENT_ID}")
        return True
    except Exception as e:
        print(f"Failed to send heartbeat: {e}")
        return False

def fetch_tasks():
    try:
        response = requests.get(f"{SERVER_URL}/{AGENT_ID}/tasks")
        response.raise_for_status()
        data = response.json()
        tasks = data.get("tasks", [])
        if tasks:
            print(f"Received tasks: {tasks}")
        else:
            print("No tasks received.")
        return tasks
    except Exception as e:
        print(f"Failed to fetch tasks: {e}")
        return []

def main():
    registered = False
    while not registered:
        registered = register()
        if not registered:
            print(f"Retrying registration in {HEARTBEAT_INTERVAL} seconds...")
            time.sleep(HEARTBEAT_INTERVAL)
            
    while True:
        heartbeat()
        fetch_tasks()
        time.sleep(HEARTBEAT_INTERVAL)

if __name__ == "__main__":
    main()
