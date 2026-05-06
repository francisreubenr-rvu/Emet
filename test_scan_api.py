import requests
import time

res = requests.post("http://localhost:8000/api/scan/run", json={
    "target": "https://example.com",
    "scanners": ["nmap", "rustscan", "nuclei", "openvas", "nessus", "trivy", "semgrep", "gitleaks", "zap"],
    "profile": "standard"
})
print("Scan started:", res.json())
scan_id = res.json()["scan_id"]

for i in range(20):
    time.sleep(3)
    status_res = requests.get(f"http://localhost:8000/api/scan/{scan_id}")
    status = status_res.json()["status"]
    print(f"Status: {status}")
    if status in ["complete", "failed"]:
        break
