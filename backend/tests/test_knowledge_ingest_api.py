from db.database import SessionLocal
from db.models import CveKnowledgeModel
from pathlib import Path
import json


def test_ingest_nvd_updates_knowledge_and_dataset_status(auth_client):
    payload = {
        "source": "nvd",
        "payload": {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0001",
                        "containers": {
                            "cna": {
                                "descriptions": [
                                    {"lang": "en", "value": "Synthetic NVD test record"}
                                ]
                            }
                        },
                    }
                }
            ]
        },
    }

    response = auth_client.post("/api/rag/ingest", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "nvd"
    assert body["inserted"] >= 1

    status_response = auth_client.get("/api/settings/dataset-status")
    assert status_response.status_code == 200
    rows = status_response.json()
    nvd_row = next(item for item in rows if item["name"] == "NVD CVE Feed")
    assert nvd_row["status"] == "LOADED"
    assert int(nvd_row["size"]) >= 1


def test_ingest_osv_and_exploitdb_insert_records(auth_client):
    osv_payload = {
        "source": "osv",
        "payload": {
            "vulns": [
                {
                    "id": "OSV-TEST-1",
                    "aliases": ["CVE-2099-0002"],
                    "summary": "Synthetic OSV summary",
                }
            ]
        },
    }
    exp_payload = {
        "source": "exploitdb",
        "payload": {
            "exploits": [
                {
                    "cve": "CVE-2099-0003",
                    "title": "Synthetic exploit title",
                    "description": "Synthetic exploit description",
                }
            ]
        },
    }

    osv_res = auth_client.post("/api/rag/ingest", json=osv_payload)
    exp_res = auth_client.post("/api/rag/ingest", json=exp_payload)
    assert osv_res.status_code == 200
    assert exp_res.status_code == 200

    db = SessionLocal()
    try:
        osv = db.query(CveKnowledgeModel).filter(CveKnowledgeModel.cve_id == "CVE-2099-0002").first()
        exp = db.query(CveKnowledgeModel).filter(CveKnowledgeModel.cve_id == "CVE-2099-0003").first()
        assert osv is not None
        assert exp is not None
        assert osv.source == "osv"
        assert exp.source == "exploitdb"
    finally:
        db.close()


def test_ingest_rejects_unsupported_source(auth_client):
    response = auth_client.post("/api/rag/ingest", json={"source": "unknown", "payload": {}})
    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported source"


def test_dataset_history_contains_ingest_events(auth_client):
    payload = {
        "source": "nvd",
        "payload": {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-1000",
                        "containers": {"cna": {"descriptions": [{"value": "history test"}]}},
                    }
                }
            ]
        },
    }
    ingest = auth_client.post("/api/rag/ingest", json=payload)
    assert ingest.status_code == 200

    history = auth_client.get("/api/settings/dataset-history")
    assert history.status_code == 200
    rows = history.json()
    assert rows
    assert any(item["event_type"] in {"rag.ingest.completed", "rag.ingest.scheduled"} for item in rows)


def test_ingest_from_file_endpoint(auth_client):
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-2001",
                    "containers": {"cna": {"descriptions": [{"value": "file ingest"}]}},
                }
            }
        ]
    }
    path = Path("/tmp/emet-ingest-file.json")
    path.write_text(json.dumps(payload), encoding="utf-8")

    response = auth_client.post(
        "/api/rag/ingest/file",
        json={"source": "nvd", "file_path": str(path)},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "nvd"
    assert body["status"] == "ok"
