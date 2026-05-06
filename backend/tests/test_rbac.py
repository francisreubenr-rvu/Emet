import pytest
from fastapi.testclient import TestClient
from jose import jwt

from main import app
from services.auth_guard import SECRET_KEY, ALGORITHM
from db.database import Base, engine

# Ensure tables are created for tests
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def create_token(role="tenant_viewer", tenant_id=None, scope="admin"):
    payload = {"type": "access", "role": role, "scope": scope}
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def test_create_tenant_as_global_admin():
    token = create_token(role="global_admin")
    client.cookies.set("emet_access", token)
    response = client.post("/api/tenants/", json={"name": "TestTenant1"})
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "TestTenant1"
    assert "id" in data

def test_create_tenant_as_tenant_admin_fails():
    token = create_token(role="tenant_admin", tenant_id=1)
    client.cookies.set("emet_access", token)
    response = client.post("/api/tenants/", json={"name": "TestTenant2"})
    assert response.status_code == 403

def test_list_tenants_as_global_admin():
    token = create_token(role="global_admin")
    client.cookies.set("emet_access", token)
    response = client.get("/api/tenants/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(t["name"] == "TestTenant1" for t in data)

def test_list_tenants_as_tenant_viewer_fails():
    token = create_token(role="tenant_viewer", tenant_id=1)
    client.cookies.set("emet_access", token)
    response = client.get("/api/tenants/")
    assert response.status_code == 403
