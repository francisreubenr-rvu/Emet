from __future__ import annotations

import os

from fastapi import HTTPException, Request
from jose import JWTError, jwt


SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGORITHM = "HS256"


def _token_scopes(payload: dict) -> set[str]:
    raw_scope = payload.get("scope", "")
    if isinstance(raw_scope, str):
        return {item for item in raw_scope.split() if item}
    if isinstance(raw_scope, list):
        return {str(item) for item in raw_scope if str(item)}
    return set()


def verify_access_token(request: Request, required_scope: str | None = None) -> dict:
    token = request.cookies.get("emet_access")
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid access token") from exc
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    if required_scope and required_scope not in _token_scopes(payload):
        raise HTTPException(status_code=403, detail="Insufficient scope")
    return payload

def verify_global_admin(request: Request) -> dict:
    payload = verify_access_token(request)
    if str(payload.get("role", "")).lower() != "global_admin":
        raise HTTPException(status_code=403, detail="Global admin role required")
    return payload

def verify_tenant_access(request: Request, tenant_id: int | None = None) -> dict:
    payload = verify_access_token(request)
    role = str(payload.get("role", "")).lower()
    
    if role == "global_admin":
        return payload
        
    user_tenant_id = payload.get("tenant_id")
    if tenant_id is not None and user_tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")
    return payload

def verify_tenant_admin(request: Request, tenant_id: int | None = None) -> dict:
    payload = verify_tenant_access(request, tenant_id)
    role = str(payload.get("role", "")).lower()
    if role not in ["global_admin", "tenant_admin"]:
        raise HTTPException(status_code=403, detail="Tenant admin role required")
    return payload

def verify_admin(request: Request) -> dict:
    # Kept for backward compatibility, mapped to global_admin or tenant_admin
    payload = verify_access_token(request)
    role = str(payload.get("role", "")).lower()
    if role not in ["global_admin", "tenant_admin", "admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload


def is_read_only(payload: dict) -> bool:
    return "write" not in _token_scopes(payload)
