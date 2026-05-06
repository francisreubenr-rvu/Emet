from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from jose import JWTError, jwt
from pydantic import BaseModel

from services.audit import write_audit_event
from services.rate_limit import auth_rate_limiter
from services.redis_bus import get_redis_client

router = APIRouter(prefix="/api/auth", tags=["auth"])

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60
REFRESH_TOKEN_DAYS = 7
REFRESH_PREFIX = "refresh-token:"


class LoginRequest(BaseModel):
    identifier: str
    password: str


def _create_access_token(subject: str) -> str:
    scope = "read"
    role = "viewer"
    if subject != "guest":
        scope = "read write"
        role = "analyst"
    if subject == "admin":
        scope = "read write admin"
        role = "admin"
    expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode(
        {
            "sub": subject,
            "scope": scope,
            "role": role,
            "exp": int(expires_at.timestamp()),
            "type": "access",
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _create_refresh_token(subject: str, token_id: str) -> str:
    expires_at = datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS)
    return jwt.encode(
        {
            "sub": subject,
            "jti": token_id,
            "exp": int(expires_at.timestamp()),
            "type": "refresh",
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie("emet_access", access_token, httponly=True, secure=secure, samesite="lax", max_age=ACCESS_TOKEN_MINUTES * 60)
    response.set_cookie("emet_refresh", refresh_token, httponly=True, secure=secure, samesite="lax", max_age=REFRESH_TOKEN_DAYS * 86400)


async def _store_refresh_token(token_id: str, subject: str) -> None:
    redis = get_redis_client()
    ttl = REFRESH_TOKEN_DAYS * 86400
    await redis.set(
        f"{REFRESH_PREFIX}{token_id}",
        subject,
        ex=ttl,
    )


async def _revoke_refresh_token(token_id: str) -> None:
    redis = get_redis_client()
    await redis.delete(f"{REFRESH_PREFIX}{token_id}")


async def _is_refresh_token_active(token_id: str) -> bool:
    redis = get_redis_client()
    return await redis.exists(f"{REFRESH_PREFIX}{token_id}") == 1


@router.post("/login")
async def login(payload: LoginRequest, response: Response):
    allowed, retry_after = auth_rate_limiter.allow(payload.identifier or "anonymous")
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many login attempts. Retry in {retry_after}s")

    if payload.identifier not in {"admin", "guest", "analyst@emet.local"} or payload.password != "emet":
        write_audit_event(event_type="auth.login.failed", actor=payload.identifier, details={"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    refresh_id = uuid4().hex
    access_token = _create_access_token(payload.identifier)
    refresh_token = _create_refresh_token(payload.identifier, refresh_id)
    await _store_refresh_token(refresh_id, payload.identifier)
    _set_auth_cookies(response, access_token, refresh_token)
    write_audit_event(event_type="auth.login.success", actor=payload.identifier, details={"refresh_id": refresh_id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
    }


@router.post("/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("emet_refresh")
    if not token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    refresh_id = payload.get("jti")
    subject = payload.get("sub")
    if not refresh_id or not subject:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    if not await _is_refresh_token_active(refresh_id):
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    await _revoke_refresh_token(refresh_id)
    new_refresh_id = uuid4().hex
    access_token = _create_access_token(subject)
    refresh_token = _create_refresh_token(subject, new_refresh_id)
    await _store_refresh_token(new_refresh_id, subject)
    _set_auth_cookies(response, access_token, refresh_token)
    write_audit_event(event_type="auth.refresh.success", actor=subject, details={"old_refresh_id": refresh_id, "new_refresh_id": new_refresh_id})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
    }


@router.post("/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("emet_refresh")
    actor = "unknown"
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            refresh_id = payload.get("jti")
            actor = payload.get("sub", "unknown")
            if refresh_id:
                await _revoke_refresh_token(refresh_id)
        except JWTError:
            pass

    response.delete_cookie("emet_access")
    response.delete_cookie("emet_refresh")
    write_audit_event(event_type="auth.logout", actor=actor)
    return {"status": "logged_out"}
