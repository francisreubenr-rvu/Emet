from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime

from db.database import SessionLocal
from db.models import AuditTrailModel


def _sign_payload(payload: dict) -> str:
    secret = os.getenv("AUDIT_SIGNING_KEY") or os.getenv("SECRET_KEY", "dev-only-change-me")
    message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def write_audit_event(*, event_type: str, actor: str, scan_id: str = "", details: dict | None = None) -> None:
    details_payload = details or {}
    payload = {
        "created_at": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "actor": actor,
        "scan_id": scan_id,
        "details": details_payload,
    }
    signature = _sign_payload(payload)

    db = SessionLocal()
    try:
        db.add(
            AuditTrailModel(
                event_type=event_type,
                actor=actor,
                scan_id=scan_id,
                details=details_payload,
                signature=signature,
            )
        )
        db.commit()
    finally:
        db.close()
