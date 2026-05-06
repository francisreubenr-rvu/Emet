from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet


def _key_from_secret(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    secret = os.getenv("DATA_ENCRYPTION_KEY") or os.getenv("SECRET_KEY", "dev-only-change-me")
    return Fernet(_key_from_secret(secret))


def encrypt_json(payload: dict | list) -> str:
    fernet = get_fernet()
    raw = json.dumps(payload).encode("utf-8")
    token = fernet.encrypt(raw)
    return token.decode("utf-8")


def decrypt_json(cipher_text: str) -> dict | list:
    if not cipher_text:
        return {}
    fernet = get_fernet()
    raw = fernet.decrypt(cipher_text.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))
