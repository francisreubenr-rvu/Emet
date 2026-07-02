"""Cloud Security Posture Management connector status.

Honest reporting only: a connector is reported "connected" solely when real
provider credentials are present in the environment; otherwise "not_configured".
Posture collection itself is not implemented, and this module does not fabricate
posture findings. Enable a provider by supplying its standard credentials, e.g.
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for AWS.
"""

from __future__ import annotations

import os


_PROVIDERS = [
    ("aws", ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"), "AWS security posture connector"),
    ("gcp", ("GOOGLE_APPLICATION_CREDENTIALS",), "GCP security posture connector"),
    ("azure", ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"), "Azure security posture connector"),
]


def _has_credentials(env_keys: tuple[str, ...]) -> bool:
    return all((os.getenv(key) or "").strip() for key in env_keys)


def list_cspm_connectors() -> list[dict]:
    connectors = []
    for provider, env_keys, description in _PROVIDERS:
        configured = _has_credentials(env_keys)
        connectors.append(
            {
                "provider": provider,
                "enabled": configured,
                "status": "connected" if configured else "not_configured",
                "posture_collection": "not_implemented",
                "description": description,
            }
        )
    return connectors
