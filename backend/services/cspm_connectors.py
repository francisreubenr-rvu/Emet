from __future__ import annotations

import os


def list_cspm_connectors() -> list[dict]:
    return [
        {
            "provider": "aws",
            "enabled": os.getenv("CSPM_AWS_ENABLED", "false").lower() == "true",
            "status": "stub",
            "description": "AWS posture connector scaffold",
        },
        {
            "provider": "gcp",
            "enabled": os.getenv("CSPM_GCP_ENABLED", "false").lower() == "true",
            "status": "stub",
            "description": "GCP posture connector scaffold",
        },
        {
            "provider": "azure",
            "enabled": os.getenv("CSPM_AZURE_ENABLED", "false").lower() == "true",
            "status": "stub",
            "description": "Azure posture connector scaffold",
        },
    ]
