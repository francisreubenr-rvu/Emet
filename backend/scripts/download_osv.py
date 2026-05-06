from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import httpx


DEFAULT_OSV_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_OSV_PAYLOAD = {"queries": [{"package": {"name": "openssl", "ecosystem": "OSS-Fuzz"}}]}


async def fetch_osv_payload(url: str | None = None, body: dict | None = None) -> dict:
    request_body = body or DEFAULT_OSV_PAYLOAD
    async with httpx.AsyncClient(timeout=35.0) as client:
        response = await client.post(url or DEFAULT_OSV_URL, json=request_body)
        response.raise_for_status()
        return response.json()


def save_payload(payload: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"osv-{stamp}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def main() -> None:
    import asyncio

    parser = argparse.ArgumentParser(description="Download OSV payload to local datasets")
    parser.add_argument("--url", default=DEFAULT_OSV_URL, help="OSV endpoint URL")
    parser.add_argument("--output-dir", default="/app/datasets/osv", help="Directory to store downloaded JSON")
    args = parser.parse_args()

    payload = asyncio.run(fetch_osv_payload(args.url))
    path = save_payload(payload, Path(args.output_dir))
    print(f"[EMET] Downloaded OSV payload to {path}")


if __name__ == "__main__":
    main()
