from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import httpx


DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000"


async def fetch_nvd_payload(url: str | None = None, api_key: str | None = None) -> dict:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    async with httpx.AsyncClient(timeout=40.0, headers=headers) as client:
        response = await client.get(url or DEFAULT_NVD_URL)
        response.raise_for_status()
        return response.json()


def save_payload(payload: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"nvd-{stamp}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def main() -> None:
    import asyncio

    parser = argparse.ArgumentParser(description="Download NVD CVE payload to local datasets")
    parser.add_argument("--url", default=DEFAULT_NVD_URL, help="NVD endpoint URL")
    parser.add_argument("--api-key", default="", help="Optional NVD API key")
    parser.add_argument("--output-dir", default="/app/datasets/nvd", help="Directory to store downloaded JSON")
    args = parser.parse_args()

    payload = asyncio.run(fetch_nvd_payload(args.url, args.api_key or None))
    path = save_payload(payload, Path(args.output_dir))
    print(f"[EMET] Downloaded NVD payload to {path}")


if __name__ == "__main__":
    main()
