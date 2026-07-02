"""Download the CISA Known Exploited Vulnerabilities catalog to the local cache.

Usage: python scripts/download_cisa_kev.py
The cached file is what services.intel_feeds reads when the live feed is offline.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.intel_feeds import KEV_CACHE_PATH, kev_catalog  # noqa: E402


async def main() -> None:
    ok = await kev_catalog.refresh(force=True)
    if ok:
        print(f"[EMET] CISA KEV catalog cached to {KEV_CACHE_PATH} ({len(kev_catalog._cves)} CVEs)")
    else:
        print("[EMET] Failed to download CISA KEV feed (network unavailable).", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
