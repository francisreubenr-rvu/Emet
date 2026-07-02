"""Real threat-intelligence feed clients.

Replaces the previous fabricated enrichment (which returned EPSS/KEV values by
string-matching "2021" in the CVE id). Every value returned here is sourced from
a public feed:

- EPSS:      FIRST.org EPSS API   (https://api.first.org/data/v1/epss)
- CISA KEV:  CISA KEV JSON feed   (known_exploited_vulnerabilities.json)
- NVD:       NVD CVE API 2.0      (services.nvd.nist.gov)

All feeds are public and require no credentials (an optional NVD API key raises
rate limits). When a feed is unreachable we return None / empty and the caller
leaves the field at its default — we never invent a value.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Optional

import httpx

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DATASETS_DIR = Path(os.getenv("EMET_DATASETS_DIR", Path(__file__).resolve().parent.parent / "datasets"))
KEV_CACHE_PATH = DATASETS_DIR / "cisa_kev.json"
KEV_TTL_SECONDS = 24 * 3600
_HTTP_TIMEOUT = float(os.getenv("EMET_FEED_TIMEOUT", "15"))


def is_valid_cve(cve_id: Optional[str]) -> bool:
    return bool(cve_id and _CVE_RE.match(cve_id.strip()))


# --------------------------------------------------------------------------- EPSS

async def fetch_epss_score(cve_id: str) -> Optional[float]:
    """Return the real EPSS probability (0..1) for a CVE, or None if unavailable."""
    if not is_valid_cve(cve_id):
        return None
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": cve_id.upper()})
            resp.raise_for_status()
            data = resp.json().get("data") or []
    except (httpx.HTTPError, ValueError):
        return None
    if not data:
        return None
    try:
        score = float(data[0].get("epss"))
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, score))


# ----------------------------------------------------------------------- CISA KEV

class KevCatalog:
    """In-process cache of the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self) -> None:
        self._cves: set[str] = set()
        self._loaded_at: float = 0.0

    def _load_from_disk(self) -> bool:
        if not KEV_CACHE_PATH.exists():
            return False
        try:
            payload = json.loads(KEV_CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        self._ingest(payload)
        self._loaded_at = KEV_CACHE_PATH.stat().st_mtime
        return bool(self._cves)

    def _ingest(self, payload: dict) -> None:
        self._cves = {
            str(item.get("cveID", "")).upper()
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        }

    async def refresh(self, force: bool = False) -> bool:
        """Ensure the catalog is loaded and reasonably fresh. Returns True if usable."""
        fresh = self._cves and (time.time() - self._loaded_at) < KEV_TTL_SECONDS
        if fresh and not force:
            return True
        if not force and not self._cves and self._load_from_disk():
            if (time.time() - self._loaded_at) < KEV_TTL_SECONDS:
                return True
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(KEV_FEED_URL)
                resp.raise_for_status()
                payload = resp.json()
        except (httpx.HTTPError, ValueError):
            # Network failed — fall back to any cached copy we managed to load.
            return bool(self._cves)
        self._ingest(payload)
        self._loaded_at = time.time()
        try:
            DATASETS_DIR.mkdir(parents=True, exist_ok=True)
            KEV_CACHE_PATH.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass
        return bool(self._cves)

    async def contains(self, cve_id: str) -> Optional[bool]:
        """True/False if the catalog is available, None if it could not be loaded."""
        if not is_valid_cve(cve_id):
            return False
        available = await self.refresh()
        if not available:
            return None
        return cve_id.upper() in self._cves


kev_catalog = KevCatalog()


async def check_cisa_kev(cve_id: str) -> Optional[bool]:
    return await kev_catalog.contains(cve_id)


# ----------------------------------------------------------------------------- NVD

async def fetch_nvd_metrics(cve_id: str) -> Optional[dict]:
    """Fetch real CVSS base score + references for a CVE from NVD. None on failure."""
    if not is_valid_cve(cve_id):
        return None
    headers = {}
    api_key = (os.getenv("NVD_API_KEY") or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=headers) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id.upper()})
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities") or []
    except (httpx.HTTPError, ValueError):
        return None
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            break
    references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]
    return {
        "cve_id": cve_id.upper(),
        "cvss_score": float(score) if score is not None else None,
        "references": references[:10],
    }
