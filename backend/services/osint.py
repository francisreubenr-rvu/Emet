from __future__ import annotations

import asyncio
import os
from urllib.parse import quote

import httpx


class OsintService:
    def __init__(self) -> None:
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.hibp_api_key = os.getenv("HIBP_API_KEY", "")

    async def fetch(self, target: str) -> dict:
        async with httpx.AsyncClient(timeout=12.0) as client:
            shodan_task = self._fetch_shodan(client, target)
            whois_task = self._fetch_whois(client, target)
            ssl_task = self._fetch_ssl(client, target)
            hibp_task = self._fetch_hibp(client, target)

            shodan, whois, ssl, hibp = await asyncio.gather(
                shodan_task, whois_task, ssl_task, hibp_task, return_exceptions=True
            )

            return {
                "target": target,
                "shodan": self._safe(shodan, default={"open_ports": [], "org": "Unavailable", "hostnames": []}),
                "whois": self._safe(whois, default={"registrar": "Unavailable", "created": "Unknown", "expires": "Unknown"}),
                "ssl": self._safe(ssl, default={"issuer": "Unavailable", "valid_until": "Unknown", "grade": "N/A"}),
                "breaches": self._safe(hibp, default={"count": 0, "recent": []}),
            }

    async def _fetch_shodan(self, client: httpx.AsyncClient, target: str) -> dict:
        if not self.shodan_api_key:
            return {"open_ports": [], "org": "API key missing", "hostnames": []}
        response = await client.get(
            f"https://api.shodan.io/shodan/host/{quote(target)}",
            params={"key": self.shodan_api_key},
        )
        if response.status_code != 200:
            return {"open_ports": [], "org": f"HTTP {response.status_code}", "hostnames": []}
        data = response.json()
        return {
            "open_ports": data.get("ports", [])[:20],
            "org": data.get("org", "Unknown"),
            "hostnames": data.get("hostnames", [])[:10],
        }

    async def _fetch_whois(self, client: httpx.AsyncClient, target: str) -> dict:
        response = await client.get(f"https://rdap.org/domain/{quote(target)}")
        if response.status_code != 200:
            return {"registrar": f"HTTP {response.status_code}", "created": "Unknown", "expires": "Unknown"}
        data = response.json()
        registrar = (data.get("entities") or [{}])[0].get("handle", "Unknown")
        events = data.get("events", [])
        created = next((item.get("eventDate") for item in events if item.get("eventAction") == "registration"), "Unknown")
        expires = next((item.get("eventDate") for item in events if item.get("eventAction") == "expiration"), "Unknown")
        return {"registrar": registrar, "created": created, "expires": expires}

    async def _fetch_ssl(self, client: httpx.AsyncClient, target: str) -> dict:
        response = await client.get(
            "https://api.ssllabs.com/api/v3/analyze",
            params={"host": target, "all": "done", "fromCache": "on", "maxAge": 24},
        )
        if response.status_code != 200:
            return {"issuer": f"HTTP {response.status_code}", "valid_until": "Unknown", "grade": "N/A"}
        data = response.json()
        endpoints = data.get("endpoints", [])
        grade = endpoints[0].get("grade", "N/A") if endpoints else "N/A"
        cert = (endpoints[0].get("details", {}) if endpoints else {}).get("cert", {})
        issuer = cert.get("issuerLabel", "Unknown")
        valid_until = str(cert.get("notAfter", "Unknown"))
        return {"issuer": issuer, "valid_until": valid_until, "grade": grade}

    async def _fetch_hibp(self, client: httpx.AsyncClient, target: str) -> dict:
        if not self.hibp_api_key:
            return {"count": 0, "recent": ["HIBP API key missing"]}
        headers = {
            "hibp-api-key": self.hibp_api_key,
            "user-agent": "emet-platform",
        }
        response = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={quote(target)}",
            headers=headers,
        )
        if response.status_code == 404:
            return {"count": 0, "recent": []}
        if response.status_code != 200:
            return {"count": 0, "recent": [f"HTTP {response.status_code}"]}
        data = response.json()
        names = [item.get("Name", "Unknown") for item in data[:10]]
        return {"count": len(data), "recent": names}

    def _safe(self, value, default):
        if isinstance(value, Exception):
            return default
        return value


osint_service = OsintService()
