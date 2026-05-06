from __future__ import annotations

import json
from pathlib import Path

import httpx
from datetime import datetime

from sqlalchemy.orm import Session

from db.models import CveKnowledgeModel


SUPPORTED_INGEST_SOURCES = {"nvd", "osv", "exploitdb", "exploit-db"}


def canonical_source(source: str) -> str:
    normalized = source.strip().lower()
    if normalized == "exploit-db":
        return "exploitdb"
    return normalized


def load_json_from_file(path_value: str, *, allowed_root: str | None = None) -> tuple[dict, str]:
    candidate = Path(path_value).expanduser().resolve()
    if allowed_root:
        root = Path(allowed_root).expanduser().resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("File path is outside configured ingest root") from exc
    if not candidate.exists() or not candidate.is_file():
        raise ValueError("Input file not found")
    payload = json.loads(candidate.read_text(encoding="utf-8"))
    return payload, str(candidate)


async def load_json_from_url(url: str, *, timeout_seconds: float = 25.0) -> dict:
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("URL must start with http:// or https://")
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


def _upsert_knowledge(
    db: Session,
    *,
    cve_id: str,
    source: str,
    summary: str,
    vector_text: str,
    metadata_json: dict,
) -> bool:
    existing = db.query(CveKnowledgeModel).filter(CveKnowledgeModel.cve_id == cve_id).first()
    now = datetime.utcnow()
    if existing:
        existing.source = source
        existing.summary = summary
        existing.vector_text = vector_text
        existing.metadata_json = metadata_json
        return False
    db.add(
        CveKnowledgeModel(
            cve_id=cve_id,
            source=source,
            summary=summary,
            vector_text=vector_text,
            embedding=[],
            metadata_json=metadata_json,
            created_at=now,
        )
    )
    return True


def ingest_nvd_payload(db: Session, payload: dict, origin: str = "api") -> dict:
    vulnerabilities = payload.get("vulnerabilities") or []
    inserted = 0
    updated = 0

    for item in vulnerabilities:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue

        descriptions = ((cve.get("containers") or {}).get("cna") or {}).get("descriptions") or []
        summary = ""
        for desc in descriptions:
            value = (desc or {}).get("value")
            if value:
                summary = str(value)
                break

        was_insert = _upsert_knowledge(
            db,
            cve_id=cve_id,
            source="nvd",
            summary=summary,
            vector_text=summary,
            metadata_json={"origin": origin, "feed": "nvd-cve-5"},
        )
        inserted += 1 if was_insert else 0
        updated += 0 if was_insert else 1

    db.commit()
    return {"source": "nvd", "inserted": inserted, "updated": updated}


def ingest_osv_payload(db: Session, payload: dict, origin: str = "api") -> dict:
    items = payload.get("vulns") or []
    if not items:
        results = payload.get("results") or []
        for result in results:
            vulns = (result or {}).get("vulns") or []
            if vulns:
                items.extend(vulns)
    inserted = 0
    updated = 0

    for item in items:
        osv_id = str(item.get("id") or "").strip()
        cve_id = osv_id if osv_id.startswith("CVE-") else ""
        if not cve_id:
            aliases = item.get("aliases") or []
            cve_alias = next((str(alias) for alias in aliases if str(alias).startswith("CVE-")), "")
            cve_id = cve_alias.strip()
        if not cve_id:
            continue

        summary = str(item.get("summary") or item.get("details") or "")
        vector_text = " ".join(part for part in [summary, str(item.get("details") or "")] if part)

        was_insert = _upsert_knowledge(
            db,
            cve_id=cve_id,
            source="osv",
            summary=summary,
            vector_text=vector_text or summary,
            metadata_json={"origin": origin, "feed": "osv"},
        )
        inserted += 1 if was_insert else 0
        updated += 0 if was_insert else 1

    db.commit()
    return {"source": "osv", "inserted": inserted, "updated": updated}


def ingest_exploitdb_payload(db: Session, payload: dict, origin: str = "api") -> dict:
    items = payload.get("exploits") or payload.get("items") or []
    inserted = 0
    updated = 0

    for item in items:
        cve_id = str(item.get("cve") or "").strip()
        if not cve_id:
            continue
        title = str(item.get("title") or "")
        description = str(item.get("description") or "")
        summary = title or description
        vector_text = " ".join(part for part in [title, description] if part)

        was_insert = _upsert_knowledge(
            db,
            cve_id=cve_id,
            source="exploitdb",
            summary=summary,
            vector_text=vector_text or summary,
            metadata_json={"origin": origin, "feed": "exploitdb"},
        )
        inserted += 1 if was_insert else 0
        updated += 0 if was_insert else 1

    db.commit()
    return {"source": "exploitdb", "inserted": inserted, "updated": updated}


def ingest_payload_by_source(db: Session, source: str, payload: dict, origin: str = "api") -> dict:
    normalized = canonical_source(source)
    if normalized == "nvd":
        return ingest_nvd_payload(db, payload, origin=origin)
    if normalized == "osv":
        return ingest_osv_payload(db, payload, origin=origin)
    if normalized == "exploitdb":
        return ingest_exploitdb_payload(db, payload, origin=origin)
    raise ValueError("Unsupported source")
