from __future__ import annotations

from sqlalchemy.orm import Session

from db.models import CveKnowledgeModel, VulnerabilityModel


def keyword_retrieve(session: Session, query: str, limit: int = 5) -> list[dict]:
    text = query.strip().lower()
    if not text:
        return []

    docs: list[dict] = []

    # Knowledge table first.
    rows = (
        session.query(CveKnowledgeModel)
        .filter(
            (CveKnowledgeModel.cve_id.ilike(f"%{text}%"))
            | (CveKnowledgeModel.summary.ilike(f"%{text}%"))
            | (CveKnowledgeModel.vector_text.ilike(f"%{text}%"))
        )
        .order_by(CveKnowledgeModel.created_at.desc())
        .limit(limit)
        .all()
    )
    for row in rows:
        docs.append(
            {
                "source": row.source,
                "cve_id": row.cve_id,
                "summary": row.summary,
                "metadata": row.metadata_json,
            }
        )

    if len(docs) >= limit:
        return docs[:limit]

    vulns = (
        session.query(VulnerabilityModel)
        .filter(
            (VulnerabilityModel.cve_id.ilike(f"%{text}%"))
            | (VulnerabilityModel.title.ilike(f"%{text}%"))
            | (VulnerabilityModel.description.ilike(f"%{text}%"))
        )
        .order_by(VulnerabilityModel.detected_at.desc())
        .limit(limit)
        .all()
    )
    for row in vulns:
        docs.append(
            {
                "source": "scan-findings",
                "cve_id": row.cve_id,
                "summary": row.title,
                "metadata": {
                    "severity": row.severity,
                    "target": row.target,
                    "scan_id": row.scan_id,
                    "verification_status": row.verification_status,
                },
            }
        )

    return docs[:limit]


def build_grounded_response(query: str, docs: list[dict]) -> tuple[str, list[dict]]:
    if not docs:
        return (
            "No grounded evidence found for this query in EMET knowledge or recent findings. "
            "Run a scan or ingest CVE knowledge, then retry.",
            [{"source": "fallback-template", "confidence": "low"}],
        )

    top = docs[:3]
    lines = [
        "Grounded response based on stored evidence:",
    ]
    for item in top:
        lines.append(f"- {item.get('cve_id') or 'NO-CVE'} :: {item.get('summary')}")

    lines.append("Prioritize verified/high-severity findings and remediate internet-exposed components first.")
    citations = [{"source": item.get("source", "unknown"), "cve_id": item.get("cve_id")} for item in top]
    return " ".join(lines), citations
