"""Retrieval grounding for AI scan analysis.

Builds grounding context from the actual findings plus any related knowledge
stored in the CVE knowledge table (via services.rag_service.keyword_retrieve).
There is no synthetic "hallucination rate" here — we report what was retrieved
and let the caller ground the model on it.
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy.orm import Session

from normalizer.unified_schema import UnifiedFinding
from services.rag_service import keyword_retrieve


def build_context(findings: List[UnifiedFinding], retrieved: Optional[list[dict]] = None) -> str:
    lines = [f"SCAN FINDINGS ({len(findings)}):"]
    for item in findings[:10]:
        lines.append(
            f"- {item.cve_id or 'NO-CVE'} | sev={getattr(item.severity, 'value', item.severity)} "
            f"| cvss={item.cvss_score} | {item.title} | src={item.scanner_source}"
        )
    if retrieved:
        lines.append("")
        lines.append(f"RELATED KNOWLEDGE ({len(retrieved)}):")
        for doc in retrieved:
            lines.append(f"- [{doc.get('source')}] {doc.get('cve_id') or 'NO-CVE'} :: {doc.get('summary')}")
    return "\n".join(lines)


async def run_rag_pipeline(
    findings: List[UnifiedFinding], session: Optional[Session] = None
) -> dict:
    retrieved: list[dict] = []
    if session is not None:
        # Retrieve knowledge for the CVEs actually present in this scan.
        seen: set[str] = set()
        for finding in findings:
            key = finding.cve_id or finding.title
            if not key or key in seen:
                continue
            seen.add(key)
            retrieved.extend(keyword_retrieve(session, key, limit=2))
            if len(retrieved) >= 10:
                break
        retrieved = retrieved[:10]

    return {
        "context": build_context(findings, retrieved),
        "retrieved_docs": retrieved,
    }
