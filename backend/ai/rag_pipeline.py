from __future__ import annotations

from typing import List

from normalizer.unified_schema import UnifiedFinding


VECTOR_STORE_DATASETS = [
    "NVD CVE JSON feed (full history)",
    "Exploit-DB CSV export",
    "MITRE ATT&CK STIX bundles",
    "CISA KEV (Known Exploited Vulnerabilities)",
    "Custom Kaggle dataset: CVE severity prediction",
]


def build_context(findings: List[UnifiedFinding]) -> str:
    lines = ["RAG CONTEXT (stub)"]
    lines.append(f"findings_count={len(findings)}")
    for item in findings[:10]:
        lines.append(f"- {item.cve_id or 'NO-CVE'} | {item.title} | {item.scanner_source}")
    return "\n".join(lines)


async def run_rag_pipeline(findings: List[UnifiedFinding]) -> dict:
    context = build_context(findings)
    return {
        "context": context,
        "retrieved_docs": [],
        "hallucination_rate_estimate": 0.0,
    }
