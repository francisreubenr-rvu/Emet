from __future__ import annotations

from random import sample
from typing import List

from normalizer.unified_schema import UnifiedFinding


async def run_self_audit(findings: List[UnifiedFinding]) -> dict:
    if not findings:
        return {"sample_size": 0, "checked": 0, "issues": [], "status": "no-findings"}

    sample_size = max(1, int(len(findings) * 0.2))
    sampled = sample(findings, min(sample_size, len(findings)))

    issues = []
    for item in sampled:
        if item.cvss_score < 0 or item.cvss_score > 10:
            issues.append(f"CVSS out of bounds for {item.cve_id or item.title}")

    return {
        "sample_size": sample_size,
        "checked": len(sampled),
        "issues": issues,
        "status": "pass" if not issues else "warning",
    }
