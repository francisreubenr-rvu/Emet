from __future__ import annotations

from typing import List

from normalizer.unified_schema import UnifiedFinding


async def detect_zero_day_risk(findings: List[UnifiedFinding], target: str) -> dict:
    residual = [item for item in findings if not item.cve_id]
    score = min(100, 20 + len(residual) * 8)
    narrative = (
        "Residual anomalies were identified and require monitoring uplift."
        if residual
        else "No unclassified residual anomalies detected in this scan batch."
    )
    return {
        "target": target,
        "zero_day_risk_score": score,
        "narrative": narrative,
        "recommended_monitoring": [
            "Enable continuous telemetry for exposed services.",
            "Correlate with latest 30-day CVE advisories.",
        ],
    }
