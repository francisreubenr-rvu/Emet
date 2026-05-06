from __future__ import annotations

from normalizer.unified_schema import Severity


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def normalize_cvss(score: float, vector: str | None = None) -> tuple[float, str, Severity]:
    bounded = min(max(score, 0.0), 10.0)
    normalized_vector = vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    return bounded, normalized_vector, score_to_severity(bounded)
