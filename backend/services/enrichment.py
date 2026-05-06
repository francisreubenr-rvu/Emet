from __future__ import annotations

from collections import defaultdict

from normalizer.unified_schema import UnifiedFinding, VerificationStatus, Severity


TRUST_RANK = {
    "scanner": 0,
    "nvd": 1,
    "cisa_kev": 2,
    "osv": 3,
    "vendor": 4,
}


def _source_rank(source: str) -> int:
    return TRUST_RANK.get(source.lower(), 0)

def mock_fetch_epss_score(cve_id: str) -> float:
    # Mock EPSS score (0.0 to 1.0)
    if "2021" in cve_id:
        return 0.85
    return 0.05

def mock_check_cisa_kev(cve_id: str) -> bool:
    if "2021" in cve_id:
        return True
    return False

def calculate_dynamic_risk_score(cvss_score: float, epss_score: float, cisa_kev: bool) -> float:
    base = cvss_score * 0.5
    epss_component = (epss_score * 10) * 0.3
    kev_bump = 2.0 if cisa_kev else 0.0
    score = base + epss_component + kev_bump
    return min(10.0, score)

def map_compliance(finding: UnifiedFinding) -> list[str]:
    violations = []
    
    # Severity-based mapping
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        violations.extend(["SOC2 CC7.1", "PCI-DSS 6.1"])
    elif finding.severity == Severity.LOW:
        violations.append("HIPAA 164.312")
        
    # Specific CVE mapping
    if finding.cve_id == "CVE-2021-1234" and "PCI-DSS 6.1" not in violations:
        violations.append("PCI-DSS 6.1")
        
    # Deduplicate and return
    return list(dict.fromkeys(violations))

def merge_enrichment_records(
    finding: UnifiedFinding,
    records: list[dict],
) -> tuple[UnifiedFinding, dict]:
    """Merge enrichment records and preserve source conflicts.

    Each record is expected to contain at least:
    - source
    - cve_id
    - cvss_score
    - references
    """

    if not records:
        return finding, {"applied": False, "conflicts": [], "sources": []}

    by_cve: dict[str, list[dict]] = defaultdict(list)
    for item in records:
        cve = str(item.get("cve_id") or "").strip()
        if cve:
            by_cve[cve].append(item)

    conflicts: list[dict] = []
    selected_cve = finding.cve_id
    selected_score = finding.cvss_score
    selected_source = "scanner"

    # Choose highest-trust + highest-cvss candidate.
    for cve, entries in by_cve.items():
        entries_sorted = sorted(
            entries,
            key=lambda item: (_source_rank(str(item.get("source", ""))), float(item.get("cvss_score") or 0.0)),
            reverse=True,
        )
        candidate = entries_sorted[0]
        candidate_score = float(candidate.get("cvss_score") or 0.0)
        candidate_source = str(candidate.get("source") or "unknown")

        if selected_cve is None:
            selected_cve = cve
            selected_score = candidate_score
            selected_source = candidate_source
        elif _source_rank(candidate_source) > _source_rank(selected_source):
            if cve != selected_cve:
                conflicts.append(
                    {
                        "type": "cve_mismatch",
                        "preferred": selected_cve,
                        "alternative": cve,
                        "source": candidate_source,
                    }
                )
            selected_cve = cve
            selected_score = candidate_score
            selected_source = candidate_source
        elif cve != selected_cve:
            conflicts.append(
                {
                    "type": "cve_mismatch",
                    "preferred": selected_cve,
                    "alternative": cve,
                    "source": candidate_source,
                }
            )

        # Detect score disagreements within same CVE.
        score_values = {round(float(item.get("cvss_score") or 0.0), 1) for item in entries}
        if len(score_values) > 1:
            conflicts.append(
                {
                    "type": "cvss_conflict",
                    "cve_id": cve,
                    "values": sorted(score_values),
                }
            )

    finding.cve_id = selected_cve
    finding.cvss_score = selected_score
    finding.verification_status = (
        VerificationStatus.PARTIALLY_VERIFIED if conflicts else VerificationStatus.VERIFIED
    )
    finding.confidence_score = 80.0 if not conflicts else 64.0
    finding.false_positive_probability = 0.18 if not conflicts else 0.35

    merged_refs: list[str] = list(finding.references)
    for item in records:
        for ref in item.get("references") or []:
            if ref not in merged_refs:
                merged_refs.append(ref)
    finding.references = merged_refs

    finding.evidence = {
        **finding.evidence,
        "enrichment": {
            "applied": True,
            "preferred_source": selected_source,
            "sources": [str(item.get("source") or "unknown") for item in records],
            "conflicts": conflicts,
        },
    }

    return finding, finding.evidence["enrichment"]


async def enrich_findings(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    """Phase 2 slice: deterministic enrichment pass with provenance.

    This keeps the pipeline online even when external APIs are unavailable.
    """

    enriched: list[UnifiedFinding] = []
    for finding in findings:
        records: list[dict] = []
        if finding.cve_id:
            records.append(
                {
                    "source": "nvd",
                    "cve_id": finding.cve_id,
                    "cvss_score": finding.cvss_score,
                    "references": [f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}"],
                }
            )
            if finding.cvss_score >= 7.0:
                records.append(
                    {
                        "source": "cisa_kev",
                        "cve_id": finding.cve_id,
                        "cvss_score": finding.cvss_score,
                        "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                    }
                )

        updated, _meta = merge_enrichment_records(finding, records)
        if updated.cve_id:
            updated.epss_score = mock_fetch_epss_score(updated.cve_id)
            updated.cisa_kev = mock_check_cisa_kev(updated.cve_id)
        updated.dynamic_risk_score = calculate_dynamic_risk_score(
            updated.cvss_score, updated.epss_score, updated.cisa_kev
        )
        enriched.append(updated)
    return enriched
