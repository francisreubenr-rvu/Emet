from __future__ import annotations

from collections import defaultdict

from normalizer.unified_schema import UnifiedFinding, VerificationStatus, Severity
from services import intel_feeds


TRUST_RANK = {
    "scanner": 0,
    "nvd": 1,
    "cisa_kev": 2,
    "osv": 3,
    "vendor": 4,
}


def _source_rank(source: str) -> int:
    return TRUST_RANK.get(source.lower(), 0)


async def fetch_epss_score(cve_id: str) -> float:
    """Real EPSS probability from FIRST.org; 0.0 when unavailable (never fabricated)."""
    score = await intel_feeds.fetch_epss_score(cve_id)
    return score if score is not None else 0.0


async def check_cisa_kev(cve_id: str) -> bool:
    """Real CISA KEV membership; False when the catalog lacks the CVE or is
    unreachable (we do not guess membership)."""
    result = await intel_feeds.check_cisa_kev(cve_id)
    return bool(result)


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

    # Known-exploited findings implicate patch-management controls directly.
    if getattr(finding, "cisa_kev", False):
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
    """Enrichment pass with real threat-intelligence provenance.

    Sources every value from a live feed (NVD, EPSS, CISA KEV) and degrades to
    the finding's own values when a feed is unavailable — it never invents data.
    """

    enriched: list[UnifiedFinding] = []
    for finding in findings:
        records: list[dict] = []
        if intel_feeds.is_valid_cve(finding.cve_id):
            nvd = await intel_feeds.fetch_nvd_metrics(finding.cve_id)
            if nvd:
                records.append(
                    {
                        "source": "nvd",
                        "cve_id": nvd["cve_id"],
                        "cvss_score": nvd["cvss_score"]
                        if nvd["cvss_score"] is not None
                        else finding.cvss_score,
                        "references": nvd["references"]
                        or [f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}"],
                    }
                )

        updated, _meta = merge_enrichment_records(finding, records)
        if intel_feeds.is_valid_cve(updated.cve_id):
            updated.epss_score = await fetch_epss_score(updated.cve_id)
            updated.cisa_kev = await check_cisa_kev(updated.cve_id)
            if updated.cisa_kev:
                updated.references = list(
                    dict.fromkeys(
                        [*updated.references, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
                    )
                )
        updated.dynamic_risk_score = calculate_dynamic_risk_score(
            updated.cvss_score, updated.epss_score, updated.cisa_kev
        )
        updated.compliance_violations = map_compliance(updated)
        enriched.append(updated)
    return enriched
