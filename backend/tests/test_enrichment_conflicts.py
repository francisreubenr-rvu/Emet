from normalizer.unified_schema import UnifiedFinding, VerificationStatus
from services.enrichment import merge_enrichment_records


def _base_finding() -> UnifiedFinding:
    return UnifiedFinding(
        scan_id="scan-1",
        target="example.com",
        scanner_source="nmap",
        title="base",
        description="base",
        severity="MEDIUM",
        cvss_score=5.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cve_id="CVE-2024-1111",
        affected_component="nginx",
    )


def test_enrichment_marks_partially_verified_on_conflict():
    finding = _base_finding()
    records = [
        {"source": "nvd", "cve_id": "CVE-2024-1111", "cvss_score": 7.1, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"]},
        {"source": "vendor", "cve_id": "CVE-2024-2222", "cvss_score": 8.9, "references": ["https://vendor.example/advisory"]},
    ]
    updated, meta = merge_enrichment_records(finding, records)
    assert updated.verification_status == VerificationStatus.PARTIALLY_VERIFIED
    assert meta["conflicts"]


def test_enrichment_marks_verified_without_conflict():
    finding = _base_finding()
    records = [
        {"source": "nvd", "cve_id": "CVE-2024-1111", "cvss_score": 7.1, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"]},
        {"source": "cisa_kev", "cve_id": "CVE-2024-1111", "cvss_score": 7.1, "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]},
    ]
    updated, meta = merge_enrichment_records(finding, records)
    assert updated.verification_status == VerificationStatus.VERIFIED
    assert meta["conflicts"] == []
