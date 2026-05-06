from normalizer.unified_schema import UnifiedFinding
from services.scan_pipeline import dedupe_findings


def _finding(cvss_score: float, title: str = "test", cve_id: str | None = "CVE-2024-0001") -> UnifiedFinding:
    return UnifiedFinding(
        scan_id="scan-1",
        target="example.com",
        scanner_source="nmap",
        title=title,
        description="desc",
        cvss_score=cvss_score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        severity="HIGH",
        cve_id=cve_id,
        affected_component="nginx",
        port=443,
    )


def test_unified_finding_cve_validation_rejects_bad_format():
    try:
        UnifiedFinding(
            scan_id="scan-1",
            target="example.com",
            scanner_source="nmap",
            title="bad",
            description="bad",
            severity="LOW",
            cvss_score=1.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cve_id="NOT-A-CVE",
            affected_component="component",
        )
        raised = False
    except Exception:
        raised = True
    assert raised


def test_dedupe_keeps_highest_cvss_for_same_fingerprint():
    a = _finding(3.2)
    b = _finding(8.4)
    c = _finding(6.0, cve_id="CVE-2024-9999")

    deduped = dedupe_findings([a, b, c])
    assert len(deduped) == 2
    top = next(item for item in deduped if item.cve_id == "CVE-2024-0001")
    assert top.cvss_score == 8.4
