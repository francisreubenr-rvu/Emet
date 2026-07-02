from fastapi.testclient import TestClient

from db.database import SessionLocal
from db.models import VulnerabilityModel, ScanJobModel
from services.enrichment import calculate_dynamic_risk_score


def test_calculate_dynamic_risk_score():
    score1 = calculate_dynamic_risk_score(cvss_score=8.0, epss_score=0.9, cisa_kev=True)
    assert score1 > 8.0  # High because of CISA KEV + high EPSS
    assert score1 <= 10.0

    score2 = calculate_dynamic_risk_score(cvss_score=4.0, epss_score=0.01, cisa_kev=False)
    assert score2 == (4.0 * 0.5) + (0.01 * 10 * 0.3)


def test_recalculate_risk_endpoint(auth_client: TestClient):
    db = SessionLocal()
    try:
        db.merge(ScanJobModel(id="scan-risk-test", target="127.0.0.1", status="complete"))
        db.merge(
            VulnerabilityModel(
                finding_id="vuln-risk-test-1",
                scan_id="scan-risk-test",
                target="127.0.0.1",
                scanner_source="nmap",
                title="Test Vuln",
                cve_id="CVE-2021-44228",
                cvss_score=7.5,
            )
        )
        db.commit()
    finally:
        db.close()

    response = auth_client.post("/api/vulnerabilities/vuln-risk-test-1/risk/recalculate")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "vuln-risk-test-1"
    assert set(["epss_score", "cisa_kev", "dynamic_risk_score"]).issubset(data)
    # Values come from live feeds; assert only that they are well-formed, never fabricated shapes.
    assert 0.0 <= data["epss_score"] <= 1.0
    assert isinstance(data["cisa_kev"], bool)
    assert 0.0 <= data["dynamic_risk_score"] <= 10.0
