from normalizer.unified_schema import ScanCreateRequest
from services.scan_pipeline import _runners_for


def test_phase2_scanner_registry_includes_extended_adapters():
    runners = list(_runners_for(["nmap", "openvas", "nessus", "trivy", "semgrep", "gitleaks", "zap"]))
    names = {runner.name for runner in runners}
    assert names == {"nmap", "openvas", "nessus", "trivy", "semgrep", "gitleaks", "zap"}


def test_scan_request_rejects_unknown_scanners():
    try:
        ScanCreateRequest(target="example.com", scanners=["nmap", "unknown-tool"], profile="quick")
    except Exception as exc:
        assert "Unsupported scanners" in str(exc)
        return
    assert False, "Expected unsupported scanner validation error"
