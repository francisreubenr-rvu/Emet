from scanners.nmap_runner import NmapRunner
from scanners.nuclei_runner import NucleiRunner
from scanners.rustscan_runner import RustscanRunner
from scanners.trivy_runner import TrivyRunner
from scanners.semgrep_runner import SemgrepRunner
from scanners.gitleaks_runner import GitleaksRunner
from scanners.zap_runner import ZapRunner
from scanners.openvas_runner import OpenVASRunner
from scanners.nessus_runner import NessusRunner


NMAP_XML = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr='93.184.216.34' addrtype='ipv4'/>
    <ports>
      <port protocol='tcp' portid='80'>
        <state state='open'/>
        <service name='http' product='nginx' version='1.18.0'/>
      </port>
      <port protocol='tcp' portid='22'>
        <state state='closed'/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_xml_parser_extracts_open_ports_only():
    runner = NmapRunner()
    findings = runner.normalize({"xml": NMAP_XML, "target": "example.com", "scan_id": "scan-test", "artifact_path": "artifact.xml"})
    assert len(findings) == 1
    assert findings[0].port == 80
    assert findings[0].service == "http"


def test_rustscan_parser_extracts_ports_from_open_lines():
    runner = RustscanRunner()
    output = "Open 80\nOpen 443\nnoise 99999"
    findings = runner.normalize({"output": output, "target": "example.com", "scan_id": "scan-rs", "artifact_path": "rs.txt"})
    ports = sorted(item.port for item in findings)
    assert ports == [80, 443]


def test_nuclei_jsonl_parser_extracts_cve_and_severity():
    runner = NucleiRunner()
    jsonl = (
        '{"template-id":"cves/2024/CVE-2024-0001","matched-at":"https://example.com",'
        '"info":{"name":"Test template","severity":"high","classification":{"cve-id":["CVE-2024-0001"],"cvss-score":8.1}}}'
    )
    findings = runner.normalize({"jsonl": jsonl, "target": "example.com", "scan_id": "scan-nu", "artifact_path": "nu.jsonl"})
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-0001"
    assert findings[0].severity.value == "HIGH"


def test_trivy_json_parser_extracts_cve():
    runner = TrivyRunner()
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1001",
                        "Title": "Test Trivy",
                        "Description": "desc",
                        "Severity": "HIGH",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0",
                    }
                ],
            }
        ]
    }
    findings = runner.normalize({"json": __import__("json").dumps(payload), "target": "repo:/tmp", "scan_id": "scan-tr", "artifact_path": "trivy.json"})
    assert findings
    assert findings[0].cve_id == "CVE-2024-1001"


def test_semgrep_json_parser_extracts_results():
    runner = SemgrepRunner()
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval",
                "path": "app.py",
                "extra": {"message": "avoid eval", "metadata": {"references": ["https://example.com"]}},
            }
        ]
    }
    findings = runner.normalize({"json": __import__("json").dumps(payload), "target": "repo:/tmp", "scan_id": "scan-sm", "artifact_path": "semgrep.json"})
    assert findings
    assert findings[0].scanner_source == "semgrep"


def test_gitleaks_json_parser_extracts_secrets_findings():
    runner = GitleaksRunner()
    payload = [{"Description": "Hardcoded token", "File": "secrets.env", "RuleID": "generic-api-key", "StartLine": 5}]
    findings = runner.normalize({"json": __import__("json").dumps(payload), "target": "repo:/tmp", "scan_id": "scan-gl", "artifact_path": "gitleaks.json"})
    assert findings
    assert findings[0].severity.value == "HIGH"


def test_zap_json_parser_extracts_alerts():
    runner = ZapRunner()
    payload = {"alerts": [{"name": "X-Frame-Options Header Not Set", "risk": "Medium", "cweid": "1021", "url": "https://example.com"}]}
    findings = runner.normalize({"json": __import__("json").dumps(payload), "target": "https://example.com", "scan_id": "scan-zp", "artifact_path": "zap.json"})
    assert findings
    assert findings[0].severity.value == "MEDIUM"


def test_openvas_xml_parser_extracts_results():
    runner = OpenVASRunner()
    xml = """<report><results><result><name>OpenVAS sample</name><description>desc</description><severity>7.5</severity><nvt><cve>CVE-2024-1002</cve></nvt><port>443/tcp</port></result></results></report>"""
    findings = runner.normalize({"xml": xml, "target": "example.com", "scan_id": "scan-ov", "artifact_path": "openvas.xml"})
    assert findings
    assert findings[0].cve_id == "CVE-2024-1002"


def test_nessus_json_parser_extracts_results():
    runner = NessusRunner()
    payload = {"vulnerabilities": [{"title": "Nessus sample", "description": "desc", "cve": "CVE-2024-1003", "cvss": 8.1, "port": 443}]}
    findings = runner.normalize({"json": __import__("json").dumps(payload), "target": "example.com", "scan_id": "scan-ne", "artifact_path": "nessus.json"})
    assert findings
    assert findings[0].cve_id == "CVE-2024-1003"
