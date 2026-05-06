from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners._ingest_utils import resolve_local_path, write_scanner_artifact
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class OpenVASRunner(ScannerBase):
    name = "openvas"
    version = "phase2"

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        sample_path = os.getenv("OPENVAS_REPORT_PATH", "").strip()
        if not sample_path:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error="OPENVAS_REPORT_PATH is not configured",
                started_at=started,
                completed_at=datetime.utcnow(),
            )

        resolved, reason = resolve_local_path(sample_path, allowed_root=os.getenv("SCAN_REPORT_ALLOWED_ROOT", "/app/artifacts"), expect_file=True)
        if resolved is None:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error=reason,
                started_at=started,
                completed_at=datetime.utcnow(),
            )

        payload = Path(resolved).read_text(encoding="utf-8")
        artifact_path = write_scanner_artifact(scan_id=scan_id, scanner=self.name, payload=payload, suffix="xml")
        findings = self.normalize({"xml": payload, "target": target, "scan_id": scan_id, "artifact_path": artifact_path})
        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.SUCCESS,
            findings=findings,
            artifact_path=artifact_path,
            started_at=started,
            completed_at=datetime.utcnow(),
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        if shutil.which("python") is None and shutil.which("python3") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="python runtime unavailable")
        return ScannerAvailabilityResult(scanner=self.name, available=True, reason="OpenVAS report-ingest mode")

    def normalize(self, raw_output: dict):
        xml_output = raw_output.get("xml", "")
        target = raw_output.get("target", "unknown")
        scan_id = raw_output.get("scan_id", "scan-unknown")
        artifact_path = raw_output.get("artifact_path", "")
        if not xml_output.strip():
            return []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return []

        findings: list[UnifiedFinding] = []
        for result in root.findall(".//result"):
            name = (result.findtext("name") or "OpenVAS finding").strip()
            desc = (result.findtext("description") or "").strip()
            cve = (result.findtext("nvt/cve") or "").strip()
            severity_num = float((result.findtext("severity") or "0").strip() or 0.0)
            severity = "CRITICAL" if severity_num >= 9 else "HIGH" if severity_num >= 7 else "MEDIUM" if severity_num >= 4 else "LOW"
            port_text = (result.findtext("port") or "0").split("/")[0]
            port = int(port_text) if port_text.isdigit() else None
            refs = [f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve.startswith("CVE-") else []
            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title=name,
                    description=desc or "OpenVAS report finding",
                    severity=severity,
                    cvss_score=severity_num,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cve_id=cve if cve.startswith("CVE-") else None,
                    affected_component="network-service",
                    port=port,
                    protocol="tcp",
                    service="network",
                    evidence={"report": "openvas", "raw_name": name},
                    remediation="Follow OpenVAS remediation guidance and validate with patch management.",
                    references=refs,
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=66.0,
                    false_positive_probability=0.31,
                    tags=["openvas", "report-ingest"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings
