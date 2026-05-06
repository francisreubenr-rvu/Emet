from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners._ingest_utils import resolve_local_path, write_scanner_artifact
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class NessusRunner(ScannerBase):
    name = "nessus"
    version = "phase2"

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        sample_path = os.getenv("NESSUS_REPORT_PATH", "").strip()
        if not sample_path:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error="NESSUS_REPORT_PATH is not configured",
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
        artifact_path = write_scanner_artifact(scan_id=scan_id, scanner=self.name, payload=payload, suffix="json")
        findings = self.normalize({"json": payload, "target": target, "scan_id": scan_id, "artifact_path": artifact_path})
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
        return ScannerAvailabilityResult(scanner=self.name, available=True, reason="Nessus report-ingest mode")

    def normalize(self, raw_output: dict):
        payload_text = raw_output.get("json", "")
        target = raw_output.get("target", "unknown")
        scan_id = raw_output.get("scan_id", "scan-unknown")
        artifact_path = raw_output.get("artifact_path", "")
        if not payload_text.strip():
            return []
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            return []

        findings: list[UnifiedFinding] = []
        for item in payload.get("vulnerabilities") or payload.get("findings") or []:
            cve = str(item.get("cve") or "").strip()
            score = float(item.get("cvss") or item.get("cvss_score") or 0.0)
            severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            refs = [str(ref) for ref in (item.get("references") or [])]
            if cve.startswith("CVE-") and f"https://nvd.nist.gov/vuln/detail/{cve}" not in refs:
                refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title=str(item.get("title") or "Nessus finding"),
                    description=str(item.get("description") or "Nessus report finding"),
                    severity=severity,
                    cvss_score=score,
                    cvss_vector=str(item.get("cvss_vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                    cve_id=cve if cve.startswith("CVE-") else None,
                    affected_component=str(item.get("asset") or item.get("plugin_name") or "host"),
                    port=int(item.get("port") or 0) or None,
                    protocol=str(item.get("protocol") or "tcp"),
                    service=str(item.get("service") or "network"),
                    evidence={"plugin_id": item.get("plugin_id"), "plugin_name": item.get("plugin_name")},
                    remediation=str(item.get("solution") or "Follow Nessus remediation guidance."),
                    references=refs,
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=69.0,
                    false_positive_probability=0.29,
                    tags=["nessus", "report-ingest"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings
