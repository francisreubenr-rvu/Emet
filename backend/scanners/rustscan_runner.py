from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
import re
import shutil

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class RustscanRunner(ScannerBase):
    name = "rustscan"
    version = "phase1"

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        availability = await self.is_available()
        if not availability.available:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                error=availability.reason,
                started_at=started,
                completed_at=datetime.utcnow(),
            )
        command = ["rustscan", "-a", target, "--ulimit", "5000", "--", "-Pn", "-T4"]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        completed = datetime.utcnow()

        output = stdout.decode("utf-8", errors="ignore")
        artifact_path = self._write_artifact(scan_id=scan_id, payload=output)

        if process.returncode != 0:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.FAILED,
                findings=[],
                error=(stderr.decode("utf-8", errors="ignore") or "rustscan command failed")[:1200],
                artifact_path=artifact_path,
                started_at=started,
                completed_at=completed,
            )

        findings = self.normalize(
            {
                "output": output,
                "target": target,
                "scan_id": scan_id,
                "artifact_path": artifact_path,
            }
        )
        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.SUCCESS,
            findings=findings,
            artifact_path=artifact_path,
            started_at=started,
            completed_at=completed,
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        if shutil.which("rustscan") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="rustscan binary not found")
        return ScannerAvailabilityResult(scanner=self.name, available=True)

    def normalize(self, raw_output: dict):
        output = raw_output.get("output", "")
        target = raw_output.get("target", "unknown")
        scan_id = raw_output.get("scan_id", "scan-unknown")
        artifact_path = raw_output.get("artifact_path", "")

        ports = sorted(
            {
                int(match.group(1))
                for match in re.finditer(r"(?i)open\s+(\d{1,5})", output)
                if 0 < int(match.group(1)) <= 65535
            }
        )
        findings: list[UnifiedFinding] = []
        for port in ports[:128]:
            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title="Rustscan open port discovery",
                    description=f"Open TCP port {port} discovered by rustscan",
                    severity="INFO",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    affected_component="network-service",
                    port=port,
                    protocol="tcp",
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=48.0,
                    false_positive_probability=0.45,
                    tags=["port-discovery", "rustscan"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings

    def _write_artifact(self, *, scan_id: str, payload: str) -> str:
        base = Path("artifacts") / scan_id
        base.mkdir(parents=True, exist_ok=True)
        path = base / "rustscan.txt"
        path.write_text(payload or "", encoding="utf-8")
        return str(path)
