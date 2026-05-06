from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import datetime
from urllib.parse import urlparse

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners._ingest_utils import resolve_local_path, write_scanner_artifact
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class TrivyRunner(ScannerBase):
    name = "trivy"
    version = "phase2"

    def _resolve_repo_path(self, target: str) -> tuple[str | None, str]:
        if target.startswith("repo:"):
            raw = target.split("repo:", 1)[1]
        elif target.startswith("file://"):
            raw = urlparse(target).path
        else:
            return None, "Trivy requires a repository target using repo:/path or file:///path"
        return resolve_local_path(raw, allowed_root=os.getenv("SCAN_REPO_ALLOWED_ROOT", "/app"), expect_file=False)

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        availability = await self.is_available()
        if not availability.available:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error=availability.reason,
                started_at=started,
                completed_at=datetime.utcnow(),
            )

        repo_path, reason = self._resolve_repo_path(target)
        if repo_path is None:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error=reason,
                started_at=started,
                completed_at=datetime.utcnow(),
            )

        severities = {
            "quick": "CRITICAL,HIGH",
            "standard": "CRITICAL,HIGH,MEDIUM",
            "deep": "CRITICAL,HIGH,MEDIUM,LOW",
        }.get(profile.lower(), "CRITICAL,HIGH,MEDIUM")

        command = ["trivy", "fs", "--format", "json", "--quiet", "--severity", severities, repo_path]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        completed = datetime.utcnow()
        output = stdout.decode("utf-8", errors="ignore")
        artifact_path = write_scanner_artifact(scan_id=scan_id, scanner=self.name, payload=output, suffix="json")

        if process.returncode not in {0, 5}:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.FAILED,
                findings=[],
                error=(stderr.decode("utf-8", errors="ignore") or "trivy command failed")[:1200],
                artifact_path=artifact_path,
                started_at=started,
                completed_at=completed,
            )

        findings = self.normalize({"json": output, "target": target, "scan_id": scan_id, "artifact_path": artifact_path})
        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.SUCCESS,
            findings=findings,
            artifact_path=artifact_path,
            started_at=started,
            completed_at=completed,
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        if shutil.which("trivy") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="trivy binary not found")
        return ScannerAvailabilityResult(scanner=self.name, available=True)

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
        for result in payload.get("Results") or []:
            component = str(result.get("Target") or result.get("Type") or "artifact")
            for vuln in result.get("Vulnerabilities") or []:
                vuln_id = str(vuln.get("VulnerabilityID") or "")
                severity = str(vuln.get("Severity") or "INFO").upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    severity = "INFO"
                refs = [str(vuln.get("PrimaryURL") or "")] + [str(item) for item in (vuln.get("References") or [])]
                refs = [item for item in refs if item]
                findings.append(
                    UnifiedFinding(
                        scan_id=scan_id,
                        target=target,
                        scanner_source=self.name,
                        title=str(vuln.get("Title") or vuln_id or "Trivy finding"),
                        description=str(vuln.get("Description") or "Trivy vulnerability match"),
                        severity=severity,
                        cvss_score=float((vuln.get("CVSS") or {}).get("nvd", {}).get("V3Score") or 0.0),
                        cvss_vector=str((vuln.get("CVSS") or {}).get("nvd", {}).get("V3Vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                        cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                        affected_component=str(vuln.get("PkgName") or component),
                        affected_version=str(vuln.get("InstalledVersion") or "") or None,
                        evidence={"class": vuln.get("Class"), "target": component},
                        remediation=str(vuln.get("FixedVersion") or "Review package update recommendations"),
                        references=refs,
                        verification_status=VerificationStatus.UNVERIFIED,
                        confidence_score=70.0,
                        false_positive_probability=0.28,
                        tags=["trivy", "dependency-scan"],
                        source_artifact_path=artifact_path,
                    )
                )
        return findings
