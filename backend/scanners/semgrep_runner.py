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


class SemgrepRunner(ScannerBase):
    name = "semgrep"
    version = "phase2"

    def _resolve_repo_path(self, target: str) -> tuple[str | None, str]:
        if target.startswith("repo:"):
            raw = target.split("repo:", 1)[1]
        elif target.startswith("file://"):
            raw = urlparse(target).path
        else:
            return None, "Semgrep requires a repository target using repo:/path or file:///path"
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

        command = ["semgrep", "scan", "--json", "--quiet", repo_path]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        completed = datetime.utcnow()
        output = stdout.decode("utf-8", errors="ignore")
        artifact_path = write_scanner_artifact(scan_id=scan_id, scanner=self.name, payload=output, suffix="json")

        if process.returncode not in {0, 1}:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.FAILED,
                findings=[],
                error=(stderr.decode("utf-8", errors="ignore") or "semgrep command failed")[:1200],
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
        if shutil.which("semgrep") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="semgrep binary not found")
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
        for item in payload.get("results") or []:
            metadata = item.get("extra", {}).get("metadata", {})
            severity = str(metadata.get("severity") or item.get("extra", {}).get("severity") or "INFO").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "INFO"
            references = [str(ref) for ref in (metadata.get("references") or [])]
            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title=str(item.get("check_id") or "Semgrep finding"),
                    description=str(item.get("extra", {}).get("message") or "Semgrep rule matched"),
                    severity=severity,
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id=str((metadata.get("cwe") or [None])[0] or "") or None,
                    affected_component=str(item.get("path") or "source-code"),
                    evidence={"lines": item.get("extra", {}).get("lines"), "start": item.get("start")},
                    remediation="Review code path and apply secure coding controls.",
                    references=references,
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=60.0,
                    false_positive_probability=0.35,
                    tags=["semgrep", "sast"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings
