from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
import shutil

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class NucleiRunner(ScannerBase):
    name = "nuclei"
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
        severity_filter = {
            "quick": ["critical", "high"],
            "standard": ["critical", "high", "medium"],
            "deep": ["critical", "high", "medium", "low"],
        }.get(profile.lower(), ["critical", "high", "medium"])

        command = [
            "nuclei",
            "-target",
            target,
            "-jsonl",
            "-silent",
            "-severity",
            ",".join(severity_filter),
        ]
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
                error=(stderr.decode("utf-8", errors="ignore") or "nuclei command failed")[:1200],
                artifact_path=artifact_path,
                started_at=started,
                completed_at=completed,
            )

        findings = self.normalize(
            {
                "jsonl": output,
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
        if shutil.which("nuclei") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="nuclei binary not found")
        return ScannerAvailabilityResult(scanner=self.name, available=True)

    def normalize(self, raw_output: dict):
        jsonl = raw_output.get("jsonl", "")
        target = raw_output.get("target", "unknown")
        scan_id = raw_output.get("scan_id", "scan-unknown")
        artifact_path = raw_output.get("artifact_path", "")

        findings: list[UnifiedFinding] = []
        for line in jsonl.splitlines():
            row = line.strip()
            if not row:
                continue
            try:
                payload = json.loads(row)
            except json.JSONDecodeError:
                continue

            info = payload.get("info") or {}
            cve_ids = info.get("classification", {}).get("cve-id") or []
            cve_id = cve_ids[0] if cve_ids else None
            severity = str(info.get("severity") or "info").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "INFO"

            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title=str(info.get("name") or payload.get("template-id") or "Nuclei finding"),
                    description=str(info.get("description") or payload.get("matched-at") or "Nuclei match"),
                    severity=severity,
                    cvss_score=float(info.get("classification", {}).get("cvss-score") or 0.0),
                    cvss_vector=str(info.get("classification", {}).get("cvss-metrics") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                    cve_id=cve_id,
                    affected_component=str(payload.get("template-id") or "web-surface"),
                    service="http",
                    protocol="tcp",
                    evidence={
                        "matcher_name": payload.get("matcher-name"),
                        "matched_at": payload.get("matched-at"),
                        "template_id": payload.get("template-id"),
                    },
                    remediation=str(info.get("remediation") or "Review matched template and patch accordingly."),
                    references=[str(item) for item in (info.get("reference") or [])],
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=68.0,
                    false_positive_probability=0.28,
                    tags=["nuclei", "template-match"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings

    def _write_artifact(self, *, scan_id: str, payload: str) -> str:
        base = Path("artifacts") / scan_id
        base.mkdir(parents=True, exist_ok=True)
        path = base / "nuclei.jsonl"
        path.write_text(payload or "", encoding="utf-8")
        return str(path)
