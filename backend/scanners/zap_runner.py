from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import datetime
from urllib.parse import quote

import httpx

from normalizer.unified_schema import ScannerRunState, UnifiedFinding, VerificationStatus
from scanners._ingest_utils import write_scanner_artifact
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class ZapRunner(ScannerBase):
    name = "zap"
    version = "phase2"

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

        base = os.getenv("ZAP_API_URL", "http://localhost:8080")
        apikey = os.getenv("ZAP_API_KEY", "")
        encoded_target = quote(target, safe="")

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                await client.get(f"{base}/JSON/spider/action/scan/?url={encoded_target}&apikey={apikey}")
                await asyncio.sleep(1.0)
                response = await client.get(f"{base}/JSON/core/view/alerts/?baseurl={encoded_target}&apikey={apikey}")
                response.raise_for_status()
                payload = response.text
        except Exception as exc:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.FAILED,
                findings=[],
                error=f"ZAP API request failed: {exc}",
                started_at=started,
                completed_at=datetime.utcnow(),
            )

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
        if shutil.which("curl") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="curl binary not found for ZAP API checks")
        if not os.getenv("ZAP_API_URL"):
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="ZAP_API_URL is not configured")
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
        for item in payload.get("alerts") or []:
            risk = str(item.get("risk") or "Informational")
            severity = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(risk.lower(), "INFO")
            refs = [str(ref) for ref in str(item.get("reference") or "").split("\n") if ref.strip()]
            findings.append(
                UnifiedFinding(
                    scan_id=scan_id,
                    target=target,
                    scanner_source=self.name,
                    title=str(item.get("name") or "ZAP alert"),
                    description=str(item.get("description") or "ZAP web finding"),
                    severity=severity,
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    cwe_id=(f"CWE-{item.get('cweid')}" if str(item.get("cweid") or "").isdigit() else None),
                    affected_component=str(item.get("url") or "web-surface"),
                    protocol="http",
                    service="web",
                    evidence={"param": item.get("param"), "attack": item.get("attack")},
                    remediation=str(item.get("solution") or "Follow ZAP recommendation and validate manually."),
                    references=refs,
                    verification_status=VerificationStatus.UNVERIFIED,
                    confidence_score=62.0,
                    false_positive_probability=0.34,
                    tags=["zap", "dast"],
                    source_artifact_path=artifact_path,
                )
            )
        return findings
