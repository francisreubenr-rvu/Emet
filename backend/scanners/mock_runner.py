from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta
from uuid import uuid4

from scanners.scanner_base import ScannerBase, ScannerExecutionResult, ScannerAvailabilityResult
from normalizer.unified_schema import ScannerRunState, UnifiedFinding, Severity


class MockScanner(ScannerBase):
    def __init__(self, name: str):
        self.name = name
        self.version = "1.0.0-mock"

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started_at = datetime.utcnow()
        # Simulate work
        await asyncio.sleep(random.uniform(2, 5))
        
        findings = []
        num_findings = random.randint(1, 5)
        
        for i in range(num_findings):
            severity = random.choice([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])
            finding = UnifiedFinding(
                finding_id=f"mock-{uuid4().hex[:8]}",
                scan_id=scan_id,
                title=f"Simulated {self.name} Finding #{i+1}",
                description=f"This is a simulated vulnerability finding from the {self.name} mock runner for target {target}.",
                severity=severity.value,
                scanner_source=self.name,
                target=target,
                affected_component=random.choice(["web-server", "database", "api-gateway", "os-kernel"]),
                cve_id=f"CVE-2026-{random.randint(1000, 9999)}",
                remediation="Apply the latest security patches and follow hardening guidelines.",
                verification_status="unverified",
                timestamp=datetime.utcnow().isoformat(),
                dynamic_risk_score=random.uniform(1.0, 10.0),
                compliance_violations=[random.choice(["SOC2 CC7.1", "PCI-DSS 6.1", "HIPAA 164.308"])]
            )
            findings.append(finding)

        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.SUCCESS,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.utcnow()
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        return ScannerAvailabilityResult(scanner=self.name, available=True)
