from __future__ import annotations

from datetime import datetime

from normalizer.unified_schema import ScannerRunState
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class NiktoRunner(ScannerBase):
    name = "nikto"
    version = "stub-1.0"

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.UNAVAILABLE,
            findings=[],
            error="Nikto adapter not configured",
            started_at=started,
            completed_at=datetime.utcnow(),
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        return ScannerAvailabilityResult(scanner=self.name, available=False, reason="Nikto binary unavailable")

    def normalize(self, raw_output: dict):
        return []
