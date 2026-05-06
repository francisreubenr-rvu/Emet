from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from normalizer.unified_schema import ScannerRunState, UnifiedFinding


@dataclass(slots=True)
class ScannerExecutionResult:
    scanner: str
    status: ScannerRunState
    findings: list[UnifiedFinding] = field(default_factory=list)
    error: str = ""
    artifact_path: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(slots=True)
class ScannerAvailabilityResult:
    scanner: str
    available: bool
    reason: str = ""


class ScannerBase(ABC):
    name: str
    version: str

    @abstractmethod
    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        """Run scanner and return normalized findings and execution metadata."""

    @abstractmethod
    async def is_available(self) -> ScannerAvailabilityResult:
        """Check scanner binary/service availability."""

    def normalize(self, raw_output: dict) -> list[UnifiedFinding]:
        """Convert tool output to unified findings schema."""
        raise NotImplementedError
