import asyncio
from datetime import datetime

from db.database import SessionLocal
from db.models import ScanJobModel
from normalizer.unified_schema import ScannerRunState, UnifiedFinding
from services.scan_pipeline import execute_scan_job


def test_execute_scan_job_with_unavailable_scanners_marks_complete_with_partial_failures(monkeypatch):
    import services.scan_pipeline as pipeline
    from scanners.scanner_base import ScannerExecutionResult

    class FakeRunner:
        name = "nmap"

        async def scan(self, *, target: str, profile: str, scan_id: str):
            return ScannerExecutionResult(
                scanner="nmap",
                status=ScannerRunState.SUCCESS,
                findings=[
                    UnifiedFinding(
                        scan_id=scan_id,
                        target=target,
                        scanner_source="nmap",
                        title="Open service requires manual validation",
                        description="Detected open tcp 443",
                        severity="INFO",
                        cvss_score=0.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        affected_component="https",
                        port=443,
                        protocol="tcp",
                        service="https",
                    )
                ],
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
            )

    class UnavailableRunner:
        def __init__(self, name: str):
            self.name = name

        async def scan(self, *, target: str, profile: str, scan_id: str):
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                findings=[],
                error=f"{self.name} unavailable",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
            )

    monkeypatch.setattr(pipeline, "_runners_for", lambda scanners: [FakeRunner(), UnavailableRunner("rustscan")])
    monkeypatch.setattr(pipeline, "run_rag_pipeline", lambda findings: asyncio.sleep(0, result={"context": ""}))
    monkeypatch.setattr(
        pipeline,
        "analyze_findings",
        lambda findings, rag_context, mode="unified": asyncio.sleep(
            0,
            result={
                "executive_summary": "ok",
                "key_findings": [],
                "recommended_actions": [],
                "zero_day_risk_assessment": "n/a",
            },
        ),
    )
    monkeypatch.setattr(pipeline, "detect_zero_day_risk", lambda findings, target: asyncio.sleep(0, result={"narrative": "n/a"}))
    monkeypatch.setattr(pipeline, "run_self_audit", lambda findings: asyncio.sleep(0, result={"status": "pass"}))
    monkeypatch.setattr(pipeline, "publish_progress", lambda *args, **kwargs: asyncio.sleep(0, result=None))
    monkeypatch.setattr(pipeline, "write_audit_event", lambda *args, **kwargs: None)

    asyncio.run(
        execute_scan_job(
            scan_id="scan-partial-1",
            target="example.com",
            profile="quick",
            scanners=["nmap", "rustscan"],
            actor="test",
        )
    )

    db = SessionLocal()
    try:
        record = db.get(ScanJobModel, "scan-partial-1")
        assert record is not None
        assert record.status == "complete"
        assert any(item.get("scanner") == "rustscan" and item.get("status") == "unavailable" for item in (record.scanner_runs or []))
    finally:
        db.close()
