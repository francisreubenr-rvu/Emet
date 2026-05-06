from __future__ import annotations

import time
from datetime import datetime

from ai.gemini_client import analyze_findings
from ai.rag_pipeline import run_rag_pipeline
from ai.self_audit import run_self_audit
from ai.zero_day_detector import detect_zero_day_risk
from db.database import SessionLocal
from db.models import ScanJobModel
from normalizer.unified_schema import ScannerRunSummary, ScannerRunState, UnifiedFinding
from scanners.nmap_runner import NmapRunner
from scanners.nessus_runner import NessusRunner
from scanners.nuclei_runner import NucleiRunner
from scanners.openvas_runner import OpenVASRunner
from scanners.rustscan_runner import RustscanRunner
from scanners.semgrep_runner import SemgrepRunner
from scanners.trivy_runner import TrivyRunner
from scanners.gitleaks_runner import GitleaksRunner
from scanners.zap_runner import ZapRunner
from scanners.mock_runner import MockScanner
from services.enrichment import enrich_findings
from services.progress import publish_progress
from services.scan_store import add_raw_artifact, get_scan_findings, upsert_scan_record
from services.audit import write_audit_event
from services.attack_paths import build_attack_paths, persist_attack_paths
from services.alerts import send_webhook_alert


def dedupe_findings(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    deduped: dict[str, UnifiedFinding] = {}
    for item in findings:
        key = "|".join(
            [
                item.cve_id or "NO-CVE",
                item.affected_component or "unknown",
                str(item.port or 0),
                item.target,
            ]
        )
        existing = deduped.get(key)
        if existing is None or item.cvss_score > existing.cvss_score:
            deduped[key] = item
    return list(deduped.values())


def _runners_for(scanners: list[str]):
    import os
    simulate = os.getenv("EMET_SIMULATE_SCANS", "false").lower() in ("true", "1", "yes")
    registry = {
        "nmap": NmapRunner,
        "rustscan": RustscanRunner,
        "nuclei": NucleiRunner,
        "openvas": OpenVASRunner,
        "nessus": NessusRunner,
        "trivy": TrivyRunner,
        "semgrep": SemgrepRunner,
        "gitleaks": GitleaksRunner,
        "zap": ZapRunner,
    }
    for key in scanners:
        if simulate:
            yield MockScanner(name=key)
            continue
        runner_cls = registry.get(key)
        if runner_cls is not None:
            yield runner_cls()


async def execute_scan_job(scan_id: str, target: str, profile: str, scanners: list[str], actor: str = "worker") -> None:
    db = SessionLocal()
    started = time.monotonic()
    run_summaries: list[ScannerRunSummary] = []
    all_findings: list[UnifiedFinding] = []
    failed_scanners: list[str] = []

    try:
        write_audit_event(event_type="scan.job.started", actor=actor, scan_id=scan_id, details={"target": target, "scanners": scanners})
        upsert_scan_record(
            db,
            scan_id=scan_id,
            target=target,
            profile=profile,
            status="running",
            tools=scanners,
            findings=[],
            scanner_runs=[],
            actor=actor,
            queue_identity="worker",
        )
        await publish_progress(
            scan_id,
            {
                "phase": "INITIALIZING",
                "message": "Preparing scanner pipeline",
            },
        )

        selected_runners = list(_runners_for(scanners))
        if not selected_runners:
            raise RuntimeError("No supported scanners selected for this job")

        total = len(selected_runners)
        for index, runner in enumerate(selected_runners, start=1):
            current = db.get(ScanJobModel, scan_id)
            if current and current.cancellation_requested:
                upsert_scan_record(
                    db,
                    scan_id=scan_id,
                    target=target,
                    profile=profile,
                    status="cancelled",
                    tools=scanners,
                    findings=all_findings,
                    duration_seconds=max(1, int(time.monotonic() - started)),
                    scanner_runs=run_summaries,
                    actor=actor,
                    queue_identity="worker",
                )
                await publish_progress(scan_id, {"phase": "CANCELLED", "message": "Scan cancelled"})
                write_audit_event(event_type="scan.job.cancelled", actor=actor, scan_id=scan_id)
                return

            await publish_progress(
                scan_id,
                {
                    "phase": "SCANNER_RUNNING",
                    "scanner": runner.name,
                    "scanner_index": index,
                    "scanner_total": total,
                    "message": f"Running {runner.name}",
                },
            )

            result = await runner.scan(target=target, profile=profile, scan_id=scan_id)
            run_summaries.append(
                ScannerRunSummary(
                    scanner=result.scanner,
                    status=result.status,
                    findings_count=len(result.findings),
                    error=result.error,
                    artifact_path=result.artifact_path,
                    started_at=result.started_at,
                    completed_at=result.completed_at,
                )
            )

            if result.artifact_path:
                add_raw_artifact(db, scan_id=scan_id, scanner_source=result.scanner, artifact_path=result.artifact_path)

            if result.status == ScannerRunState.SUCCESS:
                all_findings.extend(result.findings)
            else:
                failed_scanners.append(f"{result.scanner}: {result.error or result.status.value}")

            await publish_progress(
                scan_id,
                {
                    "phase": "SCANNER_COMPLETE",
                    "scanner": result.scanner,
                    "status": result.status.value,
                    "message": result.error or f"{result.scanner} completed",
                },
            )

        await publish_progress(
            scan_id,
            {
                "phase": "NORMALIZING",
                "message": "Deduplicating findings and preparing enrichment context",
            },
        )

        findings = dedupe_findings(all_findings)
        findings = await enrich_findings(findings)
        rag = await run_rag_pipeline(findings)
        unified = await analyze_findings(findings, rag_context=rag["context"], mode="unified")
        zero_day = await detect_zero_day_risk(findings, target)
        self_audit = await run_self_audit(findings)

        if failed_scanners:
            unified.setdefault("key_findings", [])
            unified["key_findings"] = [*unified.get("key_findings", []), *failed_scanners]

        score = max((item.cvss_score for item in findings), default=0.0)
        duration_seconds = max(1, int(time.monotonic() - started))
        pipeline_status = "complete" if findings or not failed_scanners else "failed"

        upsert_scan_record(
            db,
            scan_id=scan_id,
            target=target,
            profile=profile,
            status=pipeline_status,
            tools=scanners,
            findings=findings,
            duration_seconds=duration_seconds,
            score=score,
            unified_report=unified,
            zero_day=zero_day,
            self_audit=self_audit,
            scanner_runs=run_summaries,
            actor=actor,
            queue_identity="worker",
        )

        stored_findings = get_scan_findings(db, scan_id)
        attack_paths = build_attack_paths(scan_id, stored_findings)
        persist_attack_paths(db, scan_id, attack_paths)

        await publish_progress(
            scan_id,
            {
                "phase": "COMPLETE" if pipeline_status == "complete" else "FAILED",
                "message": "Scan pipeline complete" if pipeline_status == "complete" else "All scanners failed",
            },
        )

        if findings:
            top = max(findings, key=lambda item: item.cvss_score)
            top_severity = top.severity.value if hasattr(top.severity, "value") else str(top.severity)
            await send_webhook_alert(
                event_type="scan.completed.top_finding",
                severity=top_severity,
                payload={
                    "scan_id": scan_id,
                    "target": target,
                    "finding_id": top.finding_id,
                    "cve_id": top.cve_id,
                    "title": top.title,
                    "severity": top_severity,
                },
            )

        write_audit_event(
            event_type="scan.job.completed" if pipeline_status == "complete" else "scan.job.failed",
            actor=actor,
            scan_id=scan_id,
            details={"findings": len(findings), "failed_scanners": failed_scanners},
        )
    except Exception as exc:
        import sys
        import traceback
        print(f"CRITICAL EXCEPTION IN PIPELINE: {exc}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        upsert_scan_record(
            db,
            scan_id=scan_id,
            target=target,
            profile=profile,
            status="failed",
            tools=scanners,
            findings=[],
            unified_report={"executive_summary": f"Scan failed: {exc}"},
            scanner_runs=run_summaries,
            actor=actor,
            queue_identity="worker",
        )
        await publish_progress(
            scan_id,
            {
                "phase": "FAILED",
                "message": f"Scan failed: {exc}",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
        write_audit_event(event_type="scan.job.failed", actor=actor, scan_id=scan_id, details={"error": str(exc)[:300]})
    finally:
        db.close()
