from __future__ import annotations

import csv
import io
import json

from db.models import ScanJobModel, VulnerabilityModel


def export_scan_json(scan: ScanJobModel, findings: list[VulnerabilityModel]) -> bytes:
    payload = {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "profile": scan.profile,
        "tools": scan.tools,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "finding_id": row.finding_id,
                "cve_id": row.cve_id or None,
                "severity": row.severity,
                "title": row.title,
                "description": row.description,
                "scanner_source": row.scanner_source,
                "target": row.target,
                "verification_status": row.verification_status,
                "status": row.status,
            }
            for row in findings
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def export_scan_csv(findings: list[VulnerabilityModel]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "finding_id",
            "scan_id",
            "target",
            "scanner_source",
            "severity",
            "cve_id",
            "title",
            "verification_status",
            "status",
        ]
    )
    for row in findings:
        writer.writerow(
            [
                row.finding_id,
                row.scan_id,
                row.target,
                row.scanner_source,
                row.severity,
                row.cve_id,
                row.title,
                row.verification_status,
                row.status,
            ]
        )
    return buffer.getvalue().encode("utf-8")
