from __future__ import annotations

from collections import defaultdict
import os

from sqlalchemy.orm import Session

from db.models import AttackPathModel, VulnerabilityModel


def _severity_weight(severity: str) -> int:
    mapping = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return mapping.get((severity or "INFO").upper(), 1)


def build_relational_attack_paths(scan_id: str, findings: list[VulnerabilityModel]) -> list[dict]:
    by_target: dict[str, list[VulnerabilityModel]] = defaultdict(list)
    for finding in findings:
        by_target[finding.target].append(finding)

    paths: list[dict] = []
    for target, rows in by_target.items():
        rows_sorted = sorted(rows, key=lambda item: (_severity_weight(item.severity), item.cvss_score), reverse=True)
        top = rows_sorted[:5]
        chain = []
        for row in top:
            label = row.cve_id or row.title
            if row.service:
                label = f"{label} [{row.service}]"
            chain.append(label)

        confidence = min(0.95, max(0.2, 0.35 + (sum(_severity_weight(item.severity) for item in top) / 25.0)))
        paths.append(
            {
                "scan_id": scan_id,
                "target": target,
                "path_summary": " -> ".join(chain) if chain else "No meaningful path",
                "confidence_score": round(confidence, 2),
                "provenance": {
                    "mode": "relational-fallback",
                    "nodes": [row.finding_id for row in top],
                    "sources": list(sorted({row.scanner_source for row in top})),
                },
            }
        )
    return paths


def build_attack_paths(scan_id: str, findings: list[VulnerabilityModel]) -> list[dict]:
    if os.getenv("ENABLE_NEO4J", "false").lower() == "true":
        neo4j_uri = os.getenv("NEO4J_URI", "").strip()
        neo4j_user = os.getenv("NEO4J_USER", "").strip()
        neo4j_password = os.getenv("NEO4J_PASSWORD", "").strip()
        if neo4j_uri and neo4j_user and neo4j_password:
            try:
                from neo4j import GraphDatabase

                paths = build_relational_attack_paths(scan_id, findings)
                driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
                with driver.session() as session:
                    for item in paths:
                        session.run(
                            """
                            MERGE (s:Scan {scan_id: $scan_id})
                            MERGE (t:Target {name: $target})
                            MERGE (s)-[:OBSERVED]->(t)
                            MERGE (p:Path {scan_id: $scan_id, summary: $summary})
                            SET p.confidence = $confidence, p.mode = 'neo4j'
                            MERGE (t)-[:HAS_PATH]->(p)
                            """,
                            scan_id=item["scan_id"],
                            target=item["target"],
                            summary=item["path_summary"],
                            confidence=float(item["confidence_score"]),
                        )
                driver.close()
                for item in paths:
                    item["provenance"]["graph_mode"] = "neo4j"
                return paths
            except Exception:
                pass

        paths = build_relational_attack_paths(scan_id, findings)
        for item in paths:
            item["provenance"]["graph_mode"] = "neo4j-config-missing-fallback"
        return paths
    return build_relational_attack_paths(scan_id, findings)


def persist_attack_paths(db: Session, scan_id: str, paths: list[dict]) -> None:
    db.query(AttackPathModel).filter(AttackPathModel.scan_id == scan_id).delete()
    for item in paths:
        db.add(
            AttackPathModel(
                scan_id=scan_id,
                target=item["target"],
                path_summary=item["path_summary"],
                confidence_score=float(item["confidence_score"]),
                provenance=item["provenance"],
            )
        )
    db.commit()
