from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import VulnerabilityModel

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

@router.get("/{framework}")
async def get_compliance_vulnerabilities(
    framework: str,
    db: Session = Depends(get_db)
):
    """
    Retrieve vulnerabilities that violate a specific compliance framework.
    For example: /api/v1/compliance/SOC2
    """
    # Since compliance_violations is a JSON array, we can use JSON contains or just fetch and filter
    # To keep it compatible across sqlite/postgres, we'll fetch all and filter in Python for this implementation,
    # or if we assume Postgres, we could use `.contains`. We will fetch and filter to be safe if DB is generic.
    
    # Simple Python-side filtering (OK for prototype/testing)
    vulns = db.query(VulnerabilityModel).all()
    
    results = []
    framework_upper = framework.upper()
    for vuln in vulns:
        if vuln.compliance_violations:
            # Check if any violation matches the framework
            for violation in vuln.compliance_violations:
                if framework_upper in violation.upper():
                    results.append({
                        "finding_id": vuln.finding_id,
                        "scan_id": vuln.scan_id,
                        "target": vuln.target,
                        "scanner_source": vuln.scanner_source,
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "compliance_violations": vuln.compliance_violations
                    })
                    break # Don't add the same vuln multiple times
                    
    return results
