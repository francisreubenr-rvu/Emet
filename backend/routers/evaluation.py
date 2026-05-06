from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import EvalRunModel
from services.auth_guard import verify_access_token
from services.audit import write_audit_event
from services.eval_metrics import evaluate_fixture

router = APIRouter(prefix="/api/eval", tags=["evaluation"])


class EvalRunRequest(BaseModel):
    run_type: str = "retrieval-grounding"
    model_name: str = "fallback-template"
    fixture_name: str = "default"


@router.post("/runs")
async def run_evaluation(payload: EvalRunRequest, request: Request, db: Session = Depends(get_db)):
    token = verify_access_token(request, required_scope="write")
    actor = str(token.get("sub", "unknown"))
    run_id = f"eval-{uuid4().hex[:12]}"
    row = EvalRunModel(
        id=run_id,
        run_type=payload.run_type,
        model_name=payload.model_name,
        metrics=evaluate_fixture(
            predicted_cves=["CVE-2023-46604", "CVE-2018-15473"],
            expected_cves=["CVE-2023-46604", "CVE-2018-15473"],
            candidate_answer="Patch exposed services and prioritize verified high severity findings first.",
            reference_answer="Prioritize verified high severity findings and patch exposed services first.",
        ),
        metadata_json={"mode": "fixture-eval", "fixture": payload.fixture_name},
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    write_audit_event(event_type="eval.run.created", actor=actor, details={"run_id": run_id})
    return {"run_id": run_id, "status": "completed", "metrics": row.metrics}


@router.get("/runs")
async def list_evaluation_runs(request: Request, db: Session = Depends(get_db)):
    verify_access_token(request, required_scope="read")
    rows = db.query(EvalRunModel).order_by(EvalRunModel.created_at.desc()).limit(200).all()
    return [
        {
            "run_id": item.id,
            "run_type": item.run_type,
            "model_name": item.model_name,
            "metrics": item.metrics,
            "metadata": item.metadata_json,
            "created_at": item.created_at.isoformat(),
        }
        for item in rows
    ]
