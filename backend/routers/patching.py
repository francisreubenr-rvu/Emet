from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from db.database import get_db
from db.models import PatchJobModel
from services.patching import deploy_patch_job

router = APIRouter(prefix="/api/v1/patching", tags=["patching"])

class PatchRequest(BaseModel):
    vulnerability_id: str
    target: str

class PatchResponse(BaseModel):
    id: int
    vulnerability_id: str
    target: str
    status: str
    log_output: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True

@router.post("/deploy", response_model=PatchResponse)
async def deploy_patch(request: PatchRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    job = PatchJobModel(
        vulnerability_id=request.vulnerability_id,
        target=request.target,
        status="pending"
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(deploy_patch_job, job.id)
    return job

@router.get("/jobs/{job_id}", response_model=PatchResponse)
async def get_patch_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(PatchJobModel).filter(PatchJobModel.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    return job
