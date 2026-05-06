import asyncio
from datetime import datetime
from db.database import SessionLocal
from db.models import PatchJobModel

async def deploy_patch_job(job_id: int):
    # Retrieve job
    db = SessionLocal()
    try:
        job = db.query(PatchJobModel).filter(PatchJobModel.id == job_id).first()
        if not job:
            return
        job.status = "deploying"
        job.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    # Simulate patch deployment delay (e.g., Ansible/Terraform runner)
    await asyncio.sleep(1)

    db = SessionLocal()
    try:
        job = db.query(PatchJobModel).filter(PatchJobModel.id == job_id).first()
        if job:
            job.status = "success"
            job.log_output = "PLAY [Deploy Patch] **********\n\nTASK [Apply fix] **********\nchanged: [target]\n\nPLAY RECAP **********\ntarget : ok=1 changed=1 unreachable=0 failed=0"
            job.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()
