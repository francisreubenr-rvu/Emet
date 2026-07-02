"""Patch deployment via a real Ansible playbook runner.

Gated on real configuration. Previously this returned a hard-coded fake
"PLAY RECAP ... changed=1" log after sleeping one second. It now either runs a
real playbook or reports honestly that automation is not configured — it never
claims a patch was applied when it was not. Configure via environment:

    EMET_PATCH_PLAYBOOK   path to an Ansible playbook to run
    EMET_PATCH_INVENTORY  (optional) inventory file; defaults to the target as a host
"""

from __future__ import annotations

import asyncio
import os
import shutil
from datetime import datetime

from db.database import SessionLocal
from db.models import PatchJobModel


def _set(job_id: int, **fields) -> None:
    db = SessionLocal()
    try:
        job = db.query(PatchJobModel).filter(PatchJobModel.id == job_id).first()
        if not job:
            return
        for key, value in fields.items():
            setattr(job, key, value)
        job.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


async def deploy_patch_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.query(PatchJobModel).filter(PatchJobModel.id == job_id).first()
        if not job:
            return
        target = job.target
    finally:
        db.close()

    playbook = (os.getenv("EMET_PATCH_PLAYBOOK") or "").strip()
    ansible = shutil.which("ansible-playbook")

    if not playbook or not ansible:
        _set(
            job_id,
            status="not_configured",
            log_output=(
                "Patch automation is not configured. Set EMET_PATCH_PLAYBOOK to an "
                "Ansible playbook and install ansible-playbook to enable real deployment. "
                "No patch was applied."
            ),
        )
        return

    _set(job_id, status="deploying")

    inventory = (os.getenv("EMET_PATCH_INVENTORY") or "").strip()
    command = [ansible, playbook, "--extra-vars", f"target={target}"]
    if inventory:
        command += ["-i", inventory]
    else:
        command += ["-i", f"{target},"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
    except OSError as exc:
        _set(job_id, status="failed", log_output=f"Failed to launch ansible-playbook: {exc}")
        return

    log = (stdout.decode("utf-8", "ignore") + stderr.decode("utf-8", "ignore")).strip()
    _set(
        job_id,
        status="success" if process.returncode == 0 else "failed",
        log_output=log[:8000] or "(no output)",
    )
