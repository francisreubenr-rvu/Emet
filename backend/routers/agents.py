from __future__ import annotations

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import AgentModel

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])

class AgentRegisterPayload(BaseModel):
    id: str
    name: str = "Unnamed Agent"
    machine_info: dict = {}
    ip_address: str = ""
    version: str = "1.0.0"

@router.post("/register")
async def register_agent(payload: AgentRegisterPayload, db: Session = Depends(get_db)):
    if not payload.id:
        raise HTTPException(status_code=400, detail="Missing agent ID")
    
    agent = db.query(AgentModel).filter(AgentModel.id == payload.id).first()
    if not agent:
        agent = AgentModel(
            id=payload.id,
            name=payload.name,
            machine_info=payload.machine_info,
            ip_address=payload.ip_address,
            version=payload.version,
            status="online",
            last_heartbeat=datetime.utcnow()
        )
        db.add(agent)
    else:
        agent.status = "online"
        agent.last_heartbeat = datetime.utcnow()
        agent.machine_info = payload.machine_info
        agent.ip_address = payload.ip_address
        agent.version = payload.version
        agent.updated_at = datetime.utcnow()
        
    db.commit()
    db.refresh(agent)
    return {"status": "registered", "agent_id": agent.id}

@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    agent.status = "online"
    agent.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"status": "ok"}

@router.get("/{agent_id}/tasks")
async def get_agent_tasks(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Return empty tasks for now, future expansion
    return {"tasks": []}
