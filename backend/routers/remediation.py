from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from db.database import get_db
from db.models import RemediationTicketModel
from services.ticketing import TicketingService

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])

@router.post("/tickets", response_model=Dict[str, Any])
def create_ticket(finding_id: str, db: Session = Depends(get_db)):
    service = TicketingService(db)
    ticket = service.create_ticket_for_finding(finding_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": ticket.id,
        "finding_id": ticket.finding_id,
        "external_id": ticket.external_id,
        "status": ticket.status,
        "summary": ticket.summary
    }

@router.post("/sync", response_model=Dict[str, Any])
def sync_ticket(ticket_id: int, db: Session = Depends(get_db)):
    service = TicketingService(db)
    ticket = service.sync_ticket_status(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return {
        "id": ticket.id,
        "external_id": ticket.external_id,
        "status": ticket.status,
        "last_sync_at": ticket.last_sync_at.isoformat() if ticket.last_sync_at else None
    }

@router.get("/tickets", response_model=List[Dict[str, Any]])
def get_tickets(db: Session = Depends(get_db)):
    tickets = db.query(RemediationTicketModel).all()
    return [
        {
            "id": t.id,
            "finding_id": t.finding_id,
            "external_id": t.external_id,
            "status": t.status,
            "summary": t.summary,
            "last_sync_at": t.last_sync_at.isoformat() if t.last_sync_at else None
        } for t in tickets
    ]
