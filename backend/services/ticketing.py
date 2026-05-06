from typing import Optional
from datetime import datetime
from sqlalchemy.orm import Session
from db.models import RemediationTicketModel, VulnerabilityModel

class MockJiraClient:
    def create_ticket(self, summary: str, description: str) -> str:
        return f"JIRA-{int(datetime.utcnow().timestamp())}"

    def update_ticket(self, ticket_id: str, status: str) -> bool:
        return True

    def get_ticket_status(self, ticket_id: str) -> str:
        return "in-progress"

class TicketingService:
    def __init__(self, db: Session):
        self.db = db
        self.client = MockJiraClient()

    def create_ticket_for_finding(self, finding_id: str) -> Optional[RemediationTicketModel]:
        vulnerability = self.db.query(VulnerabilityModel).filter(VulnerabilityModel.finding_id == finding_id).first()
        if not vulnerability:
            return None

        # check if ticket already exists
        existing_ticket = self.db.query(RemediationTicketModel).filter(RemediationTicketModel.finding_id == finding_id).first()
        if existing_ticket:
            return existing_ticket

        summary = f"Remediate: {vulnerability.title}"
        description = f"Fix vulnerability {vulnerability.cve_id or finding_id} on {vulnerability.target}.\n\nDetails: {vulnerability.description}"
        
        external_id = self.client.create_ticket(summary, description)

        ticket = RemediationTicketModel(
            finding_id=finding_id,
            external_id=external_id,
            external_system="jira",
            status="open",
            summary=summary,
            description=description,
        )
        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)
        return ticket

    def sync_ticket_status(self, ticket_id: int) -> Optional[RemediationTicketModel]:
        ticket = self.db.query(RemediationTicketModel).filter(RemediationTicketModel.id == ticket_id).first()
        if not ticket:
            return None

        external_status = self.client.get_ticket_status(ticket.external_id)
        ticket.status = external_status
        ticket.last_sync_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(ticket)
        return ticket
