"""Remediation ticketing against a real Jira Cloud instance.

Gated on real configuration. When Jira credentials are not present we create a
local ticket record and report it as unsynced — we never fabricate an external
ticket id or a synced status. Configure via environment:

    JIRA_BASE_URL      e.g. https://your-org.atlassian.net
    JIRA_EMAIL         Atlassian account email
    JIRA_API_TOKEN     API token (id.atlassian.com/manage-profile/security/api-tokens)
    JIRA_PROJECT_KEY   e.g. SEC
"""

from __future__ import annotations

import os
from typing import Optional
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from db.models import RemediationTicketModel, VulnerabilityModel


class JiraClient:
    def __init__(self) -> None:
        self.base_url = (os.getenv("JIRA_BASE_URL") or "").rstrip("/")
        self.email = os.getenv("JIRA_EMAIL") or ""
        self.token = os.getenv("JIRA_API_TOKEN") or ""
        self.project_key = os.getenv("JIRA_PROJECT_KEY") or ""

    @property
    def is_configured(self) -> bool:
        return all((self.base_url, self.email, self.token, self.project_key))

    def create_issue(self, summary: str, description: str) -> str:
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary[:255],
                "issuetype": {"name": "Task"},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": description}]}
                    ],
                },
            }
        }
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                f"{self.base_url}/rest/api/3/issue",
                json=payload,
                auth=(self.email, self.token),
            )
            resp.raise_for_status()
            return resp.json()["key"]

    def get_issue_status(self, issue_key: str) -> str:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                params={"fields": "status"},
                auth=(self.email, self.token),
            )
            resp.raise_for_status()
            return resp.json()["fields"]["status"]["name"]


class TicketingService:
    def __init__(self, db: Session):
        self.db = db
        self.client = JiraClient()

    def create_ticket_for_finding(self, finding_id: str) -> Optional[RemediationTicketModel]:
        vulnerability = (
            self.db.query(VulnerabilityModel)
            .filter(VulnerabilityModel.finding_id == finding_id)
            .first()
        )
        if not vulnerability:
            return None

        existing_ticket = (
            self.db.query(RemediationTicketModel)
            .filter(RemediationTicketModel.finding_id == finding_id)
            .first()
        )
        if existing_ticket:
            return existing_ticket

        summary = f"Remediate: {vulnerability.title}"
        description = (
            f"Fix vulnerability {vulnerability.cve_id or finding_id} on {vulnerability.target}.\n\n"
            f"Details: {vulnerability.description}"
        )

        external_id = ""
        if self.client.is_configured:
            # Real API call; if it fails we surface the error rather than faking success.
            external_id = self.client.create_issue(summary, description)

        ticket = RemediationTicketModel(
            finding_id=finding_id,
            external_id=external_id,
            external_system="jira",
            status="open",
            summary=summary,
            description=description,
            last_sync_at=datetime.utcnow() if external_id else None,
        )
        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)
        return ticket

    def sync_ticket_status(self, ticket_id: int) -> Optional[RemediationTicketModel]:
        ticket = (
            self.db.query(RemediationTicketModel)
            .filter(RemediationTicketModel.id == ticket_id)
            .first()
        )
        if not ticket:
            return None

        # Only real, configured, externally-tracked tickets can be synced.
        if not (self.client.is_configured and ticket.external_id):
            return ticket

        ticket.status = self.client.get_issue_status(ticket.external_id)
        ticket.last_sync_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(ticket)
        return ticket

    def integration_configured(self) -> bool:
        return self.client.is_configured
