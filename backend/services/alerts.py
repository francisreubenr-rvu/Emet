from __future__ import annotations

import os

import httpx
from sqlalchemy.orm import Session

from db.models import AlertEventModel


def _severity_rank(level: str) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get((level or "INFO").upper(), 1)


def sanitize_text(value: str, max_len: int = 2000) -> str:
    return " ".join(str(value).split())[:max_len]


def _dedupe_key(kind: str, title: str, body: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"{kind}|{title}|{body}".encode("utf-8")).hexdigest()
    return f"alert-dedupe:{kind}:{digest}"


def _is_valid_https_url(value: str) -> bool:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme in {"https", "http"} and bool(parsed.netloc)


def store_alert_event(db: Session, *, event_type: str, severity: str, payload: dict) -> AlertEventModel:
    row = AlertEventModel(event_type=event_type, severity=severity, payload=payload)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


async def send_webhook_alert(*, event_type: str, severity: str, payload: dict) -> bool:
    endpoint = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    min_level = os.getenv("ALERT_MIN_SEVERITY", "HIGH").strip().upper()
    if not endpoint:
        return False
    if not _is_valid_https_url(endpoint):
        return False
    if _severity_rank(severity) < _severity_rank(min_level):
        return False
    try:
        safe_payload = {
            "event_type": sanitize_text(event_type, 120),
            "severity": sanitize_text(severity, 16),
            "payload": payload,
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(endpoint, json=safe_payload)
            return response.status_code < 300
    except Exception:
        return False


async def create_github_issue(*, title: str, body: str, labels: list[str] | None = None) -> tuple[bool, str]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    repo = os.getenv("GITHUB_ISSUES_REPO", "").strip()
    if not token or not repo or "/" not in repo:
        return False, "GitHub integration not configured"

    clean_title = sanitize_text(title, 140)
    clean_body = sanitize_text(body, 5000)
    payload = build_github_issue_payload(title=clean_title, body=clean_body, labels=labels)
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis.asyncio as redis

            client = redis.from_url(redis_url, decode_responses=True)
            key = _dedupe_key("github", clean_title, clean_body)
            if await client.get(key):
                return False, "Duplicate GitHub issue request suppressed"
            await client.set(key, "1", ex=900)
        except Exception:
            pass
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.post(
                f"https://api.github.com/repos/{repo}/issues",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                json=payload,
            )
            if response.status_code >= 300:
                return False, f"GitHub API error {response.status_code}"
            data = response.json()
            return True, str(data.get("html_url") or "")
    except Exception as exc:
        return False, f"GitHub integration failed: {exc}"


async def create_jira_issue(*, summary: str, description: str) -> tuple[bool, str]:
    base = os.getenv("JIRA_BASE_URL", "").strip().rstrip("/")
    email = os.getenv("JIRA_EMAIL", "").strip()
    token = os.getenv("JIRA_API_TOKEN", "").strip()
    project_key = os.getenv("JIRA_PROJECT_KEY", "").strip()
    issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task").strip()
    if not base or not email or not token or not project_key:
        return False, "Jira integration not configured"
    if not _is_valid_https_url(base):
        return False, "Jira base URL invalid"

    clean_summary = sanitize_text(summary, 200)
    clean_description = sanitize_text(description, 5000)
    payload = _build_jira_issue_payload(
        summary=clean_summary,
        description=clean_description,
        issue_type=issue_type,
        project_key=project_key,
    )
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis.asyncio as redis

            client = redis.from_url(redis_url, decode_responses=True)
            key = _dedupe_key("jira", clean_summary, clean_description)
            if await client.get(key):
                return False, "Duplicate Jira issue request suppressed"
            await client.set(key, "1", ex=900)
        except Exception:
            pass
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.post(
                f"{base}/rest/api/3/issue",
                auth=(email, token),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )
            if response.status_code >= 300:
                return False, f"Jira API error {response.status_code}"
            data = response.json()
            key = str(data.get("key") or "")
            return True, key
    except Exception as exc:
        return False, f"Jira integration failed: {exc}"


def build_github_issue_payload(*, title: str, body: str, labels: list[str] | None = None) -> dict:
    return {
        "title": title,
        "body": body,
        "labels": labels or ["security", "vulnerability"],
    }


def build_jira_issue_payload(*, summary: str, description: str, issue_type: str = "Task") -> dict:
    return _build_jira_issue_payload(summary=summary, description=description, issue_type=issue_type, project_key="")


def _build_jira_issue_payload(*, summary: str, description: str, issue_type: str = "Task", project_key: str = "") -> dict:
    project = {"key": project_key} if project_key else None
    fields = {
        "summary": summary,
        "description": description,
        "issuetype": {"name": issue_type},
    }
    if project is not None:
        fields["project"] = project
    return {
        "fields": fields
    }
