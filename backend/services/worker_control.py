from __future__ import annotations

TERMINAL_SCAN_STATUSES = {"complete", "failed", "cancelled"}


def can_execute_scan(status: str | None) -> bool:
    if not status:
        return True
    return status.lower() not in TERMINAL_SCAN_STATUSES


def heartbeat_key(worker_id: str) -> str:
    return f"worker:heartbeat:{worker_id}"


def lock_key(scan_id: str) -> str:
    return f"scan-lock:{scan_id}"
